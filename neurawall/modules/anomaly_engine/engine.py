"""Tier 1 — statistical anomaly engine (blueprint §5.1).

Four detectors, combined into one bounded score with feature attribution:

* **Isolation Forest** over the flow feature vector (multivariate outliers).
* **EWMA baselines** of outbound volume per ``(source, service, hour-of-week)``.
* **Entropy** of DNS labels (DGA / tunnelling hints on encrypted traffic).
* **Rate of change** of connections per source (scans, floods).

Authority: raises suspicion only. It never emits an enforcement action.
"""

from __future__ import annotations

import math
import random
import threading
import time
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from neurawall.core.models import AnomalyScore, Attribution, FlowRecord
from neurawall.core.telemetry import REGISTRY
from neurawall.core.validation import check_probability, ip_in_any
from neurawall.modules.anomaly_engine.features import (
    FEATURE_NAMES,
    SourceWindow,
    extract,
    hour_of_week,
)

_scored = REGISTRY.counter("neurawall_tier1_scored_total", "Flows scored by Tier 1")
_latency = REGISTRY.histogram("neurawall_tier1_batch_seconds", "Tier 1 batch scoring latency")


#: A source is flooding when it opens this many times more connections than a typical
#: source, and at least this many per minute in absolute terms.
FLOOD_RATIO = 3.0
FLOOD_MIN_CONNS_PER_MINUTE = 60.0


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class Ewma:
    __slots__ = ("mean", "n", "var")

    def __init__(self) -> None:
        self.mean = 0.0
        self.var = 1.0
        self.n = 0

    def zscore(self, x: float) -> float:
        if self.n < 5:
            return 0.0
        return (x - self.mean) / math.sqrt(max(self.var, 0.25))

    def update(self, x: float, alpha: float = 0.05) -> None:
        if self.n == 0:
            self.mean, self.var = x, 1.0
        else:
            d = x - self.mean
            self.mean += alpha * d
            self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1


@dataclass
class Suppression:
    """Change-window suppression: planned deployments should not page anyone."""

    cidrs: list[str]
    until: float
    reason: str


class AnomalyEngine:
    def __init__(
        self,
        *,
        warmup_flows: int = 200,
        trees: int = 100,
        reservoir_size: int = 4000,
        refit_every: int = 2000,
        seed: int = 7,
        max_baselines: int = 100_000,
    ) -> None:
        self.warmup_flows = warmup_flows
        self.trees = trees
        self.reservoir_size = reservoir_size
        self.refit_every = refit_every
        self.max_baselines = max_baselines
        self._rng = random.Random(seed)
        self._seed = seed
        self._window = SourceWindow()
        self._baselines: OrderedDict[tuple[str, int, int], Ewma] = OrderedDict()
        #: Population baseline of log(connections/min per source): floods are judged against
        #: what sources typically do, not against a host's own (lagging) history.
        self._population_rate = Ewma()
        self._reservoir: list[np.ndarray] = []
        self._seen = 0
        self._since_fit = 0
        self._forest: IsolationForest | None = None
        self._offset = 0.0
        self._median = np.zeros(len(FEATURE_NAMES))
        self._mad = np.ones(len(FEATURE_NAMES))
        self._suppressions: list[Suppression] = []
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    @property
    def trained(self) -> bool:
        return self._forest is not None

    def suppress(self, cidrs: list[str], seconds: float, reason: str) -> None:
        self._suppressions.append(Suppression(cidrs, time.time() + seconds, reason))

    def score(self, flow: FlowRecord) -> AnomalyScore:
        return self.score_batch([flow])[0]

    def score_batch(self, flows: Sequence[FlowRecord]) -> list[AnomalyScore]:
        """Score many flows with one model call (amortises per-call overhead)."""
        if not flows:
            return []
        with _latency.time(), self._lock:
            feats = np.vstack([extract(f, self._window) for f in flows])
            forest_scores = self._forest_scores(feats)
            out = [self._score_one(f, feats[i], forest_scores[i]) for i, f in enumerate(flows)]
            for i, f in enumerate(flows):
                self._learn(f, feats[i])
        _scored.inc(len(flows))
        return out

    # -- internals ------------------------------------------------------------

    def _forest_scores(self, feats: np.ndarray) -> np.ndarray:
        if self._forest is None:
            return np.zeros(len(feats))
        raw = -self._forest.score_samples(feats)  # higher = more anomalous, ~0.35..0.8
        return np.clip((raw - self._offset) * 6.0, -6, 6)

    def _score_one(self, flow: FlowRecord, x: np.ndarray, forest_logit: float) -> AnomalyScore:
        contributions: dict[str, float] = {}

        # Isolation forest, attributed to the most deviant features (robust z-score).
        forest = _sigmoid(forest_logit) if self._forest is not None else 0.0
        if forest > 0.5:
            dev = np.abs(x - self._median) / self._mad
            for idx in np.argsort(dev)[::-1][:3]:
                if dev[idx] > 2:
                    contributions[FEATURE_NAMES[idx]] = float(forest * min(dev[idx], 20) / 20)

        # EWMA volume baseline.
        key = (flow.src_ip, flow.dst_port, hour_of_week(flow.ts_start))
        base = self._baselines.get(key)
        z = base.zscore(x[0]) if base else 0.0
        volume = _sigmoid(abs(z) - 4.0) if z > 0 else 0.0
        if volume > 0.3:
            contributions["volume_vs_baseline"] = volume

        # DNS entropy: > ~3.8 bits in a label is unusual for human-chosen names.
        ent = float(x[FEATURE_NAMES.index("dns_label_entropy")])
        entropy = _sigmoid((ent - 3.8) * 4.0) if ent else 0.0
        if entropy > 0.3:
            contributions["dns_label_entropy"] = entropy

        # Connection-rate change per source.
        rate_x = float(x[FEATURE_NAMES.index("src_conn_rate")])
        conns_per_min = math.expm1(rate_x)
        flood = 0.0
        if conns_per_min >= FLOOD_MIN_CONNS_PER_MINUTE and self._population_rate.n >= 50:
            excess = rate_x - self._population_rate.mean  # log-ratio vs a typical source
            flood = _sigmoid((excess - math.log(FLOOD_RATIO)) * 5.0)
        port_ent = float(x[FEATURE_NAMES.index("src_port_entropy")])
        rate = max(flood, _sigmoid((port_ent - 4.0) * 3.0))
        if rate > 0.3:
            contributions["connection_rate"] = rate

        parts = [forest, volume, entropy, rate]
        # Noisy-OR: independent weak signals accumulate; any strong one dominates.
        combined = 1.0 - math.prod(1.0 - 0.9 * p for p in parts)

        if self._is_suppressed(flow.src_ip):
            combined *= 0.25
            contributions["change_window_suppression"] = -0.75

        score = check_probability(round(min(max(combined, 0.0), 1.0), 4), what="tier1 score")
        confidence = min(1.0, self._seen / self.warmup_flows) * (1.0 if self.trained else 0.6)
        top = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:3]
        return AnomalyScore(
            flow_id=flow.flow_id,
            score=score,
            confidence=round(confidence, 3),
            top_features=[Attribution(feature=k, contribution=round(v, 4)) for k, v in top],
            model_version=f"tier1-if{self.trees}",
        )

    def _learn(self, flow: FlowRecord, x: np.ndarray) -> None:
        self._seen += 1
        self._since_fit += 1
        key = (flow.src_ip, flow.dst_port, hour_of_week(flow.ts_start))
        base = self._baselines.get(key)
        if base is None:
            base = Ewma()
            self._baselines[key] = base
            if len(self._baselines) > self.max_baselines:
                self._baselines.popitem(last=False)
        base.update(x[0])
        self._population_rate.update(float(x[FEATURE_NAMES.index("src_conn_rate")]), alpha=0.01)

        # Reservoir sampling keeps a uniform sample of history for (re)training.
        if len(self._reservoir) < self.reservoir_size:
            self._reservoir.append(x)
        else:
            j = self._rng.randrange(self._seen)
            if j < self.reservoir_size:
                self._reservoir[j] = x

        due = self._forest is None and self._seen >= self.warmup_flows
        if due or self._since_fit >= self.refit_every:
            self._fit()

    def _fit(self) -> None:
        data = np.vstack(self._reservoir)
        forest = IsolationForest(
            n_estimators=self.trees, random_state=self._seed, contamination="auto"
        )
        forest.fit(data)
        raw = -forest.score_samples(data)
        self._offset = float(np.quantile(raw, 0.99))
        self._median = np.median(data, axis=0)
        self._mad = np.maximum(np.median(np.abs(data - self._median), axis=0) * 1.4826, 0.05)
        self._forest = forest
        self._since_fit = 0

    def _is_suppressed(self, ip: str) -> bool:
        now = time.time()
        self._suppressions = [s for s in self._suppressions if s.until > now]
        return any(ip_in_any(ip, s.cidrs) for s in self._suppressions)
