"""Tier 2 — L7 metadata classifier (blueprint §5.2).

Runs off the hot path on flows escalated by Tier 1 (or carrying L7 metadata), rate
limited per node. Emits one :class:`Classification` per firing detector with feature
attributions; when Tier 1 is confident something is wrong but no detector explains
it, emits ``novel`` so Tier 3 can reason about it.
"""

from __future__ import annotations

from collections.abc import Callable

from neurawall.core.models import AnomalyScore, Classification, FlowRecord, ThreatLabel
from neurawall.core.telemetry import REGISTRY
from neurawall.core.validation import check_probability
from neurawall.modules.l7_classifier.detectors import behavioral, dns, injection
from neurawall.modules.l7_classifier.detectors.base import Finding
from neurawall.security.ratelimit import TokenBucket

MODEL_VERSION = "tier2-heuristic-1.0"
Detector = Callable[[FlowRecord], list[Finding]]


def default_detectors() -> tuple[Detector, ...]:
    return (
        injection.detect,
        dns.DnsDetector(),
        behavioral.detect_beacon,
        behavioral.detect_exfiltration,
        behavioral.detect_tls_mismatch,
    )


_invocations = REGISTRY.counter("neurawall_tier2_invocations_total", "Tier 2 invocations")
_rate_limited = REGISTRY.counter("neurawall_tier2_rate_limited_total", "Tier 2 calls shed")
_labels = REGISTRY.counter("neurawall_tier2_labels_total", "Tier 2 labels emitted")


class L7Classifier:
    def __init__(
        self,
        *,
        rate_per_second: float = 500.0,
        novel_threshold: float = 0.8,
        detectors: tuple[Detector, ...] | None = None,
    ) -> None:
        self._bucket = TokenBucket(rate_per_second, burst=rate_per_second * 2)
        self.novel_threshold = novel_threshold
        self.detectors = detectors if detectors is not None else default_detectors()

    def should_invoke(
        self, flow: FlowRecord, anomaly: AnomalyScore | None, escalation_threshold: float
    ) -> bool:
        """Escalation contract (blueprint §5.4): Tier 1 score, or L7 metadata to inspect."""
        escalated = anomaly is not None and anomaly.score >= escalation_threshold
        return (
            escalated
            or flow.l7 is not None
            or len(flow.inter_arrival_ms) >= 6
            or flow.bytes_out >= 20_000_000
        )

    def classify(
        self, flow: FlowRecord, anomaly: AnomalyScore | None = None
    ) -> list[Classification]:
        """Classify one flow. Returns ``[]`` when shed by the rate limiter."""
        if not self._bucket.try_acquire():
            _rate_limited.inc()
            return []
        _invocations.inc()
        findings: list[Finding] = []
        for det in self.detectors:
            findings.extend(det(flow))

        out = [
            Classification(
                flow_id=flow.flow_id,
                label=f.label,
                confidence=check_probability(f.confidence, what=f"{f.detector} confidence"),
                detector=f.detector,
                attributions=f.attributions(),
                model_version=MODEL_VERSION,
            )
            for f in sorted(findings, key=lambda f: f.confidence, reverse=True)
        ]
        if not out and anomaly is not None and anomaly.score >= self.novel_threshold:
            out.append(
                Classification(
                    flow_id=flow.flow_id,
                    label=ThreatLabel.NOVEL,
                    confidence=round(0.4 + 0.3 * anomaly.score * anomaly.confidence, 4),
                    detector="novelty",
                    attributions=list(anomaly.top_features),
                    model_version=MODEL_VERSION,
                )
            )
        if not out:
            out.append(
                Classification(
                    flow_id=flow.flow_id,
                    label=ThreatLabel.BENIGN,
                    confidence=0.9,
                    detector="none",
                    model_version=MODEL_VERSION,
                )
            )
        for c in out:
            _labels.inc(label=c.label.value)
        return out


def needs_tier3(classifications: list[Classification], low: float, high: float) -> bool:
    """Novel label, or a malicious label in the ambiguous confidence band."""
    return any(
        c.label == ThreatLabel.NOVEL
        or (c.label != ThreatLabel.BENIGN and low <= c.confidence <= high)
        for c in classifications
    )
