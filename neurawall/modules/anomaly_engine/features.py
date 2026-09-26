"""Flow feature extraction for Tier 1. Works on encrypted traffic — metadata only."""

from __future__ import annotations

import math
import time
from collections import Counter, OrderedDict, deque

import numpy as np

from neurawall.core.models import FlowRecord

FEATURE_NAMES: tuple[str, ...] = (
    "log_bytes_out",
    "log_bytes_in",
    "log_packets_out",
    "log_packets_in",
    "out_ratio",
    "mean_pkt_out",
    "log_duration",
    "src_port_entropy",
    "src_conn_rate",
    "dns_label_entropy",
    "iat_cv",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def dns_label_entropy(qname: str | None) -> float:
    """Entropy of the longest non-registrable label — high for DGA / tunnelling names."""
    if not qname:
        return 0.0
    labels = qname.split(".")
    candidates = labels[:-2] if len(labels) > 2 else labels[:1]
    return max((shannon_entropy(label) for label in candidates), default=0.0)


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 3:
        return 1.0  # unknown -> neutral
    arr = np.asarray(values, dtype=float)
    mean = float(arr.mean())
    return float(arr.std() / mean) if mean > 0 else 1.0


class SourceWindow:
    """Per-source sliding window (60 s) of destination ports, for rate and port entropy.

    LRU-bounded so an address-spoofing flood cannot exhaust memory.
    """

    def __init__(self, window_seconds: float = 60.0, max_sources: int = 50000) -> None:
        self.window = window_seconds
        self.max_sources = max_sources
        self._events: OrderedDict[str, deque[tuple[float, int]]] = OrderedDict()

    def observe(self, src: str, dst_port: int, ts: float | None = None) -> tuple[float, float]:
        ts = ts if ts is not None else time.time()
        q = self._events.get(src)
        if q is None:
            q = deque(maxlen=4096)
            self._events[src] = q
            if len(self._events) > self.max_sources:
                self._events.popitem(last=False)
        else:
            self._events.move_to_end(src)
        q.append((ts, dst_port))
        while q and q[0][0] < ts - self.window:
            q.popleft()
        ports = Counter(p for _, p in q)
        n = len(q)
        entropy = -sum((c / n) * math.log2(c / n) for c in ports.values()) if n else 0.0
        return float(n), entropy


def extract(flow: FlowRecord, window: SourceWindow) -> np.ndarray:
    conn_rate, port_entropy = window.observe(flow.src_ip, flow.dst_port, flow.ts_start)
    total = flow.bytes_out + flow.bytes_in
    return np.array([
        math.log1p(flow.bytes_out),
        math.log1p(flow.bytes_in),
        math.log1p(flow.packets_out),
        math.log1p(flow.packets_in),
        flow.bytes_out / total if total else 0.5,
        flow.bytes_out / flow.packets_out if flow.packets_out else 0.0,
        math.log1p(flow.duration),
        port_entropy,
        math.log1p(conn_rate),
        dns_label_entropy(flow.dns_qname),
        coefficient_of_variation(flow.inter_arrival_ms),
    ], dtype=float)


def hour_of_week(ts: float) -> int:
    t = time.gmtime(ts)
    return t.tm_wday * 24 + t.tm_hour
