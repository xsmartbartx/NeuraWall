"""Backend-agnostic telemetry primitives with a Prometheus text exposition."""

from __future__ import annotations

import bisect
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

_DEFAULT_BUCKETS = (0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0)


def _label_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(labels.items()))


def _fmt_labels(key: tuple[tuple[str, str], ...], extra: str = "") -> str:
    parts = [f'{k}="{v}"' for k, v in key]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


class _Metric:
    kind = "untyped"

    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help = help_text
        self._lock = threading.Lock()

    def expose(self) -> list[str]:  # pragma: no cover - overridden
        raise NotImplementedError


class Counter(_Metric):
    kind = "counter"

    def __init__(self, name: str, help_text: str) -> None:
        super().__init__(name, help_text)
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        return self._values.get(_label_key(labels), 0.0)

    def expose(self) -> list[str]:
        return [f"{self.name}{_fmt_labels(k)} {v}" for k, v in self._values.items()]


class Gauge(Counter):
    kind = "gauge"

    def set(self, value: float, **labels: str) -> None:
        with self._lock:
            self._values[_label_key(labels)] = value


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, name: str, help_text: str, buckets: tuple[float, ...] = _DEFAULT_BUCKETS):
        super().__init__(name, help_text)
        self.buckets = buckets
        self._counts: dict[tuple[tuple[str, str], ...], list[int]] = {}
        self._sums: dict[tuple[tuple[str, str], ...], float] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = _label_key(labels)
        with self._lock:
            counts = self._counts.setdefault(key, [0] * (len(self.buckets) + 1))
            counts[bisect.bisect_left(self.buckets, value)] += 1
            self._sums[key] = self._sums.get(key, 0.0) + value

    @contextmanager
    def time(self, **labels: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(time.perf_counter() - start, **labels)

    def expose(self) -> list[str]:
        lines: list[str] = []
        for key, counts in self._counts.items():
            cumulative = 0
            for bound, c in zip(self.buckets, counts, strict=False):
                cumulative += c
                lines.append(f"{self.name}_bucket{_fmt_labels(key, f'le=\"{bound}\"')} {cumulative}")
            cumulative += counts[-1]
            lines.append(f"{self.name}_bucket{_fmt_labels(key, 'le=\"+Inf\"')} {cumulative}")
            lines.append(f"{self.name}_sum{_fmt_labels(key)} {self._sums[key]}")
            lines.append(f"{self.name}_count{_fmt_labels(key)} {cumulative}")
        return lines


class Registry:
    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}
        self._lock = threading.Lock()

    def _get(self, cls: type[_Metric], name: str, help_text: str) -> _Metric:
        with self._lock:
            m = self._metrics.get(name)
            if m is None:
                m = cls(name, help_text)
                self._metrics[name] = m
            elif not isinstance(m, cls):
                raise TypeError(f"metric {name} already registered as {m.kind}")
            return m

    def counter(self, name: str, help_text: str = "") -> Counter:
        return self._get(Counter, name, help_text)  # type: ignore[return-value]

    def gauge(self, name: str, help_text: str = "") -> Gauge:
        return self._get(Gauge, name, help_text)  # type: ignore[return-value]

    def histogram(self, name: str, help_text: str = "") -> Histogram:
        return self._get(Histogram, name, help_text)  # type: ignore[return-value]

    def expose(self) -> str:
        out: list[str] = []
        for m in self._metrics.values():
            out.append(f"# HELP {m.name} {m.help}")
            out.append(f"# TYPE {m.name} {m.kind}")
            out.extend(m.expose())
        return "\n".join(out) + "\n"


REGISTRY = Registry()
