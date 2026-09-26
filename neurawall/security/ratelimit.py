"""Token-bucket rate limiting and bounded budgets.

Used for console API requests, login attempts, Tier 2 invocation per node and the
Tier 3 cost budget (blueprint §5.4: "a traffic flood cannot trigger unbounded
inference spend").
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict


class TokenBucket:
    def __init__(self, rate_per_second: float, burst: float | None = None) -> None:
        self.rate = rate_per_second
        self.capacity = burst if burst is not None else max(1.0, rate_per_second)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False


class KeyedRateLimiter:
    """One bucket per key (client IP, user, node), LRU-bounded so keys cannot exhaust memory."""

    def __init__(self, rate_per_second: float, burst: float | None = None, max_keys: int = 10000):
        self.rate = rate_per_second
        self.burst = burst
        self.max_keys = max_keys
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self.rate, self.burst)
                self._buckets[key] = bucket
                if len(self._buckets) > self.max_keys:
                    self._buckets.popitem(last=False)
            else:
                self._buckets.move_to_end(key)
        return bucket.try_acquire(cost)


class HourlyBudget:
    """Fixed-window call budget; the circuit breaker for Tier 3 spend."""

    def __init__(self, max_calls_per_hour: int) -> None:
        self.max_calls = max_calls_per_hour
        self._window = int(time.time() // 3600)
        self._used = 0
        self._lock = threading.Lock()

    def try_spend(self) -> bool:
        with self._lock:
            window = int(time.time() // 3600)
            if window != self._window:
                self._window, self._used = window, 0
            if self._used >= self.max_calls:
                return False
            self._used += 1
            return True

    @property
    def remaining(self) -> int:
        return max(0, self.max_calls - self._used)
