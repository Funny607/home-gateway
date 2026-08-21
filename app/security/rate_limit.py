from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int = 0


class SlidingWindowRateLimiter:
    """Small in-memory limiter for a single-process local gateway."""

    def __init__(self, *, max_keys: int = 10000) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._last_seen: dict[str, float] = {}
        self._max_keys = max_keys
        self._lock = threading.Lock()

    def check(self, key: str, *, limit: int, window_seconds: int, block_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        with self._lock:
            if key not in self._last_seen and len(self._last_seen) >= self._max_keys:
                stale_before = now - max(window_seconds, block_seconds)
                stale = [item for item, seen in self._last_seen.items() if seen < stale_before]
                for item in stale:
                    self._events.pop(item, None)
                    self._blocked_until.pop(item, None)
                    self._last_seen.pop(item, None)
                if len(self._last_seen) >= self._max_keys:
                    oldest = min(self._last_seen, key=self._last_seen.get)
                    self._events.pop(oldest, None)
                    self._blocked_until.pop(oldest, None)
                    self._last_seen.pop(oldest, None)
            self._last_seen[key] = now
            blocked_until = self._blocked_until.get(key, 0.0)
            if blocked_until > now:
                return RateLimitDecision(False, max(1, int(blocked_until - now + 0.999)))
            events = self._events[key]
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                self._blocked_until[key] = now + block_seconds
                events.clear()
                return RateLimitDecision(False, block_seconds)
            events.append(now)
            return RateLimitDecision(True)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
            self._blocked_until.pop(key, None)
            self._last_seen.pop(key, None)
