"""Small bounded, per-process ingest rate limiter (NOT distributed WAF protection)."""
from __future__ import annotations

from dataclasses import dataclass
import math
from threading import Lock
import time
from typing import Callable


@dataclass
class _Bucket:
    start: float
    hits: int
    warned: bool = False


class IngestRateLimiter:
    """Fixed-window IP and authenticated token limits. No unbounded peer map.

    Use only the TCP peer from ASGI, never client-supplied forwarded headers.
    Reset is per worker/restart. For shared/LAN production add edge throttling.
    """

    def __init__(self, peer_limit: int = 60, token_limit: int = 30,
                 window_seconds: int = 60, max_keys: int = 4096,
                 clock: Callable[[], float] = time.monotonic):
        if not all(type(v) is int and v > 0
                   for v in (peer_limit, token_limit, window_seconds, max_keys)):
            raise ValueError("Limiter settings must be positive integers")
        self.peer_limit = peer_limit
        self.token_limit = token_limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def check_peer(self, peer: str) -> tuple[int, bool]:
        return self._check("peer:" + peer, self.peer_limit)

    def check_token(self, token_id: str) -> tuple[int, bool]:
        return self._check("token:" + token_id, self.token_limit)

    def _check(self, key: str, limit: int) -> tuple[int, bool]:
        """(retry_after_seconds, first_rejection_this_window). 0 means allowed."""
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(key)
            if bucket is not None and now - bucket.start >= self.window_seconds:
                del self._buckets[key]
                bucket = None
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._buckets = {
                        name: record for name, record in self._buckets.items()
                        if now - record.start < self.window_seconds
                    }
                    if len(self._buckets) >= self.max_keys:
                        return self.window_seconds, False
                bucket = _Bucket(now, 0)
                self._buckets[key] = bucket
            if bucket.hits >= limit:
                first = not bucket.warned
                bucket.warned = True
                remaining = max(1, math.ceil(self.window_seconds - (now - bucket.start)))
                return remaining, first
            bucket.hits += 1
            return 0, False
