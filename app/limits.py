"""A tiny in-process rate limiter.

One process only. When this service runs behind multiple workers or replicas,
move the counter to Redis or enforce the limit at the gateway. The point here is
to stop a single client from hammering an expensive endpoint.
"""

from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Deque, Dict, Optional


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = Lock()

    def retry_after(self, key: str) -> Optional[int]:
        """Record a hit and return None, or return seconds to wait if limited."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            cutoff = now - self.window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self.limit:
                return max(1, int(self.window_seconds - (now - hits[0])) + 1)

            hits.append(now)
            if len(self._hits) > self.max_keys:
                self._prune(cutoff)
            return None

    def _prune(self, cutoff: float) -> None:
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in stale:
            self._hits.pop(key, None)
