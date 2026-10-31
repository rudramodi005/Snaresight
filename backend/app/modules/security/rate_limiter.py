"""Thread-safe in-memory sliding-window rate limiter for sensitive authentication endpoints.

Prevents brute-force credential stuffing and password guessing attacks.
"""

import time
import threading
from typing import Dict, List


class SlidingWindowRateLimiter:
    """Sliding-window counter rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: Dict[str, List[float]] = {}

    def is_allowed(self, key: str, max_attempts: int, window_seconds: int) -> bool:
        """Determines if a request from key is permitted under the rate limit."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._attempts.get(key, [])
            # Filter out timestamps older than the sliding window
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._attempts[key] = valid_timestamps

            return len(valid_timestamps) < max_attempts

    def record_attempt(self, key: str) -> None:
        """Records an attempt timestamp for the specified key."""
        now = time.time()
        with self._lock:
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key].append(now)

    def reset(self, key: str) -> None:
        """Resets the attempt history for a key upon successful authentication."""
        with self._lock:
            self._attempts.pop(key, None)

    def get_remaining_attempts(self, key: str, max_attempts: int, window_seconds: int) -> int:
        """Returns the number of remaining attempts before lockout."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._attempts.get(key, [])
            valid_count = len([t for t in timestamps if t > cutoff])
            return max(0, max_attempts - valid_count)


# Global rate limiter instance for auth endpoints
auth_rate_limiter = SlidingWindowRateLimiter()

