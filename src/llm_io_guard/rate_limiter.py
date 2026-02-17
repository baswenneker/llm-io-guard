"""Rate limiting for agent workflows."""

import asyncio
import threading
import time
from dataclasses import dataclass, field

_SECONDS_PER_MINUTE: int = 60
_SECONDS_PER_DAY: int = 86_400


@dataclass
class RateLimiter:
    """Simple token-bucket rate limiter."""

    max_requests_per_minute: int = 60
    max_cost_per_day_usd: float = 50.0
    _request_times: list[float] = field(default_factory=list)
    _daily_cost: float = 0.0
    _cost_reset_time: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Initialize locks for thread-safe and async-safe access."""
        self._async_lock: asyncio.Lock | None = None
        self._sync_lock = threading.Lock()

    def check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < _SECONDS_PER_MINUTE]
        return len(self._request_times) < self.max_requests_per_minute

    def check_cost_limit(self, estimated_cost: float) -> bool:
        """Check if we're within daily cost limits."""
        now = time.time()
        if now - self._cost_reset_time > _SECONDS_PER_DAY:
            self._daily_cost = 0.0
            self._cost_reset_time = now
        return self._daily_cost + estimated_cost <= self.max_cost_per_day_usd

    def record_request(self, cost: float = 0.0) -> None:
        """Record a request for rate limiting."""
        self._request_times.append(time.time())
        self._daily_cost += cost

    async def aacquire(self, estimated_cost: float = 0.0) -> bool:
        """Atomically check limits and record a request (async)."""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        async with self._async_lock:
            if not self.check_rate_limit():
                return False
            if not self.check_cost_limit(estimated_cost):
                return False
            self.record_request(estimated_cost)
            return True

    def acquire(self, estimated_cost: float = 0.0) -> bool:
        """Atomically check limits and record a request (sync)."""
        with self._sync_lock:
            if not self.check_rate_limit():
                return False
            if not self.check_cost_limit(estimated_cost):
                return False
            self.record_request(estimated_cost)
            return True
