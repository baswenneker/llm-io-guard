"""Rate limiting for agent workflows."""

import time
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    """Simple token-bucket rate limiter."""

    max_requests_per_minute: int = 60
    max_cost_per_day_usd: float = 50.0
    _request_times: list[float] = field(default_factory=list)
    _daily_cost: float = 0.0
    _cost_reset_time: float = field(default_factory=time.time)

    def check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < 60]
        return len(self._request_times) < self.max_requests_per_minute

    def check_cost_limit(self, estimated_cost: float) -> bool:
        """Check if we're within daily cost limits."""
        now = time.time()
        if now - self._cost_reset_time > 86400:
            self._daily_cost = 0.0
            self._cost_reset_time = now
        return self._daily_cost + estimated_cost <= self.max_cost_per_day_usd

    def record_request(self, cost: float = 0.0) -> None:
        """Record a request for rate limiting."""
        self._request_times.append(time.time())
        self._daily_cost += cost
