"""Tests for the rate limiter."""

import time

import pytest

from llm_io_guard.rate_limiter import RateLimiter


class TestRateLimit:
    """Tests for request rate limiting."""

    def test_under_rate_limit(self):
        limiter = RateLimiter(max_requests_per_minute=10)
        limiter.record_request()
        limiter.record_request()
        assert limiter.check_rate_limit() is True

    def test_over_rate_limit(self):
        limiter = RateLimiter(max_requests_per_minute=5)
        for _ in range(5):
            limiter.record_request()
        assert limiter.check_rate_limit() is False

    def test_rate_limit_window_expires(self):
        limiter = RateLimiter(max_requests_per_minute=2)
        # Simulate old requests by injecting timestamps > 60s ago
        old_time = time.time() - 61
        limiter._request_times = [old_time, old_time]
        assert limiter.check_rate_limit() is True


class TestCostLimit:
    """Tests for daily cost limiting."""

    def test_under_cost_limit(self):
        limiter = RateLimiter(max_cost_per_day_usd=10.0)
        limiter.record_request(cost=5.0)
        assert limiter.check_cost_limit(estimated_cost=3.0) is True

    def test_over_cost_limit(self):
        limiter = RateLimiter(max_cost_per_day_usd=10.0)
        limiter.record_request(cost=8.0)
        assert limiter.check_cost_limit(estimated_cost=5.0) is False

    def test_cost_resets_daily(self):
        limiter = RateLimiter(max_cost_per_day_usd=10.0)
        limiter.record_request(cost=9.0)
        # Simulate that the cost reset time was > 24h ago
        limiter._cost_reset_time = time.time() - 86401
        assert limiter.check_cost_limit(estimated_cost=5.0) is True


class TestRecordRequest:
    """Tests for recording requests."""

    def test_record_request(self):
        limiter = RateLimiter()
        assert len(limiter._request_times) == 0
        assert limiter._daily_cost == 0.0
        limiter.record_request(cost=1.50)
        assert len(limiter._request_times) == 1
        assert limiter._daily_cost == 1.50


class TestAcquire:
    """Tests for the atomic acquire method."""

    @pytest.mark.asyncio
    async def test_acquire_within_limits(self):
        """Test atomic acquire within limits."""
        limiter = RateLimiter(max_requests_per_minute=10, max_cost_per_day_usd=1.0)
        result = await limiter.aacquire(estimated_cost=0.1)
        assert result is True

    @pytest.mark.asyncio
    async def test_acquire_exceeds_rate_limit(self):
        """Test atomic acquire when rate limit exceeded."""
        limiter = RateLimiter(max_requests_per_minute=1, max_cost_per_day_usd=100.0)
        # First request succeeds
        result1 = await limiter.aacquire(estimated_cost=0.0)
        assert result1 is True
        # Second request exceeds rate limit
        result2 = await limiter.aacquire(estimated_cost=0.0)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_acquire_exceeds_cost_limit(self):
        """Test atomic acquire when cost limit exceeded."""
        limiter = RateLimiter(max_requests_per_minute=100, max_cost_per_day_usd=0.01)
        result = await limiter.aacquire(estimated_cost=0.02)
        assert result is False
