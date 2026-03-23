"""Tests for middleware: rate limiter, security headers."""

from __future__ import annotations

import pytest

from middleware.rate_limiter import RateLimitConfig, RateLimiter


class TestRateLimiter:
    async def test_allows_within_limit(self) -> None:
        limiter = RateLimiter()
        allowed, retry = await limiter.check("key1", limit=5)
        assert allowed is True
        assert retry == 0

    async def test_blocks_over_limit(self) -> None:
        limiter = RateLimiter()
        for _ in range(5):
            await limiter.check("key2", limit=5)
        allowed, retry = await limiter.check("key2", limit=5)
        assert allowed is False
        assert retry > 0

    async def test_different_keys_independent(self) -> None:
        limiter = RateLimiter()
        for _ in range(5):
            await limiter.check("keyA", limit=5)
        allowed, _ = await limiter.check("keyB", limit=5)
        assert allowed is True

    async def test_cleanup(self) -> None:
        limiter = RateLimiter()
        await limiter.check("cleanup_key", limit=10)
        await limiter.cleanup()
        # Should not raise


class TestRateLimitConfig:
    def test_defaults(self) -> None:
        config = RateLimitConfig()
        assert config.token_per_minute == 30
        assert config.authorize_per_minute == 60
        assert config.login_per_minute == 10
        assert config.admin_per_minute == 120

    def test_custom_values(self) -> None:
        config = RateLimitConfig(token_per_minute=100)
        assert config.token_per_minute == 100
