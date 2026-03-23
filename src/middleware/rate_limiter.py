"""In-memory rate limiter middleware."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration per endpoint category."""

    token_per_minute: int = 30
    authorize_per_minute: int = 60
    login_per_minute: int = 10
    admin_per_minute: int = 120


class RateLimiter:
    """In-memory sliding window rate limiter."""

    __slots__ = ("_lock", "_requests")

    def __init__(self) -> None:
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window: int = 60) -> tuple[bool, int]:
        """Check if request is within rate limit.

        Returns (allowed, retry_after_seconds).
        """
        now = time.monotonic()
        cutoff = now - window

        async with self._lock:
            timestamps = self._requests[key]
            timestamps[:] = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= limit:
                oldest = timestamps[0] if timestamps else now
                retry_after = int(oldest + window - now) + 1
                return False, retry_after

            timestamps.append(now)
            return True, 0

    async def cleanup(self) -> None:
        """Remove expired entries."""
        now = time.monotonic()
        cutoff = now - 120

        async with self._lock:
            expired = [k for k, v in self._requests.items() if all(t <= cutoff for t in v)]
            for k in expired:
                del self._requests[k]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for FastAPI."""

    __slots__ = ("_config", "_limiter")

    def __init__(self, app: object, config: RateLimitConfig | None = None) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._config = config or RateLimitConfig()
        self._limiter = RateLimiter()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Apply rate limiting based on endpoint category."""
        path = request.url.path
        method = request.method

        limit_info = self._get_limit(path, method, request)
        if not limit_info:
            return await call_next(request)

        key, limit = limit_info
        allowed, retry_after = await self._limiter.check(key, limit)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "retry_after": retry_after},
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)

    def _get_limit(self, path: str, method: str, request: Request) -> tuple[str, int] | None:
        """Determine rate limit key and limit for the request."""
        client_ip = request.client.host if request.client else "unknown"

        if path == "/oauth/token" and method == "POST":
            return f"token:{client_ip}", self._config.token_per_minute

        if path == "/oauth/authorize" and method == "GET":
            return f"authorize:{client_ip}", self._config.authorize_per_minute

        if path == "/oauth/authorize/login" and method == "POST":
            return f"login:{client_ip}", self._config.login_per_minute

        if path.startswith("/admin/") and method in ("GET", "POST", "PUT", "DELETE"):
            return f"admin:{client_ip}", self._config.admin_per_minute

        return None
