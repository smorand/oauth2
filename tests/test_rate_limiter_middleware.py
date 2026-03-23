"""Tests for RateLimitMiddleware dispatch and _get_limit."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from middleware.rate_limiter import RateLimitConfig, RateLimitMiddleware


def _build_app(config: RateLimitConfig | None = None) -> FastAPI:
    """Build a minimal FastAPI app with rate limiting."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(lifespan=lifespan)
    app.add_middleware(RateLimitMiddleware, config=config)

    @app.post("/oauth/token")
    async def token() -> JSONResponse:
        return JSONResponse(content={"ok": True})

    @app.get("/oauth/authorize")
    async def authorize() -> JSONResponse:
        return JSONResponse(content={"ok": True})

    @app.post("/oauth/authorize/login")
    async def login() -> JSONResponse:
        return JSONResponse(content={"ok": True})

    @app.get("/admin/clients")
    async def admin_clients() -> JSONResponse:
        return JSONResponse(content={"ok": True})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(content={"ok": True})

    return app


class TestRateLimitMiddleware:
    async def test_unmatched_path_not_limited(self) -> None:
        app = _build_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for _ in range(50):
                resp = await client.get("/health")
                assert resp.status_code == 200

    async def test_token_endpoint_rate_limited(self) -> None:
        config = RateLimitConfig(token_per_minute=3)
        app = _build_app(config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for _ in range(3):
                resp = await client.post("/oauth/token", data={"grant_type": "test"})
                assert resp.status_code != 429
            resp = await client.post("/oauth/token", data={"grant_type": "test"})
            assert resp.status_code == 429
            body = resp.json()
            assert body["error"] == "rate_limit_exceeded"
            assert "retry_after" in body
            assert "Retry-After" in resp.headers

    async def test_authorize_endpoint_rate_limited(self) -> None:
        config = RateLimitConfig(authorize_per_minute=2)
        app = _build_app(config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for _ in range(2):
                resp = await client.get("/oauth/authorize")
                assert resp.status_code == 200
            resp = await client.get("/oauth/authorize")
            assert resp.status_code == 429

    async def test_login_endpoint_rate_limited(self) -> None:
        config = RateLimitConfig(login_per_minute=2)
        app = _build_app(config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for _ in range(2):
                resp = await client.post("/oauth/authorize/login")
                assert resp.status_code == 200
            resp = await client.post("/oauth/authorize/login")
            assert resp.status_code == 429

    async def test_admin_endpoint_rate_limited(self) -> None:
        config = RateLimitConfig(admin_per_minute=2)
        app = _build_app(config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for _ in range(2):
                resp = await client.get("/admin/clients")
                assert resp.status_code == 200
            resp = await client.get("/admin/clients")
            assert resp.status_code == 429

    async def test_default_config(self) -> None:
        app = _build_app()  # Uses default config
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
