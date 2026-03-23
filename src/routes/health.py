"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from dependencies import AppDependencies
from models.schemas import HealthResponse


def create_health_router(deps: AppDependencies) -> APIRouter:
    """Create health check router."""
    router = APIRouter(tags=["health"])

    @router.get("/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        storage_ok = await deps.storage.health_check()
        return HealthResponse(
            status="healthy" if storage_ok else "degraded",
            storage="ok" if storage_ok else "unavailable",
            version="0.1.0",
        )

    return router
