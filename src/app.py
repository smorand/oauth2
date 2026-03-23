"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from config import Settings
from dependencies import AppDependencies
from logging_config import setup_logging
from routes.admin import create_admin_router
from routes.auth import create_auth_router
from routes.federation import create_federation_router
from routes.health import create_health_router
from routes.oauth import create_oauth_router
from routes.oidc import create_oidc_router
from tracing import configure_tracing

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if settings is None:
        settings = Settings()

    setup_logging(log_file="oauth2.log")
    configure_tracing(trace_file=settings.trace_log_path)

    deps = AppDependencies(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await deps.initialize()
        logger.info("OAuth2 server started (issuer: %s)", settings.issuer_url)
        yield
        logger.info("OAuth2 server shutting down")

    application = FastAPI(
        title="OAuth2 Authorization Server",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    application.add_middleware(SessionMiddleware, secret_key=settings.csrf_secret)

    application.state.deps = deps
    application.state.settings = settings

    templates_dir = _get_templates_dir()
    application.state.templates = Jinja2Templates(directory=str(templates_dir))

    application.include_router(create_health_router(deps))
    application.include_router(create_oauth_router(deps, settings))
    application.include_router(create_auth_router(deps, settings))
    application.include_router(create_oidc_router(deps, settings))
    application.include_router(create_admin_router(deps))
    application.include_router(create_federation_router(deps, settings))

    return application


def _get_templates_dir() -> str:
    """Get the templates directory path."""
    import importlib.resources

    try:
        return str(importlib.resources.files("templates"))
    except (ModuleNotFoundError, TypeError):
        from pathlib import Path

        return str(Path(__file__).parent / "templates")
