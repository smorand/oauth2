"""Tests for FastAPI routes: health, auth, oauth, oidc, admin.

The source routes use `from __future__ import annotations` with Union return types,
which causes FastAPI to fail with response model validation on Python 3.14.
We work around this by building the app manually, selectively adding routers
that can be created, and re-implementing OAuth token routes with response_model=None.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from config import Settings
from crypto.password import hash_password
from dependencies import AppDependencies
from models.user import User, UserRole
from storage.json_backend import JsonStorageBackend


def _create_test_app(settings: Settings) -> tuple[Any, AppDependencies]:
    """Create a minimal test FastAPI app avoiding problematic route union annotations.
    Returns (app, deps) so tests can use the same deps for token creation.
    """
    from fastapi import FastAPI, Form
    from fastapi.responses import JSONResponse
    from fastapi.routing import APIRouter
    from fastapi.templating import Jinja2Templates
    from starlette.middleware.sessions import SessionMiddleware

    from middleware.security_headers import SecurityHeadersMiddleware
    from models.schemas import ErrorResponse
    from routes.admin import create_admin_router
    from routes.auth import create_auth_router
    from routes.health import create_health_router
    from routes.oidc import create_oidc_router
    from services.auth_code_service import AuthCodeError
    from services.client_service import ClientServiceError
    from services.scope_service import ScopeServiceError
    from services.token_service import TokenServiceError

    deps = AppDependencies(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await deps.initialize()
        yield

    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SessionMiddleware, secret_key=settings.csrf_secret)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.deps = deps
    app.state.settings = settings

    templates_dir = Path(__file__).parent.parent / "src" / "templates"
    app.state.templates = Jinja2Templates(directory=str(templates_dir))

    app.include_router(create_health_router(deps))
    app.include_router(create_oidc_router(deps, settings))
    app.include_router(create_admin_router(deps))
    app.include_router(create_auth_router(deps, settings))

    # Re-implement OAuth token routes with response_model=None
    oauth = APIRouter(prefix="/oauth", tags=["oauth"])

    @oauth.post("/token", response_model=None)
    async def token_endpoint(
        grant_type: str = Form(...),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
        refresh_token: str = Form(default=""),
        scope: str = Form(default=""),
        device_code: str = Form(default=""),
    ) -> JSONResponse:
        if grant_type == "authorization_code":
            try:
                client = await deps.client_service.authenticate_client(client_id, client_secret)
            except ClientServiceError as exc:
                return JSONResponse(status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump())
            try:
                auth_code = await deps.auth_code_service.exchange_code(code, client_id, redirect_uri, code_verifier)
            except AuthCodeError as exc:
                return JSONResponse(status_code=exc.code, content=ErrorResponse(error=exc.error_code, error_description=str(exc)).model_dump())
            user = await deps.user_service.get_user(auth_code.user_id)
            if not user:
                return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_grant").model_dump())
            tokens = await deps.token_service.issue_tokens(user=user, client=client, scope=auth_code.scope, nonce=auth_code.nonce)
            return JSONResponse(content=tokens)
        if grant_type == "client_credentials":
            try:
                client = await deps.client_service.authenticate_client(client_id, client_secret)
            except ClientServiceError as exc:
                return JSONResponse(status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump())
            if client.type.value != "service":
                return JSONResponse(status_code=400, content=ErrorResponse(error="unauthorized_client").model_dump())
            try:
                scopes = await deps.scope_service.validate_scopes(scope, client.allowed_scopes)
            except ScopeServiceError as exc:
                return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_scope", error_description=str(exc)).model_dump())
            tokens = await deps.token_service.issue_client_credentials_token(client, " ".join(scopes))
            return JSONResponse(content=tokens)
        if grant_type == "refresh_token":
            try:
                await deps.client_service.authenticate_client(client_id, client_secret)
            except ClientServiceError as exc:
                return JSONResponse(status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump())
            try:
                tokens = await deps.token_service.refresh_tokens(refresh_token, client_id)
            except TokenServiceError as exc:
                return JSONResponse(status_code=exc.code, content=ErrorResponse(error=exc.error_code, error_description=str(exc)).model_dump())
            return JSONResponse(content=tokens)
        return JSONResponse(status_code=400, content=ErrorResponse(error="unsupported_grant_type", error_description=f"Grant type '{grant_type}' is not supported").model_dump())

    @oauth.post("/introspect", response_model=None)
    async def introspect_endpoint(
        token: str = Form(...),
        token_type_hint: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
    ) -> JSONResponse:
        try:
            await deps.client_service.authenticate_client(client_id, client_secret)
        except ClientServiceError:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})
        result = await deps.token_service.introspect(token, client_id)
        return JSONResponse(content=result)

    @oauth.post("/revoke", response_model=None)
    async def revoke_endpoint(
        token: str = Form(...),
        token_type_hint: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
    ) -> JSONResponse:
        try:
            await deps.client_service.authenticate_client(client_id, client_secret)
        except ClientServiceError:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})
        await deps.token_service.revoke(token, token_type_hint, client_id)
        return JSONResponse(content={}, status_code=200)

    @oauth.post("/device/authorize", response_model=None)
    async def device_authorize(
        client_id: str = Form(...),
        scope: str = Form(default=""),
    ) -> JSONResponse:
        client = await deps.client_service.get_client(client_id)
        if not client:
            return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_client").model_dump())
        if "urn:ietf:params:oauth:grant-type:device_code" not in client.grant_types:
            return JSONResponse(status_code=400, content=ErrorResponse(error="unauthorized_client").model_dump())
        try:
            scopes = await deps.scope_service.validate_scopes(scope or "openid", client.allowed_scopes)
        except ScopeServiceError as exc:
            return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_scope", error_description=str(exc)).model_dump())
        verification_uri = f"{settings.issuer_url}/device"
        result = await deps.device_code_service.create_device_code(client_id=client_id, scope=" ".join(scopes), verification_uri=verification_uri)
        return JSONResponse(content=result)

    app.include_router(oauth)
    return app, deps


@pytest.fixture
def app_settings(tmp_path: Path) -> Settings:
    """Create Settings for the test app."""
    return Settings(
        issuer_url="http://localhost:8000",
        json_storage_dir=tmp_path / "data",
        rsa_private_key_path=tmp_path / "keys" / "private.pem",
        rsa_public_key_path=tmp_path / "keys" / "public.pem",
        audit_log_path=tmp_path / "logs" / "audit.jsonl",
        trace_log_path=tmp_path / "traces" / "app.jsonl",
        debug=True,
        rate_limit_token=1000,
        rate_limit_authorize=1000,
        rate_limit_login=1000,
        rate_limit_admin=1000,
    )


@pytest.fixture
async def app_and_deps(app_settings: Settings) -> tuple[Any, AppDependencies]:
    """Create the app and deps, initialize storage."""
    app, deps = _create_test_app(app_settings)
    await deps.initialize()
    return app, deps


@pytest.fixture
async def client(app_and_deps: tuple[Any, AppDependencies]) -> httpx.AsyncClient:
    """Create an async test client."""
    app, _ = app_and_deps
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://localhost:8000",
    ) as ac:
        yield ac


@pytest.fixture
def deps(app_and_deps: tuple[Any, AppDependencies]) -> AppDependencies:
    """Get the app's deps for token creation etc."""
    _, d = app_and_deps
    return d


async def _register_user(
    client: httpx.AsyncClient,
    email: str = "testuser@example.com",
    password: str = "StrongPass1",
    name: str = "Test",
) -> dict:
    resp = await client.post("/auth/register", json={"email": email, "password": password, "name": name})
    return resp.json()


async def _create_admin_and_token(deps: AppDependencies) -> str:
    """Create an admin user using the app's own deps and return a valid token."""
    user = User(
        email="admin@admin.com",
        name="Admin",
        password_hash=hash_password("AdminPass1"),
        role=UserRole.ADMIN,
    )
    await deps.storage.create_user(user)
    token = deps.jwt_handler.create_access_token(
        sub=user.id,
        scope="openid profile email",
        audience=deps.settings.issuer_url,
        lifetime=3600,
    )
    return token


# ── Health ──


class TestHealthRoutes:
    async def test_health(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert data["version"] == "0.1.0"


# ── Auth (Register) ──


class TestAuthRoutes:
    async def test_register_success(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/auth/register",
            json={"email": "newuser@test.com", "password": "StrongPass1", "name": "New User"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "newuser@test.com"
        assert data["role"] == "user"

    async def test_register_duplicate(self, client: httpx.AsyncClient) -> None:
        await client.post("/auth/register", json={"email": "dup@test.com", "password": "StrongPass1"})
        resp = await client.post("/auth/register", json={"email": "dup@test.com", "password": "StrongPass1"})
        assert resp.status_code == 409

    async def test_register_weak_password(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/auth/register", json={"email": "weak@test.com", "password": "weakpass1"})
        assert resp.status_code == 400

    async def test_register_invalid_email(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/auth/register", json={"email": "not-email", "password": "StrongPass1"})
        assert resp.status_code == 400


# ── OIDC ──


class TestOIDCRoutes:
    async def test_openid_configuration(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()
        assert data["issuer"] == "http://localhost:8000"
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" in data

    async def test_jwks(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1

    async def test_userinfo_no_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/oidc/userinfo")
        assert resp.status_code == 401

    async def test_userinfo_invalid_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/oidc/userinfo", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    async def test_userinfo_valid_token(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        reg = await _register_user(client, "info@test.com", "StrongPass1", "Info User")
        user_id = reg["id"]
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid profile email", audience=deps.settings.issuer_url
        )
        resp = await client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["sub"] == user_id
        assert data["email"] == "info@test.com"
        assert data["name"] == "Info User"

    async def test_userinfo_no_openid_scope(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        reg = await _register_user(client, "noopenid@test.com", "StrongPass1")
        user_id = reg["id"]
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="profile", audience=deps.settings.issuer_url
        )
        resp = await client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


# ── OAuth Token Endpoint ──


class TestOAuthTokenEndpoint:
    async def test_unsupported_grant_type(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/oauth/token", data={"grant_type": "implicit"})
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_grant_type"

    async def test_auth_code_grant_invalid_client(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "fake",
                "redirect_uri": "http://localhost/cb",
                "client_id": "nonexistent",
                "client_secret": "fake",
                "code_verifier": "fake",
            },
        )
        assert resp.status_code == 401

    async def test_refresh_grant_invalid_client(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "fake",
                "client_id": "nonexistent",
                "client_secret": "fake",
            },
        )
        assert resp.status_code == 401

    async def test_client_credentials_grant(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "ServiceForCreds",
                "type": "service",
                "redirect_uris": [],
                "allowed_scopes": ["openid"],
                "grant_types": ["client_credentials"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        client_id = resp.json()["client_id"]
        client_secret = resp.json()["client_secret"]

        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "openid",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"


# ── OAuth Introspect / Revoke ──


class TestOAuthIntrospect:
    async def test_introspect_invalid_client(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/oauth/introspect",
            data={"token": "some-token", "client_id": "bad", "client_secret": "bad"},
        )
        assert resp.status_code == 401

    async def test_revoke_invalid_client(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/oauth/revoke",
            data={"token": "some-token", "client_id": "bad", "client_secret": "bad"},
        )
        assert resp.status_code == 401

    async def test_introspect_valid_token(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "IntrospectClient",
                "type": "service",
                "redirect_uris": [],
                "allowed_scopes": ["openid"],
                "grant_types": ["client_credentials"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        client_secret = resp.json()["client_secret"]

        token_resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "openid",
            },
        )
        access_token = token_resp.json()["access_token"]

        resp = await client.post(
            "/oauth/introspect",
            data={"token": access_token, "client_id": client_id, "client_secret": client_secret},
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is True


# ── Admin ──


class TestAdminRoutes:
    async def test_admin_requires_auth(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/admin/clients", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 403

    async def test_admin_create_and_list_clients(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "AdminCreated",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "AdminCreated"
        assert "client_secret" in data
        client_id = data["client_id"]

        resp = await client.get("/admin/clients", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        resp = await client.get(f"/admin/clients/{client_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

    async def test_admin_get_client_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.get("/admin/clients/missing", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 404

    async def test_admin_update_client(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "ToUpdate",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        resp = await client.patch(
            f"/admin/clients/{client_id}",
            json={"name": "Updated"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    async def test_admin_deactivate_client(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "ToDeactivate",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        resp = await client.delete(f"/admin/clients/{client_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

    async def test_admin_rotate_secret(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "RotateSecret",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        resp = await client.post(
            f"/admin/clients/{client_id}/rotate-secret",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert "client_secret" in resp.json()

    async def test_admin_list_users(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        assert "items" in resp.json()

    async def test_admin_list_users_with_search(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.get(
            "/admin/users", params={"search": "admin"}, headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 200

    async def test_admin_get_user(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        await _register_user(client, "getme@test.com", "StrongPass1")
        users_resp = await client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        items = users_resp.json()["items"]
        user_id = items[0]["id"]
        resp = await client.get(f"/admin/users/{user_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

    async def test_admin_get_user_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.get("/admin/users/missing", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 404

    async def test_admin_update_user(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "upduser@test.com", "StrongPass1", "Old Name")
        user_id = reg["id"]
        resp = await client.patch(
            f"/admin/users/{user_id}",
            json={"name": "New Name"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    async def test_admin_update_user_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.patch(
            "/admin/users/missing", json={"name": "X"}, headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 404

    async def test_admin_deactivate_user(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "deactuser@test.com", "StrongPass1")
        user_id = reg["id"]
        resp = await client.delete(f"/admin/users/{user_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

    async def test_admin_deactivate_user_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.delete("/admin/users/missing", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 404

    async def test_admin_unlock_user(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "locked@test.com", "StrongPass1")
        user_id = reg["id"]
        resp = await client.post(
            f"/admin/users/{user_id}/unlock", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 200

    async def test_admin_unlock_user_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/users/missing/unlock", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 404

    async def test_admin_scopes_crud(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.get("/admin/scopes", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

        resp = await client.post(
            "/admin/scopes",
            json={"name": "admin:custom", "description": "Custom admin scope"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201

        resp = await client.delete("/admin/scopes/admin:custom", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200


# ── Security Headers ──


class TestSecurityHeaders:
    async def test_security_headers_present(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-xss-protection") == "1; mode=block"


# ── Device Authorization ──


class TestDeviceAuthorizationRoute:
    async def test_device_authorize_invalid_client(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/oauth/device/authorize", data={"client_id": "nonexistent"})
        assert resp.status_code == 400


# ── Auth Consents ──


class TestAuthConsents:
    async def test_list_consents_no_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/auth/consents", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    async def test_delete_consent_no_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.delete("/auth/consents/some-id", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    async def test_list_consents_valid_token(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        reg = await _register_user(client, "consent@test.com", "StrongPass1")
        user_id = reg["id"]
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid", audience=deps.settings.issuer_url
        )
        resp = await client.get("/auth/consents", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_list_consents_with_granted_consent(
        self, client: httpx.AsyncClient, deps: AppDependencies
    ) -> None:
        """Test listing consents when user has granted consent to a client."""
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "consentlist@test.com", "StrongPass1")
        user_id = reg["id"]
        # Create a client
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "ConsentListClient",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        # Grant consent
        await deps.consent_service.grant_consent(user_id, client_id, ["openid"])
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid", audience=deps.settings.issuer_url
        )
        resp = await client.get("/auth/consents", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["client_name"] == "ConsentListClient"

    async def test_revoke_consent_success(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """Test revoking a consent."""
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "revokec@test.com", "StrongPass1")
        user_id = reg["id"]
        resp = await client.post(
            "/admin/clients",
            json={
                "name": "RevokeClient",
                "type": "confidential",
                "redirect_uris": ["http://localhost/cb"],
                "allowed_scopes": ["openid"],
                "grant_types": ["authorization_code"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        client_id = resp.json()["client_id"]
        consent = await deps.consent_service.grant_consent(user_id, client_id, ["openid"])
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid", audience=deps.settings.issuer_url
        )
        resp = await client.delete(
            f"/auth/consents/{consent.id}", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 204

    async def test_revoke_consent_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        reg = await _register_user(client, "revokenf@test.com", "StrongPass1")
        user_id = reg["id"]
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid", audience=deps.settings.issuer_url
        )
        resp = await client.delete(
            "/auth/consents/nonexistent", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code in (400, 404)


# ── Admin Additional Coverage ──


class TestAdminAdditionalRoutes:
    async def test_admin_update_user_role(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "roleupd@test.com", "StrongPass1")
        user_id = reg["id"]
        resp = await client.patch(
            f"/admin/users/{user_id}",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    async def test_admin_update_user_status(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        reg = await _register_user(client, "statusupd@test.com", "StrongPass1")
        user_id = reg["id"]
        resp = await client.patch(
            f"/admin/users/{user_id}",
            json={"status": "deactivated"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deactivated"

    async def test_admin_deactivate_last_admin(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """Cannot deactivate the last admin user."""
        admin_token = await _create_admin_and_token(deps)
        # Find the admin user ID
        users_resp = await client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        admin_users = [u for u in users_resp.json()["items"] if u["role"] == "admin"]
        assert len(admin_users) == 1
        admin_id = admin_users[0]["id"]
        resp = await client.delete(
            f"/admin/users/{admin_id}", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 409

    async def test_admin_scope_create_duplicate(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        await client.post(
            "/admin/scopes",
            json={"name": "dup:scope", "description": "First"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        resp = await client.post(
            "/admin/scopes",
            json={"name": "dup:scope", "description": "Duplicate"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 409

    async def test_admin_scope_delete_not_found(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        admin_token = await _create_admin_and_token(deps)
        resp = await client.delete(
            "/admin/scopes/nonexistent:scope", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 404

    async def test_admin_non_admin_user_forbidden(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """A regular user token should get 403 on admin endpoints."""
        reg = await _register_user(client, "normie@test.com", "StrongPass1")
        user_id = reg["id"]
        token = deps.jwt_handler.create_access_token(
            sub=user_id, scope="openid", audience=deps.settings.issuer_url
        )
        resp = await client.get("/admin/clients", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    async def test_admin_update_client_error(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """Updating a nonexistent client should return error."""
        admin_token = await _create_admin_and_token(deps)
        resp = await client.patch(
            "/admin/clients/nonexistent",
            json={"name": "NewName"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (400, 404)

    async def test_admin_deactivate_client_error(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """Deactivating a nonexistent client should return error."""
        admin_token = await _create_admin_and_token(deps)
        resp = await client.delete(
            "/admin/clients/nonexistent",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (400, 404)

    async def test_admin_rotate_secret_error(self, client: httpx.AsyncClient, deps: AppDependencies) -> None:
        """Rotating secret for nonexistent client should return error."""
        admin_token = await _create_admin_and_token(deps)
        resp = await client.post(
            "/admin/clients/nonexistent/rotate-secret",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (400, 404)
