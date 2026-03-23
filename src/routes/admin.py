"""Admin API endpoints."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime

from fastapi import APIRouter, Header, Query
from fastapi.responses import JSONResponse

from dependencies import AppDependencies
from models.schemas import (
    ClientCreateRequest,
    ClientResponse,
    ClientUpdateRequest,
    ScopeCreateRequest,
    ScopeResponse,
    UserAdminResponse,
    UserUpdateRequest,
)
from models.user import UserRole, UserStatus
from services.client_service import ClientServiceError
from services.scope_service import ScopeServiceError
from services.user_service import UserServiceError

logger = logging.getLogger(__name__)


def create_admin_router(deps: AppDependencies) -> APIRouter:  # noqa: PLR0915
    """Create admin API router."""
    router = APIRouter(prefix="/admin", tags=["admin"])

    async def _require_admin(authorization: str) -> str | None:
        """Validate admin access. Returns user_id if admin, None otherwise."""
        if not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        try:
            claims = deps.jwt_handler.decode_token(token)
        except Exception:
            return None
        user_id = claims.get("sub", "")
        user = await deps.user_service.get_user(user_id)
        if not user or user.role != UserRole.ADMIN:
            return None
        return str(user_id)

    # --- Client management ---

    @router.post("/clients", status_code=201)
    async def create_client(
        body: ClientCreateRequest,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            client, secret = await deps.client_service.create_client(
                name=body.name,
                client_type=body.type,
                redirect_uris=body.redirect_uris,
                allowed_scopes=body.allowed_scopes,
                grant_types=body.grant_types,
                created_by=admin_id,
            )
        except ClientServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(
            status_code=201,
            content=ClientResponse(
                client_id=client.id,
                name=client.name,
                type=client.type.value,
                redirect_uris=list(client.redirect_uris),
                allowed_scopes=list(client.allowed_scopes),
                grant_types=list(client.grant_types),
                status=client.status.value,
                created_at=client.created_at,
                client_secret=secret,
            ).model_dump(mode="json"),
        )

    @router.get("/clients")
    async def list_clients(
        authorization: str = Header(...),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        clients, total = await deps.client_service.list_clients(page, page_size)
        items = [
            ClientResponse(
                client_id=c.id,
                name=c.name,
                type=c.type.value,
                redirect_uris=list(c.redirect_uris),
                allowed_scopes=list(c.allowed_scopes),
                grant_types=list(c.grant_types),
                status=c.status.value,
                created_at=c.created_at,
            ).model_dump(mode="json")
            for c in clients
        ]
        return JSONResponse(content={"items": items, "total": total, "page": page, "page_size": page_size})

    @router.get("/clients/{client_id}")
    async def get_client(
        client_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        client = await deps.client_service.get_client(client_id)
        if not client:
            return JSONResponse(status_code=404, content={"error": "Client not found"})

        return JSONResponse(
            content=ClientResponse(
                client_id=client.id,
                name=client.name,
                type=client.type.value,
                redirect_uris=list(client.redirect_uris),
                allowed_scopes=list(client.allowed_scopes),
                grant_types=list(client.grant_types),
                status=client.status.value,
                created_at=client.created_at,
            ).model_dump(mode="json"),
        )

    @router.patch("/clients/{client_id}")
    async def update_client(
        client_id: str,
        body: ClientUpdateRequest,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            client = await deps.client_service.update_client(
                client_id,
                name=body.name,
                redirect_uris=body.redirect_uris,
                allowed_scopes=body.allowed_scopes,
                status=body.status,
            )
        except ClientServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(
            content=ClientResponse(
                client_id=client.id,
                name=client.name,
                type=client.type.value,
                redirect_uris=list(client.redirect_uris),
                allowed_scopes=list(client.allowed_scopes),
                grant_types=list(client.grant_types),
                status=client.status.value,
                created_at=client.created_at,
            ).model_dump(mode="json"),
        )

    @router.delete("/clients/{client_id}")
    async def deactivate_client(
        client_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            await deps.client_service.deactivate_client(client_id)
        except ClientServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(status_code=200, content={"status": "deactivated"})

    @router.post("/clients/{client_id}/rotate-secret")
    async def rotate_client_secret(
        client_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            client, secret = await deps.client_service.rotate_secret(client_id)
        except ClientServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(content={"client_id": client.id, "client_secret": secret})

    # --- User management ---

    @router.get("/users")
    async def list_users(
        authorization: str = Header(...),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
        search: str = Query(default=""),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        if search:
            users, total = await deps.user_service.search_users(search, page, page_size)
        else:
            users, total = await deps.user_service.list_users(page, page_size)

        items = [
            UserAdminResponse(
                id=u.id,
                email=u.email,
                name=u.name,
                role=u.role.value,
                status=u.status.value,
                failed_login_attempts=u.failed_login_attempts,
                locked_until=u.locked_until,
                created_at=u.created_at,
                updated_at=u.updated_at,
            ).model_dump(mode="json")
            for u in users
        ]
        return JSONResponse(content={"items": items, "total": total, "page": page, "page_size": page_size})

    @router.get("/users/{user_id}")
    async def get_user(
        user_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        user = await deps.user_service.get_user(user_id)
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        return JSONResponse(
            content=UserAdminResponse(
                id=user.id,
                email=user.email,
                name=user.name,
                role=user.role.value,
                status=user.status.value,
                failed_login_attempts=user.failed_login_attempts,
                locked_until=user.locked_until,
                created_at=user.created_at,
                updated_at=user.updated_at,
            ).model_dump(mode="json"),
        )

    @router.patch("/users/{user_id}")
    async def update_user(
        user_id: str,
        body: UserUpdateRequest,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        user = await deps.user_service.get_user(user_id)
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        updates: dict[str, object] = {"updated_at": datetime.now(tz=UTC)}
        if body.role is not None:
            updates["role"] = UserRole(body.role)
        if body.status is not None:
            updates["status"] = UserStatus(body.status)
        if body.name is not None:
            updates["name"] = body.name

        updated = replace(user, **updates)  # type: ignore[arg-type]
        result = await deps.user_service.update_user(updated)

        return JSONResponse(
            content=UserAdminResponse(
                id=result.id,
                email=result.email,
                name=result.name,
                role=result.role.value,
                status=result.status.value,
                failed_login_attempts=result.failed_login_attempts,
                locked_until=result.locked_until,
                created_at=result.created_at,
                updated_at=result.updated_at,
            ).model_dump(mode="json"),
        )

    @router.delete("/users/{user_id}")
    async def deactivate_user(
        user_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        user = await deps.user_service.get_user(user_id)
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        admins, _ = await deps.user_service.list_users(page=1, page_size=1000)
        admin_count = sum(1 for u in admins if u.role == UserRole.ADMIN and u.status == UserStatus.ACTIVE)
        if user.role == UserRole.ADMIN and admin_count <= 1:
            return JSONResponse(status_code=409, content={"error": "Cannot deactivate the last admin user"})

        updated = replace(user, status=UserStatus.DEACTIVATED, updated_at=datetime.now(tz=UTC))
        await deps.user_service.update_user(updated)
        return JSONResponse(status_code=200, content={"status": "deactivated"})

    @router.post("/users/{user_id}/unlock")
    async def unlock_user(
        user_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            user = await deps.user_service.unlock_user(user_id)
        except UserServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(content={"id": user.id, "status": user.status.value})

    # --- Scope management ---

    @router.post("/scopes", status_code=201)
    async def create_scope(
        body: ScopeCreateRequest,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            scope = await deps.scope_service.create_scope(body.name, body.description)
        except ScopeServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(
            status_code=201,
            content=ScopeResponse(
                name=scope.name,
                description=scope.description,
                built_in=scope.built_in,
                created_at=scope.created_at,
            ).model_dump(mode="json"),
        )

    @router.get("/scopes")
    async def list_scopes(
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        scopes = await deps.scope_service.list_scopes()
        items = [
            ScopeResponse(
                name=s.name,
                description=s.description,
                built_in=s.built_in,
                created_at=s.created_at,
            ).model_dump(mode="json")
            for s in scopes
        ]
        return JSONResponse(content=items)

    @router.delete("/scopes/{scope_name}")
    async def delete_scope(
        scope_name: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        admin_id = await _require_admin(authorization)
        if not admin_id:
            return JSONResponse(status_code=403, content={"error": "Admin access required"})

        try:
            await deps.scope_service.delete_scope(scope_name)
        except ScopeServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(status_code=200, content={"status": "deleted"})

    return router
