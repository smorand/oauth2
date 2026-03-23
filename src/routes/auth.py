"""Authentication and consent management endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from config import Settings
from dependencies import AppDependencies
from models.schemas import ConsentResponse, UserRegisterRequest, UserResponse
from services.consent_service import ConsentServiceError
from services.user_service import UserServiceError

logger = logging.getLogger(__name__)


def create_auth_router(deps: AppDependencies, _settings: Settings) -> APIRouter:
    """Create authentication router."""
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/register", status_code=201)
    async def register(body: UserRegisterRequest) -> JSONResponse:
        try:
            user = await deps.user_service.register(body.email, body.password, body.name)
        except UserServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(
            status_code=201,
            content=UserResponse(
                id=user.id,
                email=user.email,
                name=user.name,
                role=user.role.value,
                status=user.status.value,
                created_at=user.created_at,
            ).model_dump(mode="json"),
        )

    @router.get("/consents")
    async def list_consents(
        authorization: str = Header(...),
    ) -> JSONResponse:
        user_id = await _extract_user_id(deps, authorization)
        if not user_id:
            return JSONResponse(status_code=401, content={"error": "Invalid or missing token"})

        consents = await deps.consent_service.get_user_consents(user_id)
        result = []
        for consent in consents:
            client = await deps.client_service.get_client(consent.client_id)
            client_name = client.name if client else "Unknown"
            result.append(
                ConsentResponse(
                    id=consent.id,
                    client_id=consent.client_id,
                    client_name=client_name,
                    scopes=list(consent.scopes),
                    granted_at=consent.granted_at,
                ).model_dump(mode="json")
            )
        return JSONResponse(content=result)

    @router.delete("/consents/{consent_id}", status_code=204)
    async def revoke_consent(
        consent_id: str,
        authorization: str = Header(...),
    ) -> JSONResponse:
        user_id = await _extract_user_id(deps, authorization)
        if not user_id:
            return JSONResponse(status_code=401, content={"error": "Invalid or missing token"})

        try:
            consent = await deps.storage.get_consent(consent_id)
            consent_client_id = consent.client_id if consent else ""
            await deps.consent_service.revoke_consent(consent_id, user_id)
            await deps.token_service.revoke_tokens_for_user_client(user_id, consent_client_id)
        except ConsentServiceError as exc:
            return JSONResponse(status_code=exc.code, content={"error": str(exc)})

        return JSONResponse(status_code=204, content=None)

    return router


async def _extract_user_id(deps: AppDependencies, authorization: str) -> str:
    """Extract user_id from Bearer token."""
    if not authorization.startswith("Bearer "):
        return ""
    token = authorization[7:]
    try:
        claims = deps.jwt_handler.decode_token(token)
        return str(claims.get("sub", ""))
    except Exception:
        return ""
