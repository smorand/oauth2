"""OpenID Connect endpoints (Discovery, JWKS, UserInfo)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from config import Settings
from dependencies import AppDependencies

logger = logging.getLogger(__name__)


def create_oidc_router(deps: AppDependencies, settings: Settings) -> APIRouter:
    """Create OIDC router."""
    router = APIRouter(tags=["oidc"])

    @router.get("/.well-known/openid-configuration")
    async def openid_configuration() -> JSONResponse:
        issuer = settings.issuer_url
        return JSONResponse(
            content={
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/oauth/authorize",
                "token_endpoint": f"{issuer}/oauth/token",
                "userinfo_endpoint": f"{issuer}/oidc/userinfo",
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "introspection_endpoint": f"{issuer}/oauth/introspect",
                "revocation_endpoint": f"{issuer}/oauth/revoke",
                "device_authorization_endpoint": f"{issuer}/oauth/device/authorize",
                "registration_endpoint": f"{issuer}/auth/register",
                "scopes_supported": ["openid", "profile", "email"],
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "authorization_code",
                    "client_credentials",
                    "refresh_token",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
            }
        )

    @router.get("/.well-known/jwks.json")
    async def jwks() -> JSONResponse:
        return JSONResponse(content=deps.key_manager.get_jwks())

    @router.get("/oidc/userinfo")
    async def userinfo(
        authorization: str = Header(default=""),
    ) -> JSONResponse:
        if not authorization.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token"},
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        token = authorization[7:]
        try:
            claims = deps.jwt_handler.decode_token(token)
        except Exception:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token"},
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        jti = claims.get("jti", "")
        if jti and await deps.storage.is_token_revoked(jti):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token"},
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        scope = claims.get("scope", "")
        scopes = scope.split() if scope else []

        if "openid" not in scopes:
            return JSONResponse(status_code=403, content={"error": "insufficient_scope"})

        user_id = claims.get("sub", "")
        user = await deps.user_service.get_user(user_id)
        if not user:
            return JSONResponse(status_code=404, content={"error": "user_not_found"})

        result: dict[str, object] = {"sub": user.id}

        if "profile" in scopes:
            result["name"] = user.name

        if "email" in scopes:
            result["email"] = user.email
            result["email_verified"] = True

        return JSONResponse(content=result)

    return router
