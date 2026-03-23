"""Token issuance, refresh, introspection, and revocation."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import jwt as pyjwt

from crypto.jwt_handler import JWTHandler
from crypto.password import generate_opaque_token, hash_token
from models.base import generate_id
from models.client import Client
from models.token import RefreshToken, TokenRevocationEntry
from models.user import User
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)


class TokenServiceError(Exception):
    """Base error for token operations."""

    __slots__ = ("code", "error_code")

    def __init__(self, message: str, error_code: str = "invalid_request", code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.error_code = error_code


class TokenService:
    """Handles token issuance, refresh, introspection, and revocation."""

    __slots__ = (
        "_access_lifetime",
        "_audit",
        "_jwt",
        "_refresh_lifetime",
        "_storage",
    )

    def __init__(
        self,
        storage: StorageBackend,
        jwt_handler: JWTHandler,
        audit: AuditService,
        access_lifetime: int = 3600,
        refresh_lifetime: int = 2592000,
    ) -> None:
        self._storage = storage
        self._jwt = jwt_handler
        self._audit = audit
        self._access_lifetime = access_lifetime
        self._refresh_lifetime = refresh_lifetime

    async def issue_tokens(
        self,
        user: User,
        client: Client,
        scope: str,
        nonce: str = "",
        include_refresh: bool = True,
    ) -> dict[str, str | int]:
        """Issue access token, optional refresh token, and ID token."""
        access_token = self._jwt.create_access_token(
            sub=user.id,
            scope=scope,
            audience=client.id,
            lifetime=self._access_lifetime,
        )

        result: dict[str, str | int] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self._access_lifetime,
            "scope": scope,
        }

        if include_refresh:
            refresh_plain = generate_opaque_token()
            family_id = generate_id()
            refresh_record = RefreshToken(
                token_hash=hash_token(refresh_plain),
                family_id=family_id,
                user_id=user.id,
                client_id=client.id,
                scope=scope,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=self._refresh_lifetime),
            )
            await self._storage.store_refresh_token(refresh_record)
            result["refresh_token"] = refresh_plain

        scopes = scope.split()
        if "openid" in scopes:
            id_token = self._jwt.create_id_token(
                sub=user.id,
                audience=client.id,
                nonce=nonce,
            )
            result["id_token"] = id_token

        self._audit.log_event(
            "tokens_issued",
            user.id,
            "",
            "success",
            {"client_id": client.id, "scope": scope},
        )
        return result

    async def issue_client_credentials_token(
        self,
        client: Client,
        scope: str,
    ) -> dict[str, str | int]:
        """Issue access token for client credentials flow (no refresh token)."""
        access_token = self._jwt.create_access_token(
            sub=client.id,
            scope=scope,
            audience=client.id,
            lifetime=self._access_lifetime,
        )

        self._audit.log_event(
            "client_token_issued",
            client.id,
            "",
            "success",
            {"scope": scope},
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self._access_lifetime,
            "scope": scope,
        }

    async def refresh_tokens(
        self,
        refresh_token_plain: str,
        client_id: str,
    ) -> dict[str, str | int]:
        """Refresh tokens with rotation and reuse detection."""
        token_hash = hash_token(refresh_token_plain)
        stored = await self._storage.get_refresh_token(token_hash)

        if not stored:
            msg = "Invalid refresh token"
            raise TokenServiceError(msg, error_code="invalid_grant")

        if stored.revoked:
            msg = "Refresh token revoked"
            raise TokenServiceError(msg, error_code="invalid_grant")

        if stored.expires_at < datetime.now(tz=UTC):
            msg = "Refresh token expired"
            raise TokenServiceError(msg, error_code="invalid_grant")

        if stored.client_id != client_id:
            msg = "Client mismatch"
            raise TokenServiceError(msg, error_code="invalid_grant")

        if stored.used:
            logger.warning("Refresh token reuse detected! family=%s", stored.family_id)
            await self._storage.revoke_token_family(stored.family_id)
            self._audit.log_event(
                "token_reuse_detected",
                stored.user_id,
                "",
                "failure",
                {"family_id": stored.family_id, "client_id": client_id},
            )
            msg = "Refresh token already used (reuse detected, family revoked)"
            raise TokenServiceError(msg, error_code="invalid_grant")

        await self._storage.mark_refresh_token_used(token_hash)

        user = await self._storage.get_user(stored.user_id)
        if not user:
            msg = "User not found"
            raise TokenServiceError(msg, error_code="invalid_grant")

        client = await self._storage.get_client(client_id)
        if not client:
            msg = "Client not found"
            raise TokenServiceError(msg, error_code="invalid_grant")

        access_token = self._jwt.create_access_token(
            sub=user.id,
            scope=stored.scope,
            audience=client.id,
            lifetime=self._access_lifetime,
        )

        new_refresh_plain = generate_opaque_token()
        new_refresh_record = RefreshToken(
            token_hash=hash_token(new_refresh_plain),
            family_id=stored.family_id,
            user_id=user.id,
            client_id=client_id,
            scope=stored.scope,
            expires_at=datetime.now(tz=UTC) + timedelta(seconds=self._refresh_lifetime),
        )
        await self._storage.store_refresh_token(new_refresh_record)

        result: dict[str, str | int] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self._access_lifetime,
            "refresh_token": new_refresh_plain,
            "scope": stored.scope,
        }

        scopes = stored.scope.split()
        if "openid" in scopes:
            result["id_token"] = self._jwt.create_id_token(
                sub=user.id,
                audience=client.id,
            )

        self._audit.log_event(
            "tokens_refreshed",
            user.id,
            "",
            "success",
            {"client_id": client_id},
        )
        return result

    async def introspect(self, token: str, requesting_client_id: str) -> dict[str, object]:
        """Introspect a token (RFC 7662)."""
        try:
            claims = self._jwt.decode_token(token)
        except pyjwt.InvalidTokenError:
            return {"active": False}

        jti = claims.get("jti", "")
        if jti and await self._storage.is_token_revoked(jti):
            return {"active": False}

        return {
            "active": True,
            "sub": claims.get("sub", ""),
            "scope": claims.get("scope", ""),
            "client_id": claims.get("aud", ""),
            "token_type": "access_token",
            "exp": claims.get("exp", 0),
            "iat": claims.get("iat", 0),
            "iss": claims.get("iss", ""),
        }

    async def revoke(
        self,
        token: str,
        token_type_hint: str = "",
        client_id: str = "",
    ) -> None:
        """Revoke a token (RFC 7009). Always returns success."""
        if token_type_hint == "refresh_token" or not token_type_hint:
            token_hash = hash_token(token)
            stored = await self._storage.get_refresh_token(token_hash)
            if stored:
                if client_id and stored.client_id != client_id:
                    return
                await self._storage.revoke_token_family(stored.family_id)
                family_jtis = await self._get_family_jtis(stored.family_id)
                for jti in family_jtis:
                    await self._storage.store_revocation(TokenRevocationEntry(jti=jti))
                self._audit.log_event(
                    "token_revoked",
                    "",
                    "",
                    "success",
                    {"family_id": stored.family_id, "type": "refresh_token"},
                )
                return

        jti = self._jwt.extract_jti(token)
        if jti:
            try:
                claims = self._jwt.decode_token(token)
                await self._storage.store_revocation(
                    TokenRevocationEntry(
                        jti=jti,
                        expires_at=datetime.fromtimestamp(claims.get("exp", 0), tz=UTC),
                    )
                )
                self._audit.log_event(
                    "token_revoked",
                    "",
                    "",
                    "success",
                    {"jti": jti, "type": "access_token"},
                )
            except pyjwt.InvalidTokenError:
                pass

    async def revoke_tokens_for_user_client(self, user_id: str, client_id: str) -> None:
        """Revoke all tokens for a user+client pair (used by consent revocation)."""
        await self._storage.revoke_tokens_for_user_client(user_id, client_id)

    async def _get_family_jtis(self, family_id: str) -> list[str]:
        """Get JTIs associated with a token family (placeholder for now)."""
        return []
