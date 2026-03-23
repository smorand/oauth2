"""Authorization code management."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from crypto.password import generate_auth_code, hash_token
from crypto.pkce import verify_code_challenge
from models.token import AuthorizationCode
from storage.base import StorageBackend

logger = logging.getLogger(__name__)


class AuthCodeError(Exception):
    """Error during authorization code operations."""

    __slots__ = ("code", "error_code")

    def __init__(self, message: str, error_code: str = "invalid_request", code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.error_code = error_code


class AuthCodeService:
    """Manages authorization code creation and exchange."""

    __slots__ = ("_code_lifetime", "_storage")

    def __init__(self, storage: StorageBackend, code_lifetime: int = 300) -> None:
        self._storage = storage
        self._code_lifetime = code_lifetime

    async def create_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        nonce: str = "",
    ) -> str:
        """Generate and store an authorization code. Returns the plain code."""
        plain_code = generate_auth_code()
        code_hash = hash_token(plain_code)

        auth_code = AuthorizationCode(
            code_hash=code_hash,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            expires_at=datetime.now(tz=UTC) + timedelta(seconds=self._code_lifetime),
        )
        await self._storage.store_auth_code(auth_code)
        return plain_code

    async def exchange_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> AuthorizationCode:
        """Exchange an authorization code for token data.

        Validates the code, PKCE, redirect_uri, and marks it as used.
        Returns the validated AuthorizationCode for token issuance.
        """
        code_hash = hash_token(code)
        stored = await self._storage.get_auth_code(code_hash)

        if not stored:
            msg = "Invalid authorization code"
            raise AuthCodeError(msg, error_code="invalid_grant")

        if stored.used:
            logger.warning("Authorization code replay detected: client=%s", client_id)
            msg = "Authorization code already used"
            raise AuthCodeError(msg, error_code="invalid_grant")

        if stored.expires_at < datetime.now(tz=UTC):
            msg = "Authorization code expired"
            raise AuthCodeError(msg, error_code="invalid_grant")

        if stored.client_id != client_id:
            msg = "Client mismatch"
            raise AuthCodeError(msg, error_code="invalid_grant")

        if stored.redirect_uri != redirect_uri:
            msg = "Redirect URI mismatch"
            raise AuthCodeError(msg, error_code="invalid_grant")

        if not verify_code_challenge(code_verifier, stored.code_challenge, stored.code_challenge_method):
            msg = "PKCE code_verifier mismatch"
            raise AuthCodeError(msg, error_code="invalid_grant")

        await self._storage.mark_auth_code_used(code_hash)
        return stored
