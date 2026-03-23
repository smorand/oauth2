"""JWT creation and validation using RS256."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from crypto.keys import KeyManager
from models.base import generate_id

logger = logging.getLogger(__name__)


class JWTHandler:
    """Handles JWT creation and validation."""

    __slots__ = ("_issuer", "_key_manager")

    def __init__(self, key_manager: KeyManager, issuer: str) -> None:
        self._key_manager = key_manager
        self._issuer = issuer

    def create_access_token(
        self,
        sub: str,
        scope: str,
        audience: str = "",
        lifetime: int = 3600,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a signed JWT access token."""
        now = datetime.now(tz=UTC)
        kid = self._key_manager.current_kid
        private_key = self._key_manager.get_private_key(kid)

        payload: dict[str, Any] = {
            "iss": self._issuer,
            "sub": sub,
            "aud": audience or self._issuer,
            "exp": now + timedelta(seconds=lifetime),
            "iat": now,
            "jti": generate_id(),
            "scope": scope,
        }
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    def create_id_token(
        self,
        sub: str,
        audience: str,
        nonce: str = "",
        auth_time: datetime | None = None,
        lifetime: int = 3600,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a signed OIDC ID token."""
        now = datetime.now(tz=UTC)
        kid = self._key_manager.current_kid
        private_key = self._key_manager.get_private_key(kid)

        payload: dict[str, Any] = {
            "iss": self._issuer,
            "sub": sub,
            "aud": audience,
            "exp": now + timedelta(seconds=lifetime),
            "iat": now,
            "auth_time": int((auth_time or now).timestamp()),
        }
        if nonce:
            payload["nonce"] = nonce
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    def decode_token(self, token: str, audience: str = "") -> dict[str, Any]:
        """Decode and validate a JWT token.

        Raises jwt.InvalidTokenError on any validation failure.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            msg = "Malformed token"
            raise jwt.InvalidTokenError(msg) from exc

        kid = unverified_header.get("kid", "")
        alg = unverified_header.get("alg", "")

        if alg != "RS256":
            msg = f"Unsupported algorithm: {alg}"
            raise jwt.InvalidTokenError(msg)

        try:
            private_key = self._key_manager.get_private_key(kid)
        except KeyError as exc:
            msg = f"Unknown kid: {kid}"
            raise jwt.InvalidTokenError(msg) from exc

        public_key = private_key.public_key()
        options: dict[str, Any] = {}
        if not audience:
            options["verify_aud"] = False

        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=self._issuer,
            audience=audience if audience else None,
            options=options,
        )

    def extract_jti(self, token: str) -> str:
        """Extract JTI from token without full validation."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return str(payload.get("jti", ""))
        except jwt.DecodeError:
            return ""
