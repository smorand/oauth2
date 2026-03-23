"""Device authorization grant service."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from crypto.password import generate_device_user_code, generate_opaque_token, hash_token
from models.token import DeviceCode
from storage.base import StorageBackend

logger = logging.getLogger(__name__)


class DeviceCodeError(Exception):
    """Error during device code operations."""

    __slots__ = ("code", "error_code")

    def __init__(self, message: str, error_code: str = "invalid_request", code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.error_code = error_code


class DeviceCodeService:
    """Manages device authorization grant flow."""

    __slots__ = ("_code_lifetime", "_storage")

    def __init__(self, storage: StorageBackend, code_lifetime: int = 900) -> None:
        self._storage = storage
        self._code_lifetime = code_lifetime

    async def create_device_code(
        self,
        client_id: str,
        scope: str,
        verification_uri: str,
    ) -> dict[str, str | int]:
        """Create a device authorization code pair."""
        device_code_plain = generate_opaque_token()
        user_code = generate_device_user_code()
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=self._code_lifetime)

        device_code = DeviceCode(
            device_code_hash=hash_token(device_code_plain),
            user_code=user_code,
            client_id=client_id,
            scope=scope,
            expires_at=expires_at,
        )
        await self._storage.store_device_code(device_code)

        return {
            "device_code": device_code_plain,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
            "interval": 5,
            "expires_in": self._code_lifetime,
        }

    async def poll_device_code(self, device_code_plain: str, client_id: str) -> DeviceCode:
        """Poll for device code status. Raises DeviceCodeError with appropriate error codes."""
        code_hash = hash_token(device_code_plain)
        stored = await self._storage.get_device_code(code_hash)

        if not stored:
            msg = "Invalid device code"
            raise DeviceCodeError(msg, error_code="invalid_grant")

        if stored.expires_at < datetime.now(tz=UTC):
            msg = "Device code expired"
            raise DeviceCodeError(msg, error_code="expired_token")

        if stored.client_id != client_id:
            msg = "Client mismatch"
            raise DeviceCodeError(msg, error_code="invalid_grant")

        if stored.last_polled_at:
            elapsed = (datetime.now(tz=UTC) - stored.last_polled_at).total_seconds()
            if elapsed < stored.interval:
                updated = replace(
                    stored,
                    interval=stored.interval + 5,
                    last_polled_at=datetime.now(tz=UTC),
                )
                await self._storage.update_device_code(updated)
                msg = "Polling too fast"
                raise DeviceCodeError(msg, error_code="slow_down")

        updated = replace(stored, last_polled_at=datetime.now(tz=UTC))
        await self._storage.update_device_code(updated)

        if stored.status == "denied":
            msg = "Authorization denied"
            raise DeviceCodeError(msg, error_code="access_denied")

        if stored.status == "pending":
            msg = "Authorization pending"
            raise DeviceCodeError(msg, error_code="authorization_pending")

        return stored

    async def verify_user_code(self, user_code: str) -> DeviceCode | None:
        """Look up a device code by user code."""
        stored = await self._storage.get_device_code_by_user_code(user_code.upper())
        if not stored:
            return None
        if stored.expires_at < datetime.now(tz=UTC):
            return None
        return stored

    async def approve_device_code(self, user_code: str, user_id: str) -> None:
        """Approve a device code after user authentication and consent."""
        stored = await self._storage.get_device_code_by_user_code(user_code.upper())
        if not stored:
            msg = "Invalid user code"
            raise DeviceCodeError(msg, error_code="invalid_grant")

        updated = replace(stored, status="approved", user_id=user_id)
        await self._storage.update_device_code(updated)

    async def deny_device_code(self, user_code: str) -> None:
        """Deny a device code."""
        stored = await self._storage.get_device_code_by_user_code(user_code.upper())
        if not stored:
            return
        updated = replace(stored, status="denied")
        await self._storage.update_device_code(updated)
