"""Scope management service."""

from __future__ import annotations

import logging

from models.scope import Scope
from storage.base import StorageBackend

logger = logging.getLogger(__name__)

RESERVED_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})


class ScopeServiceError(Exception):
    """Error during scope operations."""

    __slots__ = ("code",)

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class ScopeService:
    """Manages OAuth2 scopes."""

    __slots__ = ("_storage",)

    def __init__(self, storage: StorageBackend) -> None:
        self._storage = storage

    async def create_scope(self, name: str, description: str = "") -> Scope:
        """Create a custom scope."""
        if name in RESERVED_SCOPES:
            msg = f"Cannot create reserved scope: {name}"
            raise ScopeServiceError(msg, 400)

        existing = await self._storage.get_scope(name)
        if existing:
            msg = f"Scope already exists: {name}"
            raise ScopeServiceError(msg, 409)

        scope = Scope(name=name, description=description)
        return await self._storage.create_scope(scope)

    async def list_scopes(self) -> list[Scope]:
        """List all scopes."""
        return await self._storage.list_scopes()

    async def delete_scope(self, name: str) -> None:
        """Delete a scope if not in use."""
        scope = await self._storage.get_scope(name)
        if not scope:
            msg = f"Scope not found: {name}"
            raise ScopeServiceError(msg, 404)

        if scope.built_in:
            msg = f"Cannot delete built-in scope: {name}"
            raise ScopeServiceError(msg, 400)

        clients, _ = await self._storage.list_clients(page=1, page_size=1000)
        for client in clients:
            if name in client.allowed_scopes:
                msg = f"Scope '{name}' is in use by client '{client.name}'"
                raise ScopeServiceError(msg, 409)

        await self._storage.delete_scope(name)

    async def validate_scopes(self, scope_string: str, allowed_scopes: tuple[str, ...] | None = None) -> list[str]:
        """Validate and return list of valid scopes."""
        if not scope_string:
            return []
        requested = scope_string.split()
        all_scopes = await self._storage.list_scopes()
        valid_names = {s.name for s in all_scopes}

        invalid = [s for s in requested if s not in valid_names]
        if invalid:
            msg = f"Invalid scopes: {', '.join(invalid)}"
            raise ScopeServiceError(msg, 400)

        if allowed_scopes is not None:
            unauthorized = [s for s in requested if s not in allowed_scopes]
            if unauthorized:
                msg = f"Unauthorized scopes: {', '.join(unauthorized)}"
                raise ScopeServiceError(msg, 400)

        return requested
