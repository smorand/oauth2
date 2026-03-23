"""OAuth2 client management service."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime

from crypto.password import generate_client_secret, hash_client_secret, verify_client_secret
from models.client import Client, ClientStatus, ClientType
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)

VALID_GRANT_TYPES = frozenset(
    {
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    }
)


class ClientServiceError(Exception):
    """Base error for client operations."""

    __slots__ = ("code",)

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class ClientService:
    """Handles OAuth2 client registration and management."""

    __slots__ = ("_audit", "_storage")

    def __init__(self, storage: StorageBackend, audit: AuditService) -> None:
        self._storage = storage
        self._audit = audit

    async def create_client(
        self,
        name: str,
        client_type: str,
        redirect_uris: list[str],
        allowed_scopes: list[str],
        grant_types: list[str],
        created_by: str,
    ) -> tuple[Client, str]:
        """Create a new OAuth2 client. Returns (client, plain_secret)."""
        existing = await self._storage.get_client_by_name(name)
        if existing:
            msg = f"Client name already exists: {name}"
            raise ClientServiceError(msg, 409)

        try:
            ct = ClientType(client_type)
        except ValueError:
            msg = f"Invalid client type: {client_type}"
            raise ClientServiceError(msg, 400) from None

        self._validate_grant_types(ct, grant_types)
        self._validate_redirect_uris(ct, redirect_uris)

        scopes = await self._storage.list_scopes()
        valid_scope_names = {s.name for s in scopes}
        invalid_scopes = [s for s in allowed_scopes if s not in valid_scope_names]
        if invalid_scopes:
            msg = f"Unknown scopes: {', '.join(invalid_scopes)}"
            raise ClientServiceError(msg, 400)

        plain_secret = ""
        secret_hash = None
        if ct in (ClientType.CONFIDENTIAL, ClientType.SERVICE):
            plain_secret = generate_client_secret()
            secret_hash = hash_client_secret(plain_secret)

        client = Client(
            name=name,
            type=ct,
            secret_hash=secret_hash,
            redirect_uris=tuple(redirect_uris),
            allowed_scopes=tuple(allowed_scopes),
            grant_types=tuple(grant_types),
            created_by=created_by,
        )
        created = await self._storage.create_client(client)
        self._audit.log_event("client_created", created_by, "", "success", {"client_id": created.id, "name": name})
        return created, plain_secret

    async def get_client(self, client_id: str) -> Client | None:
        """Get client by ID."""
        return await self._storage.get_client(client_id)

    async def authenticate_client(self, client_id: str, client_secret: str) -> Client:
        """Authenticate a client by ID and secret."""
        client = await self._storage.get_client(client_id)
        if not client:
            msg = "Invalid client"
            raise ClientServiceError(msg, 401)

        if client.status == ClientStatus.DEACTIVATED:
            msg = "Client deactivated"
            raise ClientServiceError(msg, 401)

        if client.type == ClientType.PUBLIC:
            return client

        if not client.secret_hash or not verify_client_secret(client_secret, client.secret_hash):
            msg = "Invalid client credentials"
            raise ClientServiceError(msg, 401)

        return client

    async def update_client(
        self,
        client_id: str,
        name: str | None = None,
        redirect_uris: list[str] | None = None,
        allowed_scopes: list[str] | None = None,
        status: str | None = None,
    ) -> Client:
        """Update client fields."""
        client = await self._storage.get_client(client_id)
        if not client:
            msg = "Client not found"
            raise ClientServiceError(msg, 404)

        updates: dict[str, object] = {"updated_at": datetime.now(tz=UTC)}
        if name is not None:
            existing = await self._storage.get_client_by_name(name)
            if existing and existing.id != client_id:
                msg = f"Client name already exists: {name}"
                raise ClientServiceError(msg, 409)
            updates["name"] = name
        if redirect_uris is not None:
            updates["redirect_uris"] = tuple(redirect_uris)
        if allowed_scopes is not None:
            updates["allowed_scopes"] = tuple(allowed_scopes)
        if status is not None:
            updates["status"] = ClientStatus(status)

        updated = replace(client, **updates)  # type: ignore[arg-type]
        return await self._storage.update_client(updated)

    async def deactivate_client(self, client_id: str) -> Client:
        """Soft-delete a client and revoke all its tokens."""
        client = await self._storage.get_client(client_id)
        if not client:
            msg = "Client not found"
            raise ClientServiceError(msg, 404)

        deactivated = replace(
            client,
            status=ClientStatus.DEACTIVATED,
            updated_at=datetime.now(tz=UTC),
        )
        result = await self._storage.update_client(deactivated)
        await self._storage.revoke_tokens_for_client(client_id)
        self._audit.log_event("client_deactivated", "", "", "success", {"client_id": client_id})
        return result

    async def rotate_secret(self, client_id: str) -> tuple[Client, str]:
        """Generate a new client secret."""
        client = await self._storage.get_client(client_id)
        if not client:
            msg = "Client not found"
            raise ClientServiceError(msg, 404)

        if client.type == ClientType.PUBLIC:
            msg = "Public clients do not have secrets"
            raise ClientServiceError(msg, 400)

        plain_secret = generate_client_secret()
        updated = replace(
            client,
            secret_hash=hash_client_secret(plain_secret),
            updated_at=datetime.now(tz=UTC),
        )
        result = await self._storage.update_client(updated)
        self._audit.log_event("client_secret_rotated", "", "", "success", {"client_id": client_id})
        return result, plain_secret

    async def list_clients(self, page: int = 1, page_size: int = 20) -> tuple[list[Client], int]:
        """List clients with pagination."""
        return await self._storage.list_clients(page, page_size)

    def _validate_grant_types(self, client_type: ClientType, grant_types: list[str]) -> None:
        for gt in grant_types:
            if gt not in VALID_GRANT_TYPES:
                msg = f"Invalid grant type: {gt}"
                raise ClientServiceError(msg, 400)

        if client_type == ClientType.SERVICE and "authorization_code" in grant_types:
            msg = "Service clients cannot use authorization_code grant"
            raise ClientServiceError(msg, 400)
        if client_type != ClientType.SERVICE and "client_credentials" in grant_types:
            msg = "Only service clients can use client_credentials grant"
            raise ClientServiceError(msg, 400)

    def _validate_redirect_uris(self, client_type: ClientType, redirect_uris: list[str]) -> None:
        if client_type == ClientType.SERVICE and redirect_uris:
            msg = "Service clients should not have redirect URIs"
            raise ClientServiceError(msg, 400)
        if client_type != ClientType.SERVICE and not redirect_uris:
            msg = "Non-service clients must have at least one redirect URI"
            raise ClientServiceError(msg, 400)
        max_uri_length = 2048
        for uri in redirect_uris:
            if len(uri) > max_uri_length:
                msg = f"Redirect URI too long (max {max_uri_length}): {uri[:50]}..."
                raise ClientServiceError(msg, 400)
