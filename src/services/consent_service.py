"""Consent management service."""

from __future__ import annotations

import logging

from models.consent import Consent
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)


class ConsentServiceError(Exception):
    """Error during consent operations."""

    __slots__ = ("code",)

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class ConsentService:
    """Manages user consent grants."""

    __slots__ = ("_audit", "_storage")

    def __init__(self, storage: StorageBackend, audit: AuditService) -> None:
        self._storage = storage
        self._audit = audit

    async def check_existing_consent(self, user_id: str, client_id: str, requested_scopes: list[str]) -> bool:
        """Check if user has existing consent covering all requested scopes."""
        consent = await self._storage.get_active_consent(user_id, client_id)
        if not consent:
            return False
        return set(requested_scopes).issubset(set(consent.scopes))

    async def get_missing_scopes(self, user_id: str, client_id: str, requested_scopes: list[str]) -> list[str]:
        """Get scopes not yet consented to."""
        consent = await self._storage.get_active_consent(user_id, client_id)
        if not consent:
            return requested_scopes
        return [s for s in requested_scopes if s not in consent.scopes]

    async def grant_consent(self, user_id: str, client_id: str, scopes: list[str]) -> Consent:
        """Grant or update consent for a user+client pair."""
        existing = await self._storage.get_active_consent(user_id, client_id)
        if existing:
            merged_scopes = list(set(list(existing.scopes) + scopes))
            await self._storage.revoke_consent(existing.id)
            consent = Consent(
                user_id=user_id,
                client_id=client_id,
                scopes=tuple(merged_scopes),
            )
        else:
            consent = Consent(
                user_id=user_id,
                client_id=client_id,
                scopes=tuple(scopes),
            )

        created = await self._storage.create_consent(consent)
        self._audit.log_event(
            "consent_granted",
            user_id,
            "",
            "success",
            {"client_id": client_id, "scopes": scopes},
        )
        return created

    async def get_user_consents(self, user_id: str) -> list[Consent]:
        """Get all active consents for a user."""
        return await self._storage.get_consents_for_user(user_id)

    async def revoke_consent(self, consent_id: str, user_id: str) -> None:
        """Revoke a consent and cascade to tokens."""
        consent = await self._storage.get_consent(consent_id)
        if not consent:
            msg = "Consent not found"
            raise ConsentServiceError(msg, 404)
        if consent.user_id != user_id:
            msg = "Consent belongs to different user"
            raise ConsentServiceError(msg, 403)

        await self._storage.revoke_consent(consent_id)
        await self._storage.revoke_tokens_for_user_client(consent.user_id, consent.client_id)
        self._audit.log_event(
            "consent_revoked",
            user_id,
            "",
            "success",
            {"consent_id": consent_id, "client_id": consent.client_id},
        )
