"""Consent model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from models.base import generate_id, utc_now


@dataclass(frozen=True)
class Consent:
    """User consent record."""

    user_id: str
    client_id: str
    scopes: tuple[str, ...]
    id: str = field(default_factory=generate_id)
    granted_at: datetime = field(default_factory=utc_now)
    revoked_at: datetime | None = None
