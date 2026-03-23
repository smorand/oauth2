"""OAuth2 client models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from models.base import generate_id, utc_now


class ClientType(StrEnum):
    """OAuth2 client type."""

    CONFIDENTIAL = "confidential"
    PUBLIC = "public"
    SERVICE = "service"


class ClientStatus(StrEnum):
    """Client status."""

    ACTIVE = "active"
    DEACTIVATED = "deactivated"


@dataclass(frozen=True)
class Client:
    """OAuth2 client entity."""

    name: str
    type: ClientType
    redirect_uris: tuple[str, ...]
    allowed_scopes: tuple[str, ...]
    grant_types: tuple[str, ...]
    id: str = field(default_factory=generate_id)
    secret_hash: str | None = None
    status: ClientStatus = ClientStatus.ACTIVE
    created_by: str = ""
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
