"""Token related models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from models.base import generate_id, utc_now


@dataclass(frozen=True)
class AuthorizationCode:
    """Authorization code entity."""

    code_hash: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str = "S256"
    nonce: str = ""
    expires_at: datetime = field(default_factory=utc_now)
    used: bool = False


@dataclass(frozen=True)
class RefreshToken:
    """Refresh token entity."""

    token_hash: str
    family_id: str
    user_id: str
    client_id: str
    scope: str
    expires_at: datetime
    used: bool = False
    revoked: bool = False
    created_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class TokenRevocationEntry:
    """Revoked access token tracking entry."""

    jti: str
    revoked_at: datetime = field(default_factory=utc_now)
    expires_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class DeviceCode:
    """Device authorization code entity."""

    device_code_hash: str
    user_code: str
    client_id: str
    scope: str
    id: str = field(default_factory=generate_id)
    user_id: str = ""
    status: str = "pending"  # pending, approved, denied
    interval: int = 5
    expires_at: datetime = field(default_factory=utc_now)
    last_polled_at: datetime | None = None
