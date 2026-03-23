"""User and social account models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from models.base import generate_id, utc_now


class UserRole(StrEnum):
    """User role enumeration."""

    USER = "user"
    ADMIN = "admin"


class UserStatus(StrEnum):
    """User status enumeration."""

    ACTIVE = "active"
    LOCKED = "locked"
    DEACTIVATED = "deactivated"


class SocialProvider(StrEnum):
    """Social login provider enumeration."""

    GOOGLE = "google"
    GITHUB = "github"
    SAML = "saml"


@dataclass(frozen=True)
class User:
    """User entity."""

    email: str
    name: str
    id: str = field(default_factory=generate_id)
    password_hash: str | None = None
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class SocialAccount:
    """Linked social account entity."""

    user_id: str
    provider: SocialProvider
    provider_user_id: str
    provider_email: str
    provider_name: str
    id: str = field(default_factory=generate_id)
    linked_at: datetime = field(default_factory=utc_now)
