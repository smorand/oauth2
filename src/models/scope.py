"""Scope model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from models.base import utc_now


@dataclass(frozen=True)
class Scope:
    """OAuth2 scope definition."""

    name: str
    description: str
    built_in: bool = False
    created_at: datetime = field(default_factory=utc_now)


DEFAULT_SCOPES: tuple[Scope, ...] = (
    Scope(name="openid", description="OpenID Connect authentication", built_in=True),
    Scope(name="profile", description="User profile information (name)", built_in=True),
    Scope(name="email", description="User email address", built_in=True),
)
