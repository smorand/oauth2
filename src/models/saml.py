"""SAML IdP configuration model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from models.base import generate_id


class SAMLIdPStatus(StrEnum):
    """SAML IdP status."""

    ACTIVE = "active"
    DEACTIVATED = "deactivated"


@dataclass(frozen=True)
class SAMLIdPConfig:
    """SAML Identity Provider configuration."""

    name: str
    entity_id: str
    sso_url: str
    certificate: str
    id: str = field(default_factory=generate_id)
    attribute_mapping: tuple[tuple[str, str], ...] = ()
    status: SAMLIdPStatus = SAMLIdPStatus.ACTIVE
