"""SAML Service Provider integration service."""

from __future__ import annotations

import base64
import logging
import secrets
import uuid
import zlib
from datetime import UTC, datetime
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from models.saml import SAMLIdPConfig, SAMLIdPStatus
from models.user import SocialAccount, SocialProvider, User
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


class SAMLError(Exception):
    """Raised when SAML operation fails."""


class SAMLService:
    """Handles SAML SP flows."""

    __slots__ = ("_audit", "_issuer_url", "_storage")

    def __init__(self, storage: StorageBackend, audit: AuditService, issuer_url: str) -> None:
        self._storage = storage
        self._audit = audit
        self._issuer_url = issuer_url

    async def get_active_idps(self) -> list[SAMLIdPConfig]:
        """Get all active SAML IdPs."""
        all_idps = await self._storage.get_saml_idps()
        return [idp for idp in all_idps if idp.status == SAMLIdPStatus.ACTIVE]

    async def get_idp(self, idp_id: str) -> SAMLIdPConfig | None:
        """Get a specific SAML IdP."""
        return await self._storage.get_saml_idp(idp_id)

    def generate_authn_request_redirect(self, idp: SAMLIdPConfig, relay_state: str) -> str:
        """Generate SAML AuthnRequest and return redirect URL."""
        request_id = f"_id-{uuid.uuid4()}"
        issue_instant = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        acs_url = f"{self._issuer_url}/federation/saml/acs"

        authn_request = (
            f'<samlp:AuthnRequest xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"'
            f' ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}"'
            f' Destination="{idp.sso_url}" AssertionConsumerServiceURL="{acs_url}"'
            f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f"<saml:Issuer>{self._issuer_url}</saml:Issuer>"
            f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"'
            f' AllowCreate="true"/>'
            f"</samlp:AuthnRequest>"
        )

        deflated = zlib.compress(authn_request.encode())[2:-4]
        encoded = base64.b64encode(deflated).decode()

        params = {
            "SAMLRequest": encoded,
            "RelayState": relay_state,
        }
        return f"{idp.sso_url}?{urlencode(params)}"

    async def handle_saml_response(self, saml_response_b64: str, relay_state: str) -> User:
        """Parse and validate SAML Response, find/create user."""
        try:
            response_xml = base64.b64decode(saml_response_b64)
            root = ET.fromstring(response_xml)
        except Exception as exc:
            msg = "Invalid SAML Response encoding"
            raise SAMLError(msg) from exc

        status_elem = root.find(f".//{{{SAMLP_NS}}}StatusCode")
        if status_elem is not None:
            status_value = status_elem.get("Value", "")
            if "Success" not in status_value:
                msg = f"SAML authentication failed: {status_value}"
                raise SAMLError(msg)

        issuer_elem = root.find(f".//{{{SAML_NS}}}Issuer")
        if issuer_elem is None or not issuer_elem.text:
            msg = "SAML Response missing Issuer"
            raise SAMLError(msg)

        issuer = issuer_elem.text
        idp = await self._find_idp_by_entity_id(issuer)
        if not idp:
            msg = f"Unknown SAML IdP: {issuer}"
            raise SAMLError(msg)

        assertion = root.find(f".//{{{SAML_NS}}}Assertion")
        if assertion is None:
            msg = "SAML Response missing Assertion"
            raise SAMLError(msg)

        conditions = assertion.find(f".//{{{SAML_NS}}}Conditions")
        if conditions is not None:
            not_before = conditions.get("NotBefore")
            not_on_or_after = conditions.get("NotOnOrAfter")
            now = datetime.now(tz=UTC)
            if not_before:
                nb = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                if now < nb:
                    msg = "SAML Response not yet valid"
                    raise SAMLError(msg)
            if not_on_or_after:
                noa = datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
                if now >= noa:
                    msg = "SAML Response has expired"
                    raise SAMLError(msg)

        name_id_elem = assertion.find(f".//{{{SAML_NS}}}NameID")
        if name_id_elem is None or not name_id_elem.text:
            msg = "SAML Response missing NameID"
            raise SAMLError(msg)

        name_id = name_id_elem.text
        attributes = self._extract_attributes(assertion, idp)

        email = attributes.get("email", name_id)
        name = attributes.get("name", email)

        return await self._find_or_create_user(
            idp_entity_id=issuer,
            name_id=name_id,
            email=email,
            name=name,
        )

    def _extract_attributes(self, assertion: ET.Element, idp: SAMLIdPConfig) -> dict[str, str]:
        """Extract user attributes from SAML assertion."""
        attrs: dict[str, str] = {}
        attr_mapping = dict(idp.attribute_mapping) if idp.attribute_mapping else {}

        for attr_stmt in assertion.findall(f".//{{{SAML_NS}}}AttributeStatement"):
            for attr in attr_stmt.findall(f"{{{SAML_NS}}}Attribute"):
                attr_name = attr.get("Name", "")
                value_elem = attr.find(f"{{{SAML_NS}}}AttributeValue")
                if value_elem is not None and value_elem.text:
                    mapped_name = attr_mapping.get(attr_name, attr_name)
                    attrs[mapped_name] = value_elem.text

        return attrs

    async def _find_idp_by_entity_id(self, entity_id: str) -> SAMLIdPConfig | None:
        """Find SAML IdP by entity ID."""
        all_idps = await self._storage.get_saml_idps()
        for idp in all_idps:
            if idp.entity_id == entity_id and idp.status == SAMLIdPStatus.ACTIVE:
                return idp
        return None

    async def _find_or_create_user(
        self,
        idp_entity_id: str,
        name_id: str,
        email: str,
        name: str,
    ) -> User:
        """Find existing user by SAML identity or email, or create new one."""
        provider_user_id = f"{idp_entity_id}:{name_id}"

        existing = await self._storage.get_social_account(SocialProvider.SAML.value, provider_user_id)
        if existing:
            user = await self._storage.get_user(existing.user_id)
            if user:
                self._audit.log_event("saml_login", user.id, "", "success", {"idp": idp_entity_id})
                return user

        user = await self._storage.get_user_by_email(email)
        if user:
            await self._storage.create_social_account(
                SocialAccount(
                    user_id=user.id,
                    provider=SocialProvider.SAML,
                    provider_user_id=provider_user_id,
                    provider_email=email,
                    provider_name=name,
                )
            )
            self._audit.log_event("saml_link", user.id, "", "success", {"idp": idp_entity_id})
            return user

        new_user = User(
            email=email,
            name=name,
            password_hash=None,
        )
        new_user = await self._storage.create_user(new_user)
        await self._storage.create_social_account(
            SocialAccount(
                user_id=new_user.id,
                provider=SocialProvider.SAML,
                provider_user_id=provider_user_id,
                provider_email=email,
                provider_name=name,
            )
        )
        self._audit.log_event("saml_register", new_user.id, "", "success", {"idp": idp_entity_id})
        return new_user

    def generate_relay_state(self) -> str:
        """Generate a CSRF relay state token."""
        return secrets.token_urlsafe(32)
