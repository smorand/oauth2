"""JSON file storage backend."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from models.base import utc_now
from models.client import Client, ClientStatus, ClientType
from models.consent import Consent
from models.saml import SAMLIdPConfig, SAMLIdPStatus
from models.scope import DEFAULT_SCOPES, Scope
from models.token import AuthorizationCode, DeviceCode, RefreshToken, TokenRevocationEntry
from models.user import SocialAccount, SocialProvider, User, UserRole, UserStatus

logger = logging.getLogger(__name__)

T = TypeVar("T")


class JsonStorageBackend:
    """JSON file storage backend.

    Stores each collection in a separate JSON file within a directory.
    Uses file locking via asyncio.Lock for concurrent access safety.
    """

    __slots__ = ("_dir", "_lock")

    def __init__(self, storage_dir: Path) -> None:
        self._dir = storage_dir
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize storage directory and seed default scopes."""
        self._dir.mkdir(parents=True, exist_ok=True)
        for collection in (
            "users",
            "social_accounts",
            "clients",
            "auth_codes",
            "refresh_tokens",
            "revocations",
            "consents",
            "device_codes",
            "scopes",
            "saml_idps",
        ):
            path = self._dir / f"{collection}.json"
            if not path.exists():
                path.write_text("[]")

        existing_scopes = await self.list_scopes()
        existing_names = {s.name for s in existing_scopes}
        for scope in DEFAULT_SCOPES:
            if scope.name not in existing_names:
                await self.create_scope(scope)
        logger.info("JSON storage initialized at %s", self._dir)

    async def health_check(self) -> bool:
        """Check if storage directory is accessible."""
        return self._dir.exists() and self._dir.is_dir()

    # --- Internal helpers ---

    def _read_collection(self, name: str) -> list[dict[str, Any]]:
        path = self._dir / f"{name}.json"
        if not path.exists():
            return []
        return json.loads(path.read_text())  # type: ignore[no-any-return]

    def _write_collection(self, name: str, data: list[dict[str, Any]]) -> None:
        path = self._dir / f"{name}.json"
        path.write_text(json.dumps(data, default=_json_serializer, indent=2))

    # --- User operations ---

    async def get_user(self, user_id: str) -> User | None:
        async with self._lock:
            for item in self._read_collection("users"):
                if item["id"] == user_id:
                    return _dict_to_user(item)
        return None

    async def get_user_by_email(self, email: str) -> User | None:
        async with self._lock:
            for item in self._read_collection("users"):
                if item["email"].lower() == email.lower():
                    return _dict_to_user(item)
        return None

    async def create_user(self, user: User) -> User:
        async with self._lock:
            data = self._read_collection("users")
            data.append(asdict(user))
            self._write_collection("users", data)
        return user

    async def update_user(self, user: User) -> User:
        async with self._lock:
            data = self._read_collection("users")
            for i, item in enumerate(data):
                if item["id"] == user.id:
                    data[i] = asdict(user)
                    break
            self._write_collection("users", data)
        return user

    async def list_users(self, page: int = 1, page_size: int = 20) -> tuple[list[User], int]:
        async with self._lock:
            data = self._read_collection("users")
        total = len(data)
        start = (page - 1) * page_size
        end = start + page_size
        users = [_dict_to_user(item) for item in data[start:end]]
        return users, total

    async def search_users(self, query: str, page: int = 1, page_size: int = 20) -> tuple[list[User], int]:
        async with self._lock:
            data = self._read_collection("users")
        q = query.lower()
        filtered = [item for item in data if q in item.get("email", "").lower() or q in item.get("name", "").lower()]
        total = len(filtered)
        start = (page - 1) * page_size
        end = start + page_size
        users = [_dict_to_user(item) for item in filtered[start:end]]
        return users, total

    # --- Social account operations ---

    async def get_social_account(self, provider: str, provider_user_id: str) -> SocialAccount | None:
        async with self._lock:
            for item in self._read_collection("social_accounts"):
                if item["provider"] == provider and item["provider_user_id"] == provider_user_id:
                    return _dict_to_social_account(item)
        return None

    async def get_social_accounts_for_user(self, user_id: str) -> list[SocialAccount]:
        async with self._lock:
            data = self._read_collection("social_accounts")
        return [_dict_to_social_account(item) for item in data if item["user_id"] == user_id]

    async def create_social_account(self, account: SocialAccount) -> SocialAccount:
        async with self._lock:
            data = self._read_collection("social_accounts")
            data.append(asdict(account))
            self._write_collection("social_accounts", data)
        return account

    # --- Client operations ---

    async def get_client(self, client_id: str) -> Client | None:
        async with self._lock:
            for item in self._read_collection("clients"):
                if item["id"] == client_id:
                    return _dict_to_client(item)
        return None

    async def get_client_by_name(self, name: str) -> Client | None:
        async with self._lock:
            for item in self._read_collection("clients"):
                if item["name"] == name:
                    return _dict_to_client(item)
        return None

    async def create_client(self, client: Client) -> Client:
        async with self._lock:
            data = self._read_collection("clients")
            data.append(asdict(client))
            self._write_collection("clients", data)
        return client

    async def update_client(self, client: Client) -> Client:
        async with self._lock:
            data = self._read_collection("clients")
            for i, item in enumerate(data):
                if item["id"] == client.id:
                    data[i] = asdict(client)
                    break
            self._write_collection("clients", data)
        return client

    async def list_clients(self, page: int = 1, page_size: int = 20) -> tuple[list[Client], int]:
        async with self._lock:
            data = self._read_collection("clients")
        total = len(data)
        start = (page - 1) * page_size
        end = start + page_size
        clients = [_dict_to_client(item) for item in data[start:end]]
        return clients, total

    # --- Authorization code operations ---

    async def store_auth_code(self, code: AuthorizationCode) -> None:
        async with self._lock:
            data = self._read_collection("auth_codes")
            data.append(asdict(code))
            self._write_collection("auth_codes", data)

    async def get_auth_code(self, code_hash: str) -> AuthorizationCode | None:
        async with self._lock:
            for item in self._read_collection("auth_codes"):
                if item["code_hash"] == code_hash:
                    return _dict_to_auth_code(item)
        return None

    async def mark_auth_code_used(self, code_hash: str) -> None:
        async with self._lock:
            data = self._read_collection("auth_codes")
            for item in data:
                if item["code_hash"] == code_hash:
                    item["used"] = True
                    break
            self._write_collection("auth_codes", data)

    # --- Refresh token operations ---

    async def store_refresh_token(self, token: RefreshToken) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            data.append(asdict(token))
            self._write_collection("refresh_tokens", data)

    async def get_refresh_token(self, token_hash: str) -> RefreshToken | None:
        async with self._lock:
            for item in self._read_collection("refresh_tokens"):
                if item["token_hash"] == token_hash:
                    return _dict_to_refresh_token(item)
        return None

    async def mark_refresh_token_used(self, token_hash: str) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            for item in data:
                if item["token_hash"] == token_hash:
                    item["used"] = True
                    break
            self._write_collection("refresh_tokens", data)

    async def revoke_refresh_token(self, token_hash: str) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            for item in data:
                if item["token_hash"] == token_hash:
                    item["revoked"] = True
                    break
            self._write_collection("refresh_tokens", data)

    async def revoke_token_family(self, family_id: str) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            for item in data:
                if item["family_id"] == family_id:
                    item["revoked"] = True
            self._write_collection("refresh_tokens", data)

    async def revoke_tokens_for_client(self, client_id: str) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            for item in data:
                if item["client_id"] == client_id:
                    item["revoked"] = True
            self._write_collection("refresh_tokens", data)

    async def revoke_tokens_for_user_client(self, user_id: str, client_id: str) -> None:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
            for item in data:
                if item["user_id"] == user_id and item["client_id"] == client_id:
                    item["revoked"] = True
            self._write_collection("refresh_tokens", data)

    async def get_refresh_tokens_by_family(self, family_id: str) -> list[RefreshToken]:
        async with self._lock:
            data = self._read_collection("refresh_tokens")
        return [_dict_to_refresh_token(item) for item in data if item["family_id"] == family_id]

    # --- Token revocation entries ---

    async def store_revocation(self, entry: TokenRevocationEntry) -> None:
        async with self._lock:
            data = self._read_collection("revocations")
            data.append(asdict(entry))
            self._write_collection("revocations", data)

    async def is_token_revoked(self, jti: str) -> bool:
        async with self._lock:
            for item in self._read_collection("revocations"):
                if item["jti"] == jti:
                    return True
        return False

    # --- Consent operations ---

    async def get_consent(self, consent_id: str) -> Consent | None:
        async with self._lock:
            for item in self._read_collection("consents"):
                if item["id"] == consent_id:
                    return _dict_to_consent(item)
        return None

    async def get_active_consent(self, user_id: str, client_id: str) -> Consent | None:
        async with self._lock:
            for item in self._read_collection("consents"):
                if item["user_id"] == user_id and item["client_id"] == client_id and item.get("revoked_at") is None:
                    return _dict_to_consent(item)
        return None

    async def get_consents_for_user(self, user_id: str) -> list[Consent]:
        async with self._lock:
            data = self._read_collection("consents")
        return [
            _dict_to_consent(item) for item in data if item["user_id"] == user_id and item.get("revoked_at") is None
        ]

    async def create_consent(self, consent: Consent) -> Consent:
        async with self._lock:
            data = self._read_collection("consents")
            data.append(asdict(consent))
            self._write_collection("consents", data)
        return consent

    async def revoke_consent(self, consent_id: str) -> None:
        async with self._lock:
            data = self._read_collection("consents")
            for item in data:
                if item["id"] == consent_id:
                    item["revoked_at"] = utc_now().isoformat()
                    break
            self._write_collection("consents", data)

    # --- Device code operations ---

    async def store_device_code(self, device_code: DeviceCode) -> None:
        async with self._lock:
            data = self._read_collection("device_codes")
            data.append(asdict(device_code))
            self._write_collection("device_codes", data)

    async def get_device_code(self, device_code_hash: str) -> DeviceCode | None:
        async with self._lock:
            for item in self._read_collection("device_codes"):
                if item["device_code_hash"] == device_code_hash:
                    return _dict_to_device_code(item)
        return None

    async def get_device_code_by_user_code(self, user_code: str) -> DeviceCode | None:
        async with self._lock:
            for item in self._read_collection("device_codes"):
                if item["user_code"] == user_code:
                    return _dict_to_device_code(item)
        return None

    async def update_device_code(self, device_code: DeviceCode) -> None:
        async with self._lock:
            data = self._read_collection("device_codes")
            for i, item in enumerate(data):
                if item["device_code_hash"] == device_code.device_code_hash:
                    data[i] = asdict(device_code)
                    break
            self._write_collection("device_codes", data)

    # --- Scope operations ---

    async def get_scope(self, name: str) -> Scope | None:
        async with self._lock:
            for item in self._read_collection("scopes"):
                if item["name"] == name:
                    return _dict_to_scope(item)
        return None

    async def list_scopes(self) -> list[Scope]:
        async with self._lock:
            data = self._read_collection("scopes")
        return [_dict_to_scope(item) for item in data]

    async def create_scope(self, scope: Scope) -> Scope:
        async with self._lock:
            data = self._read_collection("scopes")
            data.append(asdict(scope))
            self._write_collection("scopes", data)
        return scope

    async def delete_scope(self, name: str) -> None:
        async with self._lock:
            data = self._read_collection("scopes")
            data = [item for item in data if item["name"] != name]
            self._write_collection("scopes", data)

    # --- SAML IdP operations ---

    async def get_saml_idps(self) -> list[SAMLIdPConfig]:
        async with self._lock:
            data = self._read_collection("saml_idps")
        return [_dict_to_saml_idp(item) for item in data]

    async def get_saml_idp(self, idp_id: str) -> SAMLIdPConfig | None:
        async with self._lock:
            for item in self._read_collection("saml_idps"):
                if item["id"] == idp_id:
                    return _dict_to_saml_idp(item)
        return None

    async def create_saml_idp(self, idp: SAMLIdPConfig) -> SAMLIdPConfig:
        async with self._lock:
            data = self._read_collection("saml_idps")
            data.append(asdict(idp))
            self._write_collection("saml_idps", data)
        return idp


# --- Serialization helpers ---


def _json_serializer(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    msg = f"Object of type {type(obj)} is not JSON serializable"
    raise TypeError(msg)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _parse_datetime_required(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _dict_to_user(data: dict[str, Any]) -> User:
    return User(
        id=data["id"],
        email=data["email"],
        name=data.get("name", ""),
        password_hash=data.get("password_hash"),
        role=UserRole(data.get("role", "user")),
        status=UserStatus(data.get("status", "active")),
        failed_login_attempts=data.get("failed_login_attempts", 0),
        locked_until=_parse_datetime(data.get("locked_until")),
        created_at=_parse_datetime_required(data["created_at"]),
        updated_at=_parse_datetime_required(data["updated_at"]),
    )


def _dict_to_social_account(data: dict[str, Any]) -> SocialAccount:
    return SocialAccount(
        id=data["id"],
        user_id=data["user_id"],
        provider=SocialProvider(data["provider"]),
        provider_user_id=data["provider_user_id"],
        provider_email=data.get("provider_email", ""),
        provider_name=data.get("provider_name", ""),
        linked_at=_parse_datetime_required(data["linked_at"]),
    )


def _dict_to_client(data: dict[str, Any]) -> Client:
    return Client(
        id=data["id"],
        name=data["name"],
        type=ClientType(data["type"]),
        secret_hash=data.get("secret_hash"),
        redirect_uris=tuple(data.get("redirect_uris", [])),
        allowed_scopes=tuple(data.get("allowed_scopes", [])),
        grant_types=tuple(data.get("grant_types", [])),
        status=ClientStatus(data.get("status", "active")),
        created_by=data.get("created_by", ""),
        created_at=_parse_datetime_required(data["created_at"]),
        updated_at=_parse_datetime_required(data["updated_at"]),
    )


def _dict_to_auth_code(data: dict[str, Any]) -> AuthorizationCode:
    return AuthorizationCode(
        code_hash=data["code_hash"],
        client_id=data["client_id"],
        user_id=data["user_id"],
        redirect_uri=data["redirect_uri"],
        scope=data["scope"],
        code_challenge=data["code_challenge"],
        code_challenge_method=data.get("code_challenge_method", "S256"),
        nonce=data.get("nonce", ""),
        expires_at=_parse_datetime_required(data["expires_at"]),
        used=data.get("used", False),
    )


def _dict_to_refresh_token(data: dict[str, Any]) -> RefreshToken:
    return RefreshToken(
        token_hash=data["token_hash"],
        family_id=data["family_id"],
        user_id=data["user_id"],
        client_id=data["client_id"],
        scope=data["scope"],
        expires_at=_parse_datetime_required(data["expires_at"]),
        used=data.get("used", False),
        revoked=data.get("revoked", False),
        created_at=_parse_datetime_required(data["created_at"]),
    )


def _dict_to_consent(data: dict[str, Any]) -> Consent:
    return Consent(
        id=data["id"],
        user_id=data["user_id"],
        client_id=data["client_id"],
        scopes=tuple(data.get("scopes", [])),
        granted_at=_parse_datetime_required(data["granted_at"]),
        revoked_at=_parse_datetime(data.get("revoked_at")),
    )


def _dict_to_device_code(data: dict[str, Any]) -> DeviceCode:
    return DeviceCode(
        id=data.get("id", ""),
        device_code_hash=data["device_code_hash"],
        user_code=data["user_code"],
        client_id=data["client_id"],
        scope=data["scope"],
        user_id=data.get("user_id", ""),
        status=data.get("status", "pending"),
        interval=data.get("interval", 5),
        expires_at=_parse_datetime_required(data["expires_at"]),
        last_polled_at=_parse_datetime(data.get("last_polled_at")),
    )


def _dict_to_scope(data: dict[str, Any]) -> Scope:
    return Scope(
        name=data["name"],
        description=data.get("description", ""),
        built_in=data.get("built_in", False),
        created_at=_parse_datetime_required(data["created_at"]),
    )


def _dict_to_saml_idp(data: dict[str, Any]) -> SAMLIdPConfig:
    return SAMLIdPConfig(
        id=data["id"],
        name=data["name"],
        entity_id=data["entity_id"],
        sso_url=data["sso_url"],
        certificate=data["certificate"],
        attribute_mapping=tuple(tuple(pair) for pair in data.get("attribute_mapping", [])),
        status=SAMLIdPStatus(data.get("status", "active")),
    )
