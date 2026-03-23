"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from config import Settings
from crypto.keys import KeyManager
from crypto.jwt_handler import JWTHandler
from crypto.password import hash_password, hash_client_secret, hash_token
from models.client import Client, ClientType
from models.consent import Consent
from models.scope import Scope
from models.token import AuthorizationCode, RefreshToken
from models.user import User, UserRole, UserStatus
from services.audit_service import AuditService
from services.auth_code_service import AuthCodeService
from services.client_service import ClientService
from services.consent_service import ConsentService
from services.device_code_service import DeviceCodeService
from services.scope_service import ScopeService
from services.token_service import TokenService
from services.user_service import UserService
from storage.json_backend import JsonStorageBackend


@pytest.fixture
def sample_name() -> str:
    """Sample name for testing."""
    return "Test User"


@pytest.fixture
def tmp_settings(tmp_path: Path) -> Settings:
    """Create Settings pointing to tmp directories."""
    return Settings(
        issuer_url="http://localhost:8000",
        json_storage_dir=tmp_path / "data",
        rsa_private_key_path=tmp_path / "keys" / "private.pem",
        rsa_public_key_path=tmp_path / "keys" / "public.pem",
        audit_log_path=tmp_path / "logs" / "audit.jsonl",
        trace_log_path=tmp_path / "traces" / "app.jsonl",
        debug=True,
    )


@pytest.fixture
def key_manager() -> KeyManager:
    """Create a KeyManager with a generated key."""
    km = KeyManager()
    km.generate_key(kid="test-key-1", key_size=2048)
    return km


@pytest.fixture
def jwt_handler(key_manager: KeyManager) -> JWTHandler:
    """Create a JWTHandler with the test key manager."""
    return JWTHandler(key_manager, issuer="http://localhost:8000")


@pytest.fixture
def storage(tmp_path: Path) -> JsonStorageBackend:
    """Create an uninitialized JsonStorageBackend."""
    return JsonStorageBackend(tmp_path / "data")


@pytest.fixture
async def initialized_storage(storage: JsonStorageBackend) -> JsonStorageBackend:
    """Create and initialize a JsonStorageBackend."""
    await storage.initialize()
    return storage


@pytest.fixture
def audit_service(tmp_path: Path) -> AuditService:
    """Create an AuditService writing to tmp."""
    return AuditService(tmp_path / "logs" / "audit.jsonl")


@pytest.fixture
def user_service(initialized_storage: JsonStorageBackend, audit_service: AuditService) -> UserService:
    """Create a UserService."""
    return UserService(
        storage=initialized_storage,
        audit=audit_service,
        lockout_threshold=3,
        lockout_duration=1800,
    )


@pytest.fixture
def client_service(initialized_storage: JsonStorageBackend, audit_service: AuditService) -> ClientService:
    """Create a ClientService."""
    return ClientService(storage=initialized_storage, audit=audit_service)


@pytest.fixture
def token_service(
    initialized_storage: JsonStorageBackend,
    jwt_handler: JWTHandler,
    audit_service: AuditService,
) -> TokenService:
    """Create a TokenService."""
    return TokenService(
        storage=initialized_storage,
        jwt_handler=jwt_handler,
        audit=audit_service,
        access_lifetime=3600,
        refresh_lifetime=2592000,
    )


@pytest.fixture
def auth_code_service(initialized_storage: JsonStorageBackend) -> AuthCodeService:
    """Create an AuthCodeService."""
    return AuthCodeService(storage=initialized_storage, code_lifetime=300)


@pytest.fixture
def consent_service(initialized_storage: JsonStorageBackend, audit_service: AuditService) -> ConsentService:
    """Create a ConsentService."""
    return ConsentService(storage=initialized_storage, audit=audit_service)


@pytest.fixture
def device_code_service(initialized_storage: JsonStorageBackend) -> DeviceCodeService:
    """Create a DeviceCodeService."""
    return DeviceCodeService(storage=initialized_storage, code_lifetime=900)


@pytest.fixture
def scope_service(initialized_storage: JsonStorageBackend) -> ScopeService:
    """Create a ScopeService."""
    return ScopeService(storage=initialized_storage)


@pytest.fixture
async def test_user(user_service: UserService) -> User:
    """Create and return a test user."""
    return await user_service.register(
        email="test@example.com",
        password="TestPass123",
        name="Test User",
    )


@pytest.fixture
async def admin_user(user_service: UserService, initialized_storage: JsonStorageBackend) -> User:
    """Create and return an admin user."""
    from dataclasses import replace

    user = await user_service.register(
        email="admin@example.com",
        password="AdminPass123",
        name="Admin User",
    )
    admin = replace(user, role=UserRole.ADMIN)
    return await initialized_storage.update_user(admin)


@pytest.fixture
async def test_client(client_service: ClientService, admin_user: User) -> tuple[Client, str]:
    """Create and return a test confidential client with its secret."""
    return await client_service.create_client(
        name="Test App",
        client_type="confidential",
        redirect_uris=["http://localhost:3000/callback"],
        allowed_scopes=["openid", "profile", "email"],
        grant_types=["authorization_code", "refresh_token"],
        created_by=admin_user.id,
    )


@pytest.fixture
async def public_client(client_service: ClientService, admin_user: User) -> tuple[Client, str]:
    """Create and return a public client."""
    return await client_service.create_client(
        name="Public App",
        client_type="public",
        redirect_uris=["http://localhost:3000/callback"],
        allowed_scopes=["openid", "profile"],
        grant_types=["authorization_code"],
        created_by=admin_user.id,
    )


@pytest.fixture
async def service_client(client_service: ClientService, admin_user: User) -> tuple[Client, str]:
    """Create and return a service client."""
    return await client_service.create_client(
        name="Service App",
        client_type="service",
        redirect_uris=[],
        allowed_scopes=["openid"],
        grant_types=["client_credentials"],
        created_by=admin_user.id,
    )
