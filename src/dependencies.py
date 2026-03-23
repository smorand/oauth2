"""FastAPI dependency injection setup."""

from __future__ import annotations

from config import Settings
from crypto.jwt_handler import JWTHandler
from crypto.keys import KeyManager
from services.audit_service import AuditService
from services.auth_code_service import AuthCodeService
from services.client_service import ClientService
from services.consent_service import ConsentService
from services.device_code_service import DeviceCodeService
from services.scope_service import ScopeService
from services.token_service import TokenService
from services.user_service import UserService
from storage.json_backend import JsonStorageBackend


class AppDependencies:
    """Container for all application dependencies."""

    __slots__ = (
        "audit",
        "auth_code_service",
        "client_service",
        "consent_service",
        "device_code_service",
        "jwt_handler",
        "key_manager",
        "scope_service",
        "settings",
        "storage",
        "token_service",
        "user_service",
    )

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

        self.key_manager = KeyManager()
        if settings.rsa_private_key_path.exists():
            self.key_manager.load_from_files(settings.rsa_private_key_path)
        else:
            self.key_manager.generate_key()

        self.jwt_handler = JWTHandler(self.key_manager, settings.issuer_url)

        self.storage = JsonStorageBackend(settings.json_storage_dir)

        self.audit = AuditService(settings.audit_log_path)

        self.user_service = UserService(
            storage=self.storage,
            audit=self.audit,
            lockout_threshold=settings.account_lockout_threshold,
            lockout_duration=settings.account_lockout_duration,
        )

        self.client_service = ClientService(
            storage=self.storage,
            audit=self.audit,
        )

        self.token_service = TokenService(
            storage=self.storage,
            jwt_handler=self.jwt_handler,
            audit=self.audit,
            access_lifetime=settings.access_token_lifetime,
            refresh_lifetime=settings.refresh_token_lifetime,
        )

        self.auth_code_service = AuthCodeService(
            storage=self.storage,
            code_lifetime=settings.auth_code_lifetime,
        )

        self.consent_service = ConsentService(
            storage=self.storage,
            audit=self.audit,
        )

        self.device_code_service = DeviceCodeService(
            storage=self.storage,
            code_lifetime=settings.device_code_lifetime,
        )

        self.scope_service = ScopeService(storage=self.storage)

    async def initialize(self) -> None:
        """Initialize async resources."""
        await self.storage.initialize()
