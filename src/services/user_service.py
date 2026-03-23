"""User registration, authentication, and account management."""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from crypto.password import hash_password, verify_password
from models.user import User, UserStatus
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)

PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")


class UserServiceError(Exception):
    """Base error for user operations."""

    __slots__ = ("code",)

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class UserService:
    """Handles user registration, authentication, and management."""

    __slots__ = ("_audit", "_lockout_duration", "_lockout_threshold", "_storage")

    def __init__(
        self,
        storage: StorageBackend,
        audit: AuditService,
        lockout_threshold: int = 5,
        lockout_duration: int = 1800,
    ) -> None:
        self._storage = storage
        self._audit = audit
        self._lockout_threshold = lockout_threshold
        self._lockout_duration = lockout_duration

    async def register(self, email: str, password: str, name: str = "") -> User:
        """Register a new user with email and password."""
        email = email.strip().lower()

        if not _is_valid_email(email):
            msg = "Invalid email format"
            raise UserServiceError(msg, 400)

        if not PASSWORD_PATTERN.match(password):
            msg = "Password must be at least 8 characters with uppercase, lowercase, and digit"
            raise UserServiceError(msg, 400)

        existing = await self._storage.get_user_by_email(email)
        if existing:
            msg = "Email already registered"
            raise UserServiceError(msg, 409)

        user = User(
            email=email,
            name=name,
            password_hash=hash_password(password),
        )
        created = await self._storage.create_user(user)
        self._audit.log_event("user_registered", created.id, "", "success", {"email": email})
        logger.info("User registered: %s", email)
        return created

    async def authenticate(self, email: str, password: str, ip_address: str = "") -> User:
        """Authenticate a user by email and password."""
        email = email.strip().lower()
        user = await self._storage.get_user_by_email(email)

        if not user:
            msg = "Invalid credentials"
            raise UserServiceError(msg, 401)

        if user.status == UserStatus.DEACTIVATED:
            msg = "Account deactivated"
            raise UserServiceError(msg, 403)

        if user.status == UserStatus.LOCKED or (user.locked_until and user.locked_until > datetime.now(tz=UTC)):
            remaining = 0
            if user.locked_until:
                remaining = max(0, int((user.locked_until - datetime.now(tz=UTC)).total_seconds()))
            msg = f"Account locked. Try again in {remaining} seconds"
            raise UserServiceError(msg, 423)

        if not user.password_hash or not verify_password(password, user.password_hash):
            new_attempts = user.failed_login_attempts + 1
            updates: dict[str, object] = {"failed_login_attempts": new_attempts}

            if new_attempts >= self._lockout_threshold:
                locked_until = datetime.now(tz=UTC) + timedelta(seconds=self._lockout_duration)
                updates["locked_until"] = locked_until
                updates["status"] = UserStatus.LOCKED

            updated_user = replace(user, **updates, updated_at=datetime.now(tz=UTC))  # type: ignore[arg-type]
            await self._storage.update_user(updated_user)
            self._audit.log_event("login_failed", user.id, ip_address, "failure", {"attempts": new_attempts})
            msg = "Invalid credentials"
            raise UserServiceError(msg, 401)

        if user.failed_login_attempts > 0:
            user = replace(
                user,
                failed_login_attempts=0,
                locked_until=None,
                status=UserStatus.ACTIVE if user.status == UserStatus.LOCKED else user.status,
                updated_at=datetime.now(tz=UTC),
            )
            await self._storage.update_user(user)

        self._audit.log_event("login_success", user.id, ip_address, "success")
        return user

    async def get_user(self, user_id: str) -> User | None:
        """Get user by ID."""
        return await self._storage.get_user(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        """Get user by email."""
        return await self._storage.get_user_by_email(email.strip().lower())

    async def update_user(self, user: User) -> User:
        """Update a user record."""
        return await self._storage.update_user(user)

    async def unlock_user(self, user_id: str) -> User:
        """Unlock a locked user account (admin operation)."""
        user = await self._storage.get_user(user_id)
        if not user:
            msg = "User not found"
            raise UserServiceError(msg, 404)

        unlocked = replace(
            user,
            status=UserStatus.ACTIVE,
            failed_login_attempts=0,
            locked_until=None,
            updated_at=datetime.now(tz=UTC),
        )
        result = await self._storage.update_user(unlocked)
        self._audit.log_event("user_unlocked", user_id, "", "success")
        return result

    async def list_users(self, page: int = 1, page_size: int = 20) -> tuple[list[User], int]:
        """List users with pagination."""
        return await self._storage.list_users(page, page_size)

    async def search_users(self, query: str, page: int = 1, page_size: int = 20) -> tuple[list[User], int]:
        """Search users by email or name."""
        return await self._storage.search_users(query, page, page_size)


def _is_valid_email(email: str) -> bool:
    """Basic email validation."""
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email))
