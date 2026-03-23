"""Bootstrap utilities for initial server setup."""

from __future__ import annotations

from config import Settings
from crypto.password import hash_password
from models.user import User, UserRole
from storage.json_backend import JsonStorageBackend


async def create_admin_user(settings: Settings, email: str, password: str, name: str = "Admin") -> User:
    """Create an admin user. Used by CLI for initial setup."""
    storage = JsonStorageBackend(settings.json_storage_dir)
    await storage.initialize()

    existing = await storage.get_user_by_email(email.lower())
    if existing:
        msg = f"User with email {email} already exists"
        raise ValueError(msg)

    user = User(
        email=email.lower(),
        name=name,
        password_hash=hash_password(password),
        role=UserRole.ADMIN,
    )
    return await storage.create_user(user)
