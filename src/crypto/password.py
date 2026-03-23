"""Password hashing with Argon2id and client secret hashing with bcrypt."""

from __future__ import annotations

import hashlib
import secrets

import argon2
import bcrypt

_password_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return _password_hasher.verify(password_hash, password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
        return False


def hash_client_secret(secret: str) -> str:
    """Hash a client secret using bcrypt."""
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def verify_client_secret(secret: str, secret_hash: str) -> bool:
    """Verify a client secret against a bcrypt hash."""
    try:
        return bcrypt.checkpw(secret.encode(), secret_hash.encode())
    except (ValueError, TypeError):
        return False


def generate_client_secret() -> str:
    """Generate a random client secret (256-bit, URL-safe)."""
    return secrets.token_urlsafe(32)


def generate_opaque_token() -> str:
    """Generate a random opaque token (256-bit, URL-safe)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_auth_code() -> str:
    """Generate a random authorization code (128-bit, URL-safe)."""
    return secrets.token_urlsafe(16)


def generate_device_user_code() -> str:
    """Generate an 8-character alphanumeric user code for device flow."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))
