"""Configuration management using pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="OAUTH2_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    issuer_url: str = "http://localhost:8000"
    debug: bool = False

    # RSA Keys
    rsa_private_key_path: Path = Field(default=Path("keys/private.pem"))
    rsa_public_key_path: Path = Field(default=Path("keys/public.pem"))

    # Storage
    storage_backend: str = "json"
    json_storage_dir: Path = Field(default=Path("data"))

    # Token lifetimes (seconds)
    access_token_lifetime: int = 3600
    refresh_token_lifetime: int = 2592000  # 30 days
    auth_code_lifetime: int = 300  # 5 minutes
    device_code_lifetime: int = 900  # 15 minutes

    # Security
    account_lockout_threshold: int = 5
    account_lockout_duration: int = 1800  # 30 minutes
    max_redirect_uri_length: int = 2048

    # Rate limiting
    rate_limit_token: int = 30  # per minute per client
    rate_limit_authorize: int = 60  # per minute per IP
    rate_limit_login: int = 10  # per minute per IP
    rate_limit_admin: int = 120  # per minute per admin

    # Social login (Google)
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # Social login (GitHub)
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = ""

    # CSRF
    csrf_secret: str = "change-me-in-production"

    # Logging
    log_level: str = "INFO"
    audit_log_path: Path = Field(default=Path("logs/audit.jsonl"))
    trace_log_path: Path = Field(default=Path("traces/app.jsonl"))

    @property
    def google_enabled(self) -> bool:
        """Check if Google social login is configured."""
        return bool(self.google_client_id and self.google_client_secret)

    @property
    def github_enabled(self) -> bool:
        """Check if GitHub social login is configured."""
        return bool(self.github_client_id and self.github_client_secret)
