"""Pydantic request/response schemas for API endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class UserRegisterRequest(BaseModel):
    """User registration request."""

    email: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
    name: str = Field(default="")


class UserResponse(BaseModel):
    """User profile response (no sensitive fields)."""

    id: str
    email: str
    name: str
    role: str
    status: str
    created_at: datetime


class TokenRequest(BaseModel):
    """OAuth2 token request (form encoded)."""

    grant_type: str
    code: str = ""
    redirect_uri: str = ""
    client_id: str = ""
    client_secret: str = ""
    code_verifier: str = ""
    refresh_token: str = ""
    scope: str = ""
    device_code: str = ""


class TokenResponse(BaseModel):
    """OAuth2 token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str = ""
    id_token: str = ""
    scope: str = ""


class IntrospectionResponse(BaseModel):
    """Token introspection response (RFC 7662)."""

    active: bool
    sub: str = ""
    scope: str = ""
    client_id: str = ""
    token_type: str = ""
    exp: int = 0
    iat: int = 0
    iss: str = ""


class DeviceAuthorizationResponse(BaseModel):
    """Device authorization response."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: int = 5
    expires_in: int = 900


class ErrorResponse(BaseModel):
    """OAuth2 error response."""

    error: str
    error_description: str = ""


class ClientCreateRequest(BaseModel):
    """Client registration request."""

    name: str = Field(..., min_length=1)
    type: str = Field(...)  # confidential, public, service
    redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)


class ClientResponse(BaseModel):
    """Client details response."""

    client_id: str
    name: str
    type: str
    redirect_uris: list[str]
    allowed_scopes: list[str]
    grant_types: list[str]
    status: str
    created_at: datetime
    client_secret: str = ""


class ClientUpdateRequest(BaseModel):
    """Client update request."""

    name: str | None = None
    redirect_uris: list[str] | None = None
    allowed_scopes: list[str] | None = None
    status: str | None = None


class ScopeCreateRequest(BaseModel):
    """Scope creation request."""

    name: str = Field(..., min_length=1)
    description: str = Field(default="")


class ScopeResponse(BaseModel):
    """Scope response."""

    name: str
    description: str
    built_in: bool
    created_at: datetime


class ConsentResponse(BaseModel):
    """Consent record response."""

    id: str
    client_id: str
    client_name: str
    scopes: list[str]
    granted_at: datetime


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    storage: str
    version: str


class UserAdminResponse(BaseModel):
    """User details for admin API."""

    id: str
    email: str
    name: str
    role: str
    status: str
    failed_login_attempts: int
    locked_until: datetime | None
    created_at: datetime
    updated_at: datetime


class UserUpdateRequest(BaseModel):
    """User update request (admin)."""

    role: str | None = None
    status: str | None = None
    name: str | None = None


class PaginatedResponse(BaseModel):
    """Paginated list response wrapper."""

    items: list[dict[str, object]]
    total: int
    page: int
    page_size: int
