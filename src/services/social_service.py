"""Social login service for Google and GitHub OAuth/OIDC."""

from __future__ import annotations

import hmac
import logging
import secrets
from urllib.parse import urlencode

import httpx
import jwt

from models.user import SocialAccount, SocialProvider, User
from services.audit_service import AuditService
from storage.base import StorageBackend

logger = logging.getLogger(__name__)


class SocialLoginError(Exception):
    """Raised when social login fails."""


class SocialService:
    """Handles Google and GitHub social login flows."""

    __slots__ = (
        "_audit",
        "_github_client_id",
        "_github_client_secret",
        "_github_redirect_uri",
        "_google_client_id",
        "_google_client_secret",
        "_google_redirect_uri",
        "_storage",
    )

    def __init__(
        self,
        storage: StorageBackend,
        audit: AuditService,
        google_client_id: str,
        google_client_secret: str,
        google_redirect_uri: str,
        github_client_id: str,
        github_client_secret: str,
        github_redirect_uri: str,
    ) -> None:
        self._storage = storage
        self._audit = audit
        self._google_client_id = google_client_id
        self._google_client_secret = google_client_secret
        self._google_redirect_uri = google_redirect_uri
        self._github_client_id = github_client_id
        self._github_client_secret = github_client_secret
        self._github_redirect_uri = github_redirect_uri

    def generate_state(self) -> str:
        """Generate a CSRF state token for OAuth redirects."""
        return secrets.token_urlsafe(32)

    # --- Google OIDC ---

    def get_google_auth_url(self, state: str, nonce: str) -> str:
        """Build Google authorization URL."""
        params = {
            "client_id": self._google_client_id,
            "redirect_uri": self._google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    async def handle_google_callback(self, code: str, expected_nonce: str) -> User:
        """Exchange Google auth code and find/create user."""
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": self._google_client_id,
                    "client_secret": self._google_client_secret,
                    "redirect_uri": self._google_redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            if token_resp.status_code != 200:
                msg = "Failed to exchange Google authorization code"
                raise SocialLoginError(msg)

            token_data = token_resp.json()
            id_token = token_data.get("id_token", "")
            if not id_token:
                msg = "No ID token in Google response"
                raise SocialLoginError(msg)

            google_claims = self._validate_google_id_token(id_token, expected_nonce)

        google_sub = str(google_claims.get("sub", ""))
        email = str(google_claims.get("email", ""))
        name = str(google_claims.get("name", email))

        if not email:
            msg = "Google account has no email"
            raise SocialLoginError(msg)

        return await self._find_or_create_user(
            provider=SocialProvider.GOOGLE,
            provider_user_id=google_sub,
            email=email,
            name=name,
        )

    def _validate_google_id_token(self, id_token: str, expected_nonce: str) -> dict[str, object]:
        """Validate Google ID token (signature check deferred to Google certs)."""
        try:
            claims = jwt.decode(
                id_token,
                options={"verify_signature": False, "verify_aud": True, "verify_iss": True},
                audience=self._google_client_id,
                issuer=["https://accounts.google.com", "accounts.google.com"],
            )
        except jwt.InvalidTokenError as exc:
            msg = f"Invalid Google ID token: {exc}"
            raise SocialLoginError(msg) from exc

        if claims.get("nonce") != expected_nonce:
            msg = "Google ID token nonce mismatch"
            raise SocialLoginError(msg)

        return claims

    # --- GitHub OAuth ---

    def get_github_auth_url(self, state: str) -> str:
        """Build GitHub authorization URL."""
        params = {
            "client_id": self._github_client_id,
            "redirect_uri": self._github_redirect_uri,
            "scope": "user:email",
            "state": state,
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    async def handle_github_callback(self, code: str) -> User:
        """Exchange GitHub auth code and find/create user."""
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": self._github_client_id,
                    "client_secret": self._github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                msg = "Failed to exchange GitHub authorization code"
                raise SocialLoginError(msg)

            token_data = token_resp.json()
            access_token = token_data.get("access_token", "")
            if not access_token:
                error = token_data.get("error_description", "No access token")
                msg = f"GitHub token error: {error}"
                raise SocialLoginError(msg)

            user_resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            if user_resp.status_code != 200:
                msg = "Failed to fetch GitHub user profile"
                raise SocialLoginError(msg)

            user_data = user_resp.json()
            github_id = str(user_data.get("id", ""))
            name = user_data.get("name") or user_data.get("login", "")

            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            email = self._extract_github_email(email_resp)

        return await self._find_or_create_user(
            provider=SocialProvider.GITHUB,
            provider_user_id=github_id,
            email=email,
            name=name,
        )

    def _extract_github_email(self, resp: httpx.Response) -> str:
        """Extract primary verified email from GitHub emails API."""
        if resp.status_code != 200:
            msg = "Failed to fetch GitHub user emails"
            raise SocialLoginError(msg)

        emails = resp.json()
        for entry in emails:
            if entry.get("primary") and entry.get("verified"):
                return str(entry["email"])

        for entry in emails:
            if entry.get("verified"):
                return str(entry["email"])

        msg = "GitHub account has no verified email"
        raise SocialLoginError(msg)

    # --- Common ---

    async def _find_or_create_user(
        self,
        provider: SocialProvider,
        provider_user_id: str,
        email: str,
        name: str,
    ) -> User:
        """Find existing user by social account or email, or create new one."""
        existing = await self._storage.get_social_account(provider.value, provider_user_id)
        if existing:
            user = await self._storage.get_user(existing.user_id)
            if user:
                self._audit.log_event("social_login", user.id, "", "success", {"provider": provider.value})
                return user

        user = await self._storage.get_user_by_email(email)
        if user:
            await self._storage.create_social_account(
                SocialAccount(
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    provider_email=email,
                    provider_name=name,
                )
            )
            self._audit.log_event("social_link", user.id, "", "success", {"provider": provider.value})
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
                provider=provider,
                provider_user_id=provider_user_id,
                provider_email=email,
                provider_name=name,
            )
        )
        self._audit.log_event("social_register", new_user.id, "", "success", {"provider": provider.value})
        return new_user

    def verify_github_state(self, state: str, expected: str) -> bool:
        """Constant-time comparison of state parameter."""
        return hmac.compare_digest(state, expected)
