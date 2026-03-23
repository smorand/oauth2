"""Tests for social login and SAML services."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest

from config import Settings
from models.saml import SAMLIdPConfig, SAMLIdPStatus
from models.user import User
from services.audit_service import AuditService
from services.saml_service import SAMLError, SAMLService
from services.social_service import SocialLoginError, SocialService
from storage.json_backend import JsonStorageBackend


@pytest.fixture
def social_service(initialized_storage: JsonStorageBackend, audit_service: AuditService) -> SocialService:
    return SocialService(
        storage=initialized_storage,
        audit=audit_service,
        google_client_id="google-client-id",
        google_client_secret="google-client-secret",
        google_redirect_uri="http://localhost:8000/federation/google/callback",
        github_client_id="github-client-id",
        github_client_secret="github-client-secret",
        github_redirect_uri="http://localhost:8000/federation/github/callback",
    )


@pytest.fixture
def saml_service(initialized_storage: JsonStorageBackend, audit_service: AuditService) -> SAMLService:
    return SAMLService(
        storage=initialized_storage,
        audit=audit_service,
        issuer_url="http://localhost:8000",
    )


# ── SocialService ──


class TestSocialService:
    def test_generate_state(self, social_service: SocialService) -> None:
        state = social_service.generate_state()
        assert len(state) > 20

    def test_get_google_auth_url(self, social_service: SocialService) -> None:
        url = social_service.get_google_auth_url(state="test-state", nonce="test-nonce")
        assert "accounts.google.com" in url
        assert "test-state" in url
        assert "test-nonce" in url

    def test_get_github_auth_url(self, social_service: SocialService) -> None:
        url = social_service.get_github_auth_url(state="test-state")
        assert "github.com" in url
        assert "test-state" in url

    def test_verify_github_state_correct(self, social_service: SocialService) -> None:
        assert social_service.verify_github_state("abc", "abc")

    def test_verify_github_state_wrong(self, social_service: SocialService) -> None:
        assert not social_service.verify_github_state("abc", "def")

    async def test_handle_google_callback_success(self, social_service: SocialService) -> None:
        """Test Google callback with mocked HTTP calls."""
        id_token = pyjwt.encode(
            {
                "sub": "google-123",
                "email": "googleuser@test.com",
                "name": "Google User",
                "nonce": "test-nonce",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )

        mock_token_response = MagicMock(spec=httpx.Response)
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_response
            mock_client_cls.return_value = mock_client

            user = await social_service.handle_google_callback("auth-code", "test-nonce")
            assert user.email == "googleuser@test.com"

    async def test_handle_google_callback_failed_exchange(self, social_service: SocialService) -> None:
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 400

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="Failed to exchange"):
                await social_service.handle_google_callback("bad-code", "nonce")

    async def test_handle_google_callback_no_id_token(self, social_service: SocialService) -> None:
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="No ID token"):
                await social_service.handle_google_callback("code", "nonce")

    async def test_handle_google_callback_nonce_mismatch(self, social_service: SocialService) -> None:
        id_token = pyjwt.encode(
            {
                "sub": "g123",
                "email": "a@b.com",
                "nonce": "wrong-nonce",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="nonce mismatch"):
                await social_service.handle_google_callback("code", "expected-nonce")

    async def test_handle_github_callback_success(self, social_service: SocialService) -> None:
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "gh-token-123"}

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 200
        mock_user_resp.json.return_value = {"id": 12345, "name": "GH User", "login": "ghuser"}

        mock_email_resp = MagicMock(spec=httpx.Response)
        mock_email_resp.status_code = 200
        mock_email_resp.json.return_value = [{"email": "ghuser@test.com", "primary": True, "verified": True}]

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_resp
            mock_client.get.side_effect = [mock_user_resp, mock_email_resp]
            mock_client_cls.return_value = mock_client

            user = await social_service.handle_github_callback("auth-code")
            assert user.email == "ghuser@test.com"

    async def test_handle_github_callback_failed_token(self, social_service: SocialService) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 400

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="Failed to exchange"):
                await social_service.handle_github_callback("bad-code")

    async def test_handle_github_callback_no_access_token(self, social_service: SocialService) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error_description": "bad request"}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="token error"):
                await social_service.handle_github_callback("code")

    async def test_handle_github_callback_failed_user_fetch(self, social_service: SocialService) -> None:
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "tok"}

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 500

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_resp
            mock_client.get.return_value = mock_user_resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="Failed to fetch GitHub user"):
                await social_service.handle_github_callback("code")

    async def test_handle_github_callback_no_verified_email(self, social_service: SocialService) -> None:
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "tok"}

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 200
        mock_user_resp.json.return_value = {"id": 1, "name": "User"}

        mock_email_resp = MagicMock(spec=httpx.Response)
        mock_email_resp.status_code = 200
        mock_email_resp.json.return_value = [{"email": "unverified@test.com", "primary": True, "verified": False}]

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_resp
            mock_client.get.side_effect = [mock_user_resp, mock_email_resp]
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="no verified email"):
                await social_service.handle_github_callback("code")

    async def test_handle_google_callback_no_email(self, social_service: SocialService) -> None:
        """Google account with no email should raise."""
        id_token = pyjwt.encode(
            {
                "sub": "g-no-email",
                "nonce": "nonce1",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="no email"):
                await social_service.handle_google_callback("code", "nonce1")

    async def test_handle_google_callback_invalid_id_token(self, social_service: SocialService) -> None:
        """Invalid ID token (wrong issuer) should raise."""
        id_token = pyjwt.encode(
            {
                "sub": "g123",
                "email": "a@b.com",
                "nonce": "nonce1",
                "iss": "https://wrong-issuer.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="Invalid Google ID token"):
                await social_service.handle_google_callback("code", "nonce1")

    async def test_handle_github_callback_email_fetch_failed(self, social_service: SocialService) -> None:
        """GitHub email fetch failure should raise."""
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "tok"}

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 200
        mock_user_resp.json.return_value = {"id": 1, "name": "User"}

        mock_email_resp = MagicMock(spec=httpx.Response)
        mock_email_resp.status_code = 500

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_resp
            mock_client.get.side_effect = [mock_user_resp, mock_email_resp]
            mock_client_cls.return_value = mock_client

            with pytest.raises(SocialLoginError, match="email"):
                await social_service.handle_github_callback("code")

    async def test_handle_github_callback_secondary_verified_email(self, social_service: SocialService) -> None:
        """GitHub account with only secondary verified email should use it."""
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "tok"}

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 200
        mock_user_resp.json.return_value = {"id": 99999, "name": "SecUser"}

        mock_email_resp = MagicMock(spec=httpx.Response)
        mock_email_resp.status_code = 200
        mock_email_resp.json.return_value = [
            {"email": "notprimary@test.com", "primary": False, "verified": True},
            {"email": "unverified@test.com", "primary": True, "verified": False},
        ]

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_token_resp
            mock_client.get.side_effect = [mock_user_resp, mock_email_resp]
            mock_client_cls.return_value = mock_client

            user = await social_service.handle_github_callback("code")
            assert user.email == "notprimary@test.com"

    async def test_returning_social_user_login(
        self, social_service: SocialService, initialized_storage: JsonStorageBackend
    ) -> None:
        """Test that a returning social user (existing social account) is returned directly."""
        # First login creates user
        id_token = pyjwt.encode(
            {
                "sub": "returning-google-123",
                "email": "returning@test.com",
                "name": "Returning User",
                "nonce": "n1",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client
            user1 = await social_service.handle_google_callback("code", "n1")

        # Second login should find existing social account
        id_token2 = pyjwt.encode(
            {
                "sub": "returning-google-123",
                "email": "returning@test.com",
                "name": "Returning User",
                "nonce": "n2",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response2 = MagicMock(spec=httpx.Response)
        mock_response2.status_code = 200
        mock_response2.json.return_value = {"id_token": id_token2}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response2
            mock_client_cls.return_value = mock_client
            user2 = await social_service.handle_google_callback("code", "n2")

        assert user1.id == user2.id

    async def test_find_or_create_existing_social_user(
        self, social_service: SocialService, initialized_storage: JsonStorageBackend
    ) -> None:
        """Test linking to existing user by email."""
        user = User(email="existing@test.com", name="Existing")
        user = await initialized_storage.create_user(user)

        # Simulate Google login with same email
        id_token = pyjwt.encode(
            {
                "sub": "new-google-id",
                "email": "existing@test.com",
                "name": "Existing",
                "nonce": "nonce1",
                "iss": "https://accounts.google.com",
                "aud": "google-client-id",
                "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.now(tz=UTC).timestamp()),
            },
            "secret",
            algorithm="HS256",
        )
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": id_token}

        with patch("services.social_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await social_service.handle_google_callback("code", "nonce1")
            assert result.id == user.id  # Same user, linked


# ── SAMLService ──


class TestSAMLService:
    async def test_get_active_idps(self, saml_service: SAMLService, initialized_storage: JsonStorageBackend) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Active IdP",
                entity_id="https://idp.test.com",
                sso_url="https://idp.test.com/sso",
                certificate="CERT",
                status=SAMLIdPStatus.ACTIVE,
            )
        )
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Inactive IdP",
                entity_id="https://idp2.test.com",
                sso_url="https://idp2.test.com/sso",
                certificate="CERT",
                status=SAMLIdPStatus.DEACTIVATED,
            )
        )
        active = await saml_service.get_active_idps()
        assert len(active) == 1
        assert active[0].name == "Active IdP"

    async def test_get_idp(self, saml_service: SAMLService, initialized_storage: JsonStorageBackend) -> None:
        idp = await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Test IdP",
                entity_id="https://idp.test.com",
                sso_url="https://idp.test.com/sso",
                certificate="CERT",
            )
        )
        result = await saml_service.get_idp(idp.id)
        assert result is not None
        assert result.name == "Test IdP"

    def test_generate_relay_state(self, saml_service: SAMLService) -> None:
        state = saml_service.generate_relay_state()
        assert len(state) > 20

    def test_generate_authn_request_redirect(self, saml_service: SAMLService) -> None:
        idp = SAMLIdPConfig(
            name="Test",
            entity_id="https://idp.test.com",
            sso_url="https://idp.test.com/sso",
            certificate="CERT",
        )
        url = saml_service.generate_authn_request_redirect(idp, "relay-state-123")
        assert "idp.test.com/sso" in url
        assert "SAMLRequest" in url
        assert "RelayState" in url

    async def test_handle_saml_response_invalid_encoding(self, saml_service: SAMLService) -> None:
        with pytest.raises(SAMLError, match="Invalid SAML Response"):
            await saml_service.handle_saml_response("not-valid-base64!!!", "relay")

    async def test_handle_saml_response_missing_issuer(self, saml_service: SAMLService) -> None:
        # Valid XML but no Issuer
        xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>'
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="missing Issuer"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_unknown_idp(self, saml_service: SAMLService) -> None:
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Issuer>https://unknown-idp.com</saml:Issuer>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="Unknown SAML IdP"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_failed_status(self, saml_service: SAMLService) -> None:
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>'
            "<saml:Issuer>https://idp.test.com</saml:Issuer>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="authentication failed"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_success(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Success IdP",
                entity_id="https://idp.success.com",
                sso_url="https://idp.success.com/sso",
                certificate="CERT",
            )
        )
        now = datetime.now(tz=UTC)
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.success.com</saml:Issuer>"
            f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"/>'
            "<saml:Subject><saml:NameID>samluser@test.com</saml:NameID></saml:Subject>"
            "<saml:AttributeStatement>"
            '<saml:Attribute Name="email"><saml:AttributeValue>samluser@test.com</saml:AttributeValue></saml:Attribute>'
            '<saml:Attribute Name="name"><saml:AttributeValue>SAML User</saml:AttributeValue></saml:Attribute>'
            "</saml:AttributeStatement>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        user = await saml_service.handle_saml_response(b64, "relay")
        assert user.email == "samluser@test.com"

    async def test_handle_saml_response_missing_assertion(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="NoAssert IdP",
                entity_id="https://idp.noassert.com",
                sso_url="https://idp.noassert.com/sso",
                certificate="CERT",
            )
        )
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Issuer>https://idp.noassert.com</saml:Issuer>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="missing Assertion"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_not_yet_valid(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Future IdP",
                entity_id="https://idp.future.com",
                sso_url="https://idp.future.com/sso",
                certificate="CERT",
            )
        )
        future = (datetime.now(tz=UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        far_future = (datetime.now(tz=UTC) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.future.com</saml:Issuer>"
            f'<saml:Conditions NotBefore="{future}" NotOnOrAfter="{far_future}"/>'
            "<saml:Subject><saml:NameID>user@test.com</saml:NameID></saml:Subject>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="not yet valid"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_missing_nameid(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="NoNameID IdP",
                entity_id="https://idp.nonameid.com",
                sso_url="https://idp.nonameid.com/sso",
                certificate="CERT",
            )
        )
        now = datetime.now(tz=UTC)
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.nonameid.com</saml:Issuer>"
            f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"/>'
            "<saml:Subject></saml:Subject>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="missing NameID"):
            await saml_service.handle_saml_response(b64, "relay")

    async def test_handle_saml_response_returning_user(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        """Second SAML login should return existing user via social account lookup."""
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Return IdP",
                entity_id="https://idp.return.com",
                sso_url="https://idp.return.com/sso",
                certificate="CERT",
            )
        )
        now = datetime.now(tz=UTC)
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.return.com</saml:Issuer>"
            f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"/>'
            "<saml:Subject><saml:NameID>returning@test.com</saml:NameID></saml:Subject>"
            "<saml:AttributeStatement>"
            '<saml:Attribute Name="email"><saml:AttributeValue>returning@test.com</saml:AttributeValue></saml:Attribute>'
            "</saml:AttributeStatement>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        user1 = await saml_service.handle_saml_response(b64, "relay")
        # Second login
        user2 = await saml_service.handle_saml_response(b64, "relay")
        assert user1.id == user2.id

    async def test_handle_saml_response_link_existing_user(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        """SAML login should link to existing user with same email."""
        # Create user first
        existing_user = User(email="linked-saml@test.com", name="Existing")
        existing_user = await initialized_storage.create_user(existing_user)

        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Link IdP",
                entity_id="https://idp.link.com",
                sso_url="https://idp.link.com/sso",
                certificate="CERT",
            )
        )
        now = datetime.now(tz=UTC)
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.link.com</saml:Issuer>"
            f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"/>'
            "<saml:Subject><saml:NameID>linked-saml@test.com</saml:NameID></saml:Subject>"
            "<saml:AttributeStatement>"
            '<saml:Attribute Name="email"><saml:AttributeValue>linked-saml@test.com</saml:AttributeValue></saml:Attribute>'
            "</saml:AttributeStatement>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        result = await saml_service.handle_saml_response(b64, "relay")
        assert result.id == existing_user.id

    async def test_handle_saml_response_expired(
        self, saml_service: SAMLService, initialized_storage: JsonStorageBackend
    ) -> None:
        await initialized_storage.create_saml_idp(
            SAMLIdPConfig(
                name="Expired IdP",
                entity_id="https://idp.expired.com",
                sso_url="https://idp.expired.com/sso",
                certificate="CERT",
            )
        )
        past = (datetime.now(tz=UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "<saml:Assertion>"
            "<saml:Issuer>https://idp.expired.com</saml:Issuer>"
            f'<saml:Conditions NotOnOrAfter="{past}"/>'
            "<saml:Subject><saml:NameID>user@test.com</saml:NameID></saml:Subject>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xml.encode()).decode()
        with pytest.raises(SAMLError, match="expired"):
            await saml_service.handle_saml_response(b64, "relay")


# ── Bootstrap ──


class TestBootstrap:
    async def test_create_admin_user(self, tmp_settings: Settings) -> None:
        from services.bootstrap import create_admin_user

        user = await create_admin_user(tmp_settings, "bootstrap@test.com", "AdminPass1", "Boot Admin")
        assert user.email == "bootstrap@test.com"
        assert user.role.value == "admin"

    async def test_create_admin_user_duplicate(self, tmp_settings: Settings) -> None:
        from services.bootstrap import create_admin_user

        await create_admin_user(tmp_settings, "dupboot@test.com", "AdminPass1")
        with pytest.raises(ValueError, match="already exists"):
            await create_admin_user(tmp_settings, "dupboot@test.com", "AdminPass1")
