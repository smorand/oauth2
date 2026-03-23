"""Tests for business logic services."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from crypto.password import hash_token
from crypto.pkce import compute_code_challenge
from models.client import Client, ClientType
from models.user import User, UserStatus
from services.audit_service import AuditService
from services.auth_code_service import AuthCodeError, AuthCodeService
from services.client_service import ClientService, ClientServiceError
from services.consent_service import ConsentService, ConsentServiceError
from services.device_code_service import DeviceCodeError, DeviceCodeService
from services.scope_service import ScopeService, ScopeServiceError
from services.token_service import TokenService, TokenServiceError
from services.user_service import UserService, UserServiceError
from storage.json_backend import JsonStorageBackend

# ── UserService ──


class TestUserService:
    async def test_register_success(self, user_service: UserService) -> None:
        user = await user_service.register("new@example.com", "StrongPass1", "New User")
        assert user.email == "new@example.com"
        assert user.name == "New User"
        assert user.password_hash is not None

    async def test_register_invalid_email(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="Invalid email"):
            await user_service.register("not-an-email", "StrongPass1")

    async def test_register_weak_password(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="Password must be"):
            await user_service.register("weak@example.com", "weak")

    async def test_register_password_no_uppercase(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="Password must be"):
            await user_service.register("weak@example.com", "lowercase1")

    async def test_register_password_no_digit(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="Password must be"):
            await user_service.register("weak@example.com", "NoDigitHere")

    async def test_register_duplicate_email(self, user_service: UserService, test_user: User) -> None:
        with pytest.raises(UserServiceError, match="already registered"):
            await user_service.register("test@example.com", "StrongPass1")

    async def test_authenticate_success(self, user_service: UserService, test_user: User) -> None:
        user = await user_service.authenticate("test@example.com", "TestPass123")
        assert user.id == test_user.id

    async def test_authenticate_wrong_password(self, user_service: UserService, test_user: User) -> None:
        with pytest.raises(UserServiceError, match="Invalid credentials"):
            await user_service.authenticate("test@example.com", "WrongPass123")

    async def test_authenticate_unknown_email(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="Invalid credentials"):
            await user_service.authenticate("nobody@example.com", "Whatever1")

    async def test_authenticate_deactivated(
        self, user_service: UserService, test_user: User, initialized_storage: JsonStorageBackend
    ) -> None:
        deactivated = replace(test_user, status=UserStatus.DEACTIVATED)
        await initialized_storage.update_user(deactivated)
        with pytest.raises(UserServiceError, match="deactivated"):
            await user_service.authenticate("test@example.com", "TestPass123")

    async def test_account_lockout(self, user_service: UserService, test_user: User) -> None:
        # Lockout threshold is 3
        for _ in range(3):
            with pytest.raises(UserServiceError, match="Invalid credentials"):
                await user_service.authenticate("test@example.com", "WrongPass999")
        with pytest.raises(UserServiceError, match="Account locked"):
            await user_service.authenticate("test@example.com", "TestPass123")

    async def test_authenticate_resets_failed_attempts(self, user_service: UserService, test_user: User) -> None:
        # Fail once, then succeed
        with pytest.raises(UserServiceError):
            await user_service.authenticate("test@example.com", "WrongPass999")
        user = await user_service.authenticate("test@example.com", "TestPass123")
        assert user.failed_login_attempts == 0

    async def test_get_user(self, user_service: UserService, test_user: User) -> None:
        user = await user_service.get_user(test_user.id)
        assert user is not None
        assert user.email == "test@example.com"

    async def test_get_user_by_email(self, user_service: UserService, test_user: User) -> None:
        user = await user_service.get_user_by_email("TEST@example.com")
        assert user is not None

    async def test_unlock_user(self, user_service: UserService, test_user: User) -> None:
        # Lock the user first
        for _ in range(3):
            with pytest.raises(UserServiceError):
                await user_service.authenticate("test@example.com", "WrongPass999")
        # Unlock
        unlocked = await user_service.unlock_user(test_user.id)
        assert unlocked.status == UserStatus.ACTIVE
        assert unlocked.failed_login_attempts == 0

    async def test_unlock_nonexistent_user(self, user_service: UserService) -> None:
        with pytest.raises(UserServiceError, match="User not found"):
            await user_service.unlock_user("nonexistent")

    async def test_list_users(self, user_service: UserService, test_user: User) -> None:
        _users, total = await user_service.list_users()
        assert total >= 1

    async def test_search_users(self, user_service: UserService, test_user: User) -> None:
        _users, total = await user_service.search_users("test")
        assert total >= 1


# ── ClientService ──


class TestClientService:
    async def test_create_confidential_client(self, client_service: ClientService, admin_user: User) -> None:
        client, secret = await client_service.create_client(
            name="Confidential",
            client_type="confidential",
            redirect_uris=["http://localhost/cb"],
            allowed_scopes=["openid"],
            grant_types=["authorization_code"],
            created_by=admin_user.id,
        )
        assert client.type == ClientType.CONFIDENTIAL
        assert len(secret) > 0
        assert client.secret_hash is not None

    async def test_create_public_client(self, client_service: ClientService, admin_user: User) -> None:
        client, secret = await client_service.create_client(
            name="Public",
            client_type="public",
            redirect_uris=["http://localhost/cb"],
            allowed_scopes=["openid"],
            grant_types=["authorization_code"],
            created_by=admin_user.id,
        )
        assert client.type == ClientType.PUBLIC
        assert secret == ""

    async def test_create_service_client(self, service_client: tuple[Client, str]) -> None:
        client, secret = service_client
        assert client.type == ClientType.SERVICE
        assert len(secret) > 0

    async def test_create_duplicate_name(
        self, client_service: ClientService, admin_user: User, test_client: tuple[Client, str]
    ) -> None:
        with pytest.raises(ClientServiceError, match="already exists"):
            await client_service.create_client(
                name="Test App",
                client_type="confidential",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["openid"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )

    async def test_create_invalid_type(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="Invalid client type"):
            await client_service.create_client(
                name="Bad",
                client_type="invalid",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["openid"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )

    async def test_create_invalid_grant_type(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="Invalid grant type"):
            await client_service.create_client(
                name="BadGrant",
                client_type="confidential",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["openid"],
                grant_types=["implicit"],
                created_by=admin_user.id,
            )

    async def test_service_client_cannot_use_auth_code(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="cannot use authorization_code"):
            await client_service.create_client(
                name="BadService",
                client_type="service",
                redirect_uris=[],
                allowed_scopes=["openid"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )

    async def test_non_service_cannot_use_client_credentials(
        self, client_service: ClientService, admin_user: User
    ) -> None:
        with pytest.raises(ClientServiceError, match="Only service clients"):
            await client_service.create_client(
                name="BadCreds",
                client_type="confidential",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["openid"],
                grant_types=["client_credentials"],
                created_by=admin_user.id,
            )

    async def test_service_with_redirect_uris(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="should not have redirect URIs"):
            await client_service.create_client(
                name="BadServiceURI",
                client_type="service",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["openid"],
                grant_types=["client_credentials"],
                created_by=admin_user.id,
            )

    async def test_non_service_without_redirect_uris(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="must have at least one redirect"):
            await client_service.create_client(
                name="NoURI",
                client_type="confidential",
                redirect_uris=[],
                allowed_scopes=["openid"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )

    async def test_create_with_invalid_scopes(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="Unknown scopes"):
            await client_service.create_client(
                name="BadScopes",
                client_type="confidential",
                redirect_uris=["http://localhost/cb"],
                allowed_scopes=["nonexistent_scope"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )

    async def test_authenticate_confidential_client(
        self, client_service: ClientService, test_client: tuple[Client, str]
    ) -> None:
        client, secret = test_client
        authenticated = await client_service.authenticate_client(client.id, secret)
        assert authenticated.id == client.id

    async def test_authenticate_public_client(
        self, client_service: ClientService, public_client: tuple[Client, str]
    ) -> None:
        client, _ = public_client
        authenticated = await client_service.authenticate_client(client.id, "")
        assert authenticated.id == client.id

    async def test_authenticate_wrong_secret(
        self, client_service: ClientService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        with pytest.raises(ClientServiceError, match="Invalid client credentials"):
            await client_service.authenticate_client(client.id, "wrong-secret")

    async def test_authenticate_nonexistent_client(self, client_service: ClientService) -> None:
        with pytest.raises(ClientServiceError, match="Invalid client"):
            await client_service.authenticate_client("nonexistent", "secret")

    async def test_authenticate_deactivated_client(
        self, client_service: ClientService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        await client_service.deactivate_client(client.id)
        with pytest.raises(ClientServiceError, match="deactivated"):
            await client_service.authenticate_client(client.id, "any")

    async def test_update_client(self, client_service: ClientService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        updated = await client_service.update_client(client.id, name="New Name")
        assert updated.name == "New Name"

    async def test_update_nonexistent_client(self, client_service: ClientService) -> None:
        with pytest.raises(ClientServiceError, match="Client not found"):
            await client_service.update_client("missing", name="X")

    async def test_deactivate_client(self, client_service: ClientService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        result = await client_service.deactivate_client(client.id)
        assert result.status.value == "deactivated"

    async def test_deactivate_nonexistent_client(self, client_service: ClientService) -> None:
        with pytest.raises(ClientServiceError, match="Client not found"):
            await client_service.deactivate_client("missing")

    async def test_rotate_secret(self, client_service: ClientService, test_client: tuple[Client, str]) -> None:
        client, old_secret = test_client
        updated_client, new_secret = await client_service.rotate_secret(client.id)
        assert new_secret != old_secret
        # New secret should work
        auth = await client_service.authenticate_client(updated_client.id, new_secret)
        assert auth.id == client.id

    async def test_rotate_secret_public_client(
        self, client_service: ClientService, public_client: tuple[Client, str]
    ) -> None:
        client, _ = public_client
        with pytest.raises(ClientServiceError, match="do not have secrets"):
            await client_service.rotate_secret(client.id)

    async def test_rotate_secret_nonexistent(self, client_service: ClientService) -> None:
        with pytest.raises(ClientServiceError, match="Client not found"):
            await client_service.rotate_secret("missing")

    async def test_list_clients(self, client_service: ClientService, test_client: tuple[Client, str]) -> None:
        _clients, total = await client_service.list_clients()
        assert total >= 1

    async def test_redirect_uri_too_long(self, client_service: ClientService, admin_user: User) -> None:
        with pytest.raises(ClientServiceError, match="too long"):
            await client_service.create_client(
                name="LongURI",
                client_type="confidential",
                redirect_uris=["http://localhost/" + "x" * 2100],
                allowed_scopes=["openid"],
                grant_types=["authorization_code"],
                created_by=admin_user.id,
            )


# ── TokenService ──


class TestTokenService:
    async def test_issue_tokens(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await token_service.issue_tokens(test_user, client, "openid profile")
        assert "access_token" in result
        assert "refresh_token" in result
        assert "id_token" in result
        assert result["token_type"] == "Bearer"

    async def test_issue_tokens_without_openid(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await token_service.issue_tokens(test_user, client, "profile")
        assert "access_token" in result
        assert "id_token" not in result

    async def test_issue_tokens_without_refresh(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await token_service.issue_tokens(test_user, client, "openid", include_refresh=False)
        assert "access_token" in result
        assert "refresh_token" not in result

    async def test_issue_client_credentials_token(
        self, token_service: TokenService, service_client: tuple[Client, str]
    ) -> None:
        client, _ = service_client
        result = await token_service.issue_client_credentials_token(client, "openid")
        assert "access_token" in result
        assert "refresh_token" not in result

    async def test_refresh_tokens(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid profile")
        refresh_plain = str(tokens["refresh_token"])
        new_tokens = await token_service.refresh_tokens(refresh_plain, client.id)
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        assert new_tokens["refresh_token"] != refresh_plain

    async def test_refresh_tokens_invalid(self, token_service: TokenService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        with pytest.raises(TokenServiceError, match="Invalid refresh token"):
            await token_service.refresh_tokens("invalid-token", client.id)

    async def test_refresh_tokens_reuse_detection(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid")
        refresh_plain = str(tokens["refresh_token"])
        # First refresh should succeed
        await token_service.refresh_tokens(refresh_plain, client.id)
        # Second use of same token should fail and revoke family
        with pytest.raises(TokenServiceError, match="reuse detected"):
            await token_service.refresh_tokens(refresh_plain, client.id)

    async def test_refresh_tokens_client_mismatch(
        self,
        token_service: TokenService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid")
        refresh_plain = str(tokens["refresh_token"])
        with pytest.raises(TokenServiceError, match="Client mismatch"):
            await token_service.refresh_tokens(refresh_plain, "other-client")

    async def test_introspect_valid_token(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid")
        result = await token_service.introspect(str(tokens["access_token"]), client.id)
        assert result["active"] is True
        assert result["sub"] == test_user.id

    async def test_introspect_invalid_token(self, token_service: TokenService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        result = await token_service.introspect("garbage", client.id)
        assert result["active"] is False

    async def test_revoke_access_token(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid")
        access = str(tokens["access_token"])
        await token_service.revoke(access, "access_token", client.id)
        result = await token_service.introspect(access, client.id)
        assert result["active"] is False

    async def test_revoke_refresh_token(
        self, token_service: TokenService, test_user: User, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        tokens = await token_service.issue_tokens(test_user, client, "openid")
        refresh = str(tokens["refresh_token"])
        await token_service.revoke(refresh, "refresh_token", client.id)
        with pytest.raises(TokenServiceError, match="revoked"):
            await token_service.refresh_tokens(refresh, client.id)

    async def test_revoke_unknown_token(self, token_service: TokenService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        # Should not raise
        await token_service.revoke("unknown-token", "", client.id)


# ── AuthCodeService ──


class TestAuthCodeService:
    async def test_create_and_exchange_code(
        self,
        auth_code_service: AuthCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        plain_code = await auth_code_service.create_code(
            client_id=client.id,
            user_id=test_user.id,
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            code_challenge=challenge,
        )
        auth_code = await auth_code_service.exchange_code(
            code=plain_code,
            client_id=client.id,
            redirect_uri="http://localhost:3000/callback",
            code_verifier=verifier,
        )
        assert auth_code.user_id == test_user.id
        assert auth_code.scope == "openid"

    async def test_exchange_invalid_code(self, auth_code_service: AuthCodeService) -> None:
        with pytest.raises(AuthCodeError, match="Invalid authorization code"):
            await auth_code_service.exchange_code("bad", "c1", "http://x/cb", "verifier")

    async def test_exchange_used_code(
        self,
        auth_code_service: AuthCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        plain_code = await auth_code_service.create_code(
            client_id=client.id,
            user_id=test_user.id,
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            code_challenge=challenge,
        )
        await auth_code_service.exchange_code(plain_code, client.id, "http://localhost:3000/callback", verifier)
        with pytest.raises(AuthCodeError, match="already used"):
            await auth_code_service.exchange_code(plain_code, client.id, "http://localhost:3000/callback", verifier)

    async def test_exchange_wrong_client(
        self,
        auth_code_service: AuthCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        plain_code = await auth_code_service.create_code(
            client_id=client.id,
            user_id=test_user.id,
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            code_challenge=challenge,
        )
        with pytest.raises(AuthCodeError, match="Client mismatch"):
            await auth_code_service.exchange_code(
                plain_code, "other-client", "http://localhost:3000/callback", verifier
            )

    async def test_exchange_wrong_redirect_uri(
        self,
        auth_code_service: AuthCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        plain_code = await auth_code_service.create_code(
            client_id=client.id,
            user_id=test_user.id,
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            code_challenge=challenge,
        )
        with pytest.raises(AuthCodeError, match="Redirect URI mismatch"):
            await auth_code_service.exchange_code(plain_code, client.id, "http://wrong/callback", verifier)

    async def test_exchange_wrong_pkce(
        self,
        auth_code_service: AuthCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        plain_code = await auth_code_service.create_code(
            client_id=client.id,
            user_id=test_user.id,
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            code_challenge=challenge,
        )
        with pytest.raises(AuthCodeError, match="PKCE"):
            await auth_code_service.exchange_code(
                plain_code, client.id, "http://localhost:3000/callback", "wrong-verifier"
            )


# ── ConsentService ──


class TestConsentService:
    async def test_grant_and_check_consent(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        await consent_service.grant_consent(test_user.id, client.id, ["openid", "profile"])
        has = await consent_service.check_existing_consent(test_user.id, client.id, ["openid"])
        assert has is True

    async def test_check_no_consent(
        self,
        consent_service: ConsentService,
        test_user: User,
    ) -> None:
        has = await consent_service.check_existing_consent(test_user.id, "no-client", ["openid"])
        assert has is False

    async def test_check_insufficient_consent(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        has = await consent_service.check_existing_consent(test_user.id, client.id, ["openid", "profile"])
        assert has is False

    async def test_get_missing_scopes(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        missing = await consent_service.get_missing_scopes(test_user.id, client.id, ["openid", "profile"])
        assert missing == ["profile"]

    async def test_get_missing_scopes_no_consent(
        self,
        consent_service: ConsentService,
        test_user: User,
    ) -> None:
        missing = await consent_service.get_missing_scopes(test_user.id, "no-client", ["openid"])
        assert missing == ["openid"]

    async def test_grant_merges_scopes(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        await consent_service.grant_consent(test_user.id, client.id, ["profile"])
        has = await consent_service.check_existing_consent(test_user.id, client.id, ["openid", "profile"])
        assert has is True

    async def test_get_user_consents(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        consents = await consent_service.get_user_consents(test_user.id)
        assert len(consents) >= 1

    async def test_revoke_consent(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        consent = await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        await consent_service.revoke_consent(consent.id, test_user.id)
        has = await consent_service.check_existing_consent(test_user.id, client.id, ["openid"])
        assert has is False

    async def test_revoke_consent_not_found(self, consent_service: ConsentService) -> None:
        with pytest.raises(ConsentServiceError, match="not found"):
            await consent_service.revoke_consent("missing", "user1")

    async def test_revoke_consent_wrong_user(
        self,
        consent_service: ConsentService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        consent = await consent_service.grant_consent(test_user.id, client.id, ["openid"])
        with pytest.raises(ConsentServiceError, match="different user"):
            await consent_service.revoke_consent(consent.id, "other-user")


# ── DeviceCodeService ──


class TestDeviceCodeService:
    async def test_create_device_code(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        assert "device_code" in result
        assert "user_code" in result
        assert "verification_uri" in result
        assert "verification_uri_complete" in result

    async def test_verify_user_code(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        user_code = str(result["user_code"])
        dc = await device_code_service.verify_user_code(user_code)
        assert dc is not None

    async def test_verify_invalid_user_code(self, device_code_service: DeviceCodeService) -> None:
        dc = await device_code_service.verify_user_code("INVALID1")
        assert dc is None

    async def test_approve_and_poll(
        self,
        device_code_service: DeviceCodeService,
        test_user: User,
        test_client: tuple[Client, str],
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        user_code = str(result["user_code"])
        device_code = str(result["device_code"])
        await device_code_service.approve_device_code(user_code, test_user.id)
        dc = await device_code_service.poll_device_code(device_code, client.id)
        assert dc.status == "approved"
        assert dc.user_id == test_user.id

    async def test_poll_pending(self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        with pytest.raises(DeviceCodeError, match="pending"):
            await device_code_service.poll_device_code(str(result["device_code"]), client.id)

    async def test_poll_invalid_code(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        with pytest.raises(DeviceCodeError, match="Invalid"):
            await device_code_service.poll_device_code("bad-code", client.id)

    async def test_poll_wrong_client(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        with pytest.raises(DeviceCodeError, match="Client mismatch"):
            await device_code_service.poll_device_code(str(result["device_code"]), "other-client")

    async def test_deny_device_code(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        user_code = str(result["user_code"])
        device_code = str(result["device_code"])
        await device_code_service.deny_device_code(user_code)
        with pytest.raises(DeviceCodeError, match="denied"):
            await device_code_service.poll_device_code(device_code, client.id)

    async def test_poll_expired_device_code(
        self,
        device_code_service: DeviceCodeService,
        initialized_storage: JsonStorageBackend,
        test_client: tuple[Client, str],
    ) -> None:
        from dataclasses import replace as dc_replace

        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        device_code_plain = str(result["device_code"])
        code_hash = hash_token(device_code_plain)
        stored = await initialized_storage.get_device_code(code_hash)
        expired = dc_replace(stored, expires_at=datetime.now(tz=UTC) - timedelta(minutes=1))
        await initialized_storage.update_device_code(expired)
        with pytest.raises(DeviceCodeError, match="expired"):
            await device_code_service.poll_device_code(device_code_plain, client.id)

    async def test_poll_slow_down(
        self, device_code_service: DeviceCodeService, test_client: tuple[Client, str]
    ) -> None:
        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        device_code = str(result["device_code"])
        # First poll sets last_polled_at
        with pytest.raises(DeviceCodeError, match="pending"):
            await device_code_service.poll_device_code(device_code, client.id)
        # Immediate second poll should get slow_down
        with pytest.raises(DeviceCodeError, match="too fast"):
            await device_code_service.poll_device_code(device_code, client.id)

    async def test_verify_expired_user_code(
        self,
        device_code_service: DeviceCodeService,
        initialized_storage: JsonStorageBackend,
        test_client: tuple[Client, str],
    ) -> None:
        from dataclasses import replace as dc_replace

        client, _ = test_client
        result = await device_code_service.create_device_code(
            client_id=client.id,
            scope="openid",
            verification_uri="http://localhost:8000/device",
        )
        user_code = str(result["user_code"])
        device_code_plain = str(result["device_code"])
        code_hash = hash_token(device_code_plain)
        stored = await initialized_storage.get_device_code(code_hash)
        expired = dc_replace(stored, expires_at=datetime.now(tz=UTC) - timedelta(minutes=1))
        await initialized_storage.update_device_code(expired)
        dc = await device_code_service.verify_user_code(user_code)
        assert dc is None

    async def test_deny_nonexistent(self, device_code_service: DeviceCodeService) -> None:
        # Should not raise
        await device_code_service.deny_device_code("NONEXIST")

    async def test_approve_nonexistent(self, device_code_service: DeviceCodeService) -> None:
        with pytest.raises(DeviceCodeError, match="Invalid user code"):
            await device_code_service.approve_device_code("NONEXIST", "user1")


# ── ScopeService ──


class TestScopeService:
    async def test_create_custom_scope(self, scope_service: ScopeService) -> None:
        scope = await scope_service.create_scope("custom:write", "Custom write access")
        assert scope.name == "custom:write"
        assert scope.built_in is False

    async def test_create_reserved_scope(self, scope_service: ScopeService) -> None:
        with pytest.raises(ScopeServiceError, match="reserved"):
            await scope_service.create_scope("openid")

    async def test_create_duplicate_scope(self, scope_service: ScopeService) -> None:
        await scope_service.create_scope("dup", "first")
        with pytest.raises(ScopeServiceError, match="already exists"):
            await scope_service.create_scope("dup", "second")

    async def test_list_scopes(self, scope_service: ScopeService) -> None:
        scopes = await scope_service.list_scopes()
        assert len(scopes) >= 3  # default scopes

    async def test_delete_scope(self, scope_service: ScopeService) -> None:
        await scope_service.create_scope("deletable", "Will be deleted")
        await scope_service.delete_scope("deletable")
        scopes = await scope_service.list_scopes()
        assert all(s.name != "deletable" for s in scopes)

    async def test_delete_builtin_scope(self, scope_service: ScopeService) -> None:
        with pytest.raises(ScopeServiceError, match="Cannot delete built-in"):
            await scope_service.delete_scope("openid")

    async def test_delete_nonexistent_scope(self, scope_service: ScopeService) -> None:
        with pytest.raises(ScopeServiceError, match="not found"):
            await scope_service.delete_scope("nonexistent")

    async def test_delete_scope_in_use(
        self,
        scope_service: ScopeService,
        client_service: ClientService,
        admin_user: User,
    ) -> None:
        await scope_service.create_scope("in_use", "Used by client")
        await client_service.create_client(
            name="UsingScope",
            client_type="confidential",
            redirect_uris=["http://localhost/cb"],
            allowed_scopes=["in_use"],
            grant_types=["authorization_code"],
            created_by=admin_user.id,
        )
        with pytest.raises(ScopeServiceError, match="in use"):
            await scope_service.delete_scope("in_use")

    async def test_validate_scopes(self, scope_service: ScopeService) -> None:
        result = await scope_service.validate_scopes("openid profile")
        assert result == ["openid", "profile"]

    async def test_validate_empty_scope(self, scope_service: ScopeService) -> None:
        result = await scope_service.validate_scopes("")
        assert result == []

    async def test_validate_invalid_scope(self, scope_service: ScopeService) -> None:
        with pytest.raises(ScopeServiceError, match="Invalid scopes"):
            await scope_service.validate_scopes("nonexistent")

    async def test_validate_unauthorized_scope(self, scope_service: ScopeService) -> None:
        with pytest.raises(ScopeServiceError, match="Unauthorized scopes"):
            await scope_service.validate_scopes("openid profile", allowed_scopes=("openid",))


# ── AuditService ──


class TestAuditService:
    def test_log_event(self, audit_service: AuditService) -> None:
        import json

        audit_service.log_event("test_event", "actor1", "127.0.0.1", "success", {"key": "value"})
        content = audit_service._log_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event_type"] == "test_event"
        assert entry["actor"] == "actor1"
        assert entry["result"] == "success"
        assert entry["details"]["key"] == "value"
