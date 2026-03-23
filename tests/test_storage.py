"""Tests for JSON storage backend."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from models.base import utc_now
from models.client import Client, ClientType
from models.consent import Consent
from models.saml import SAMLIdPConfig
from models.scope import Scope
from models.token import AuthorizationCode, DeviceCode, RefreshToken, TokenRevocationEntry
from models.user import SocialAccount, SocialProvider, User
from storage.json_backend import JsonStorageBackend


class TestStorageInitialization:
    async def test_initialize_creates_directory(self, storage: JsonStorageBackend) -> None:
        await storage.initialize()
        assert await storage.health_check()

    async def test_initialize_seeds_default_scopes(self, initialized_storage: JsonStorageBackend) -> None:
        scopes = await initialized_storage.list_scopes()
        names = {s.name for s in scopes}
        assert "openid" in names
        assert "profile" in names
        assert "email" in names

    async def test_initialize_idempotent(self, storage: JsonStorageBackend) -> None:
        await storage.initialize()
        await storage.initialize()
        scopes = await storage.list_scopes()
        openid_count = sum(1 for s in scopes if s.name == "openid")
        assert openid_count == 1


class TestUserOperations:
    async def test_create_and_get_user(self, initialized_storage: JsonStorageBackend) -> None:
        user = User(email="alice@test.com", name="Alice")
        created = await initialized_storage.create_user(user)
        fetched = await initialized_storage.get_user(created.id)
        assert fetched is not None
        assert fetched.email == "alice@test.com"
        assert fetched.name == "Alice"

    async def test_get_user_by_email(self, initialized_storage: JsonStorageBackend) -> None:
        user = User(email="bob@test.com", name="Bob")
        await initialized_storage.create_user(user)
        fetched = await initialized_storage.get_user_by_email("BOB@test.com")
        assert fetched is not None
        assert fetched.email == "bob@test.com"

    async def test_get_user_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_user("nonexistent") is None

    async def test_get_user_by_email_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_user_by_email("nobody@test.com") is None

    async def test_update_user(self, initialized_storage: JsonStorageBackend) -> None:
        from dataclasses import replace

        user = User(email="carol@test.com", name="Carol")
        created = await initialized_storage.create_user(user)
        updated = replace(created, name="Carol Updated")
        result = await initialized_storage.update_user(updated)
        assert result.name == "Carol Updated"
        fetched = await initialized_storage.get_user(created.id)
        assert fetched is not None
        assert fetched.name == "Carol Updated"

    async def test_list_users(self, initialized_storage: JsonStorageBackend) -> None:
        for i in range(5):
            await initialized_storage.create_user(User(email=f"u{i}@test.com", name=f"User {i}"))
        users, total = await initialized_storage.list_users(page=1, page_size=3)
        assert len(users) == 3
        assert total == 5

    async def test_list_users_pagination(self, initialized_storage: JsonStorageBackend) -> None:
        for i in range(5):
            await initialized_storage.create_user(User(email=f"p{i}@test.com", name=f"User {i}"))
        users, total = await initialized_storage.list_users(page=2, page_size=3)
        assert len(users) == 2
        assert total == 5

    async def test_search_users(self, initialized_storage: JsonStorageBackend) -> None:
        await initialized_storage.create_user(User(email="searchme@test.com", name="SearchUser"))
        await initialized_storage.create_user(User(email="other@test.com", name="Other"))
        users, total = await initialized_storage.search_users("searchme")
        assert total == 1
        assert users[0].email == "searchme@test.com"


class TestSocialAccountOperations:
    async def test_create_and_get_social_account(self, initialized_storage: JsonStorageBackend) -> None:
        user = User(email="social@test.com", name="Social")
        user = await initialized_storage.create_user(user)
        account = SocialAccount(
            user_id=user.id,
            provider=SocialProvider.GOOGLE,
            provider_user_id="google-123",
            provider_email="social@test.com",
            provider_name="Social",
        )
        await initialized_storage.create_social_account(account)
        fetched = await initialized_storage.get_social_account("google", "google-123")
        assert fetched is not None
        assert fetched.provider == SocialProvider.GOOGLE

    async def test_get_social_accounts_for_user(self, initialized_storage: JsonStorageBackend) -> None:
        user = User(email="multi@test.com", name="Multi")
        user = await initialized_storage.create_user(user)
        for provider, pid in [("google", "g1"), ("github", "gh1")]:
            await initialized_storage.create_social_account(
                SocialAccount(
                    user_id=user.id,
                    provider=SocialProvider(provider),
                    provider_user_id=pid,
                    provider_email="multi@test.com",
                    provider_name="Multi",
                )
            )
        accounts = await initialized_storage.get_social_accounts_for_user(user.id)
        assert len(accounts) == 2

    async def test_get_social_account_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_social_account("google", "missing") is None


class TestClientOperations:
    async def test_create_and_get_client(self, initialized_storage: JsonStorageBackend) -> None:
        client = Client(
            name="TestClient",
            type=ClientType.CONFIDENTIAL,
            redirect_uris=("http://localhost/cb",),
            allowed_scopes=("openid",),
            grant_types=("authorization_code",),
        )
        created = await initialized_storage.create_client(client)
        fetched = await initialized_storage.get_client(created.id)
        assert fetched is not None
        assert fetched.name == "TestClient"

    async def test_get_client_by_name(self, initialized_storage: JsonStorageBackend) -> None:
        client = Client(
            name="ByName",
            type=ClientType.PUBLIC,
            redirect_uris=("http://localhost/cb",),
            allowed_scopes=("openid",),
            grant_types=("authorization_code",),
        )
        await initialized_storage.create_client(client)
        fetched = await initialized_storage.get_client_by_name("ByName")
        assert fetched is not None

    async def test_get_client_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_client("missing") is None

    async def test_update_client(self, initialized_storage: JsonStorageBackend) -> None:
        from dataclasses import replace

        client = Client(
            name="Updatable",
            type=ClientType.CONFIDENTIAL,
            redirect_uris=("http://localhost/cb",),
            allowed_scopes=("openid",),
            grant_types=("authorization_code",),
        )
        created = await initialized_storage.create_client(client)
        updated = replace(created, name="UpdatedClient")
        result = await initialized_storage.update_client(updated)
        assert result.name == "UpdatedClient"

    async def test_list_clients(self, initialized_storage: JsonStorageBackend) -> None:
        for i in range(3):
            await initialized_storage.create_client(
                Client(
                    name=f"Client{i}",
                    type=ClientType.PUBLIC,
                    redirect_uris=("http://localhost/cb",),
                    allowed_scopes=("openid",),
                    grant_types=("authorization_code",),
                )
            )
        _clients, total = await initialized_storage.list_clients()
        assert total == 3


class TestAuthCodeOperations:
    async def test_store_and_get_auth_code(self, initialized_storage: JsonStorageBackend) -> None:
        code = AuthorizationCode(
            code_hash="hash123",
            client_id="c1",
            user_id="u1",
            redirect_uri="http://localhost/cb",
            scope="openid",
            code_challenge="challenge",
            expires_at=utc_now() + timedelta(minutes=5),
        )
        await initialized_storage.store_auth_code(code)
        fetched = await initialized_storage.get_auth_code("hash123")
        assert fetched is not None
        assert fetched.client_id == "c1"

    async def test_mark_auth_code_used(self, initialized_storage: JsonStorageBackend) -> None:
        code = AuthorizationCode(
            code_hash="hash456",
            client_id="c1",
            user_id="u1",
            redirect_uri="http://localhost/cb",
            scope="openid",
            code_challenge="challenge",
            expires_at=utc_now() + timedelta(minutes=5),
        )
        await initialized_storage.store_auth_code(code)
        await initialized_storage.mark_auth_code_used("hash456")
        fetched = await initialized_storage.get_auth_code("hash456")
        assert fetched is not None
        assert fetched.used is True

    async def test_get_auth_code_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_auth_code("missing") is None


class TestRefreshTokenOperations:
    async def test_store_and_get_refresh_token(self, initialized_storage: JsonStorageBackend) -> None:
        rt = RefreshToken(
            token_hash="rt_hash",
            family_id="fam1",
            user_id="u1",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(days=30),
        )
        await initialized_storage.store_refresh_token(rt)
        fetched = await initialized_storage.get_refresh_token("rt_hash")
        assert fetched is not None
        assert fetched.family_id == "fam1"

    async def test_mark_refresh_token_used(self, initialized_storage: JsonStorageBackend) -> None:
        rt = RefreshToken(
            token_hash="rt_used",
            family_id="fam2",
            user_id="u1",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(days=30),
        )
        await initialized_storage.store_refresh_token(rt)
        await initialized_storage.mark_refresh_token_used("rt_used")
        fetched = await initialized_storage.get_refresh_token("rt_used")
        assert fetched is not None
        assert fetched.used is True

    async def test_revoke_refresh_token(self, initialized_storage: JsonStorageBackend) -> None:
        rt = RefreshToken(
            token_hash="rt_revoke",
            family_id="fam3",
            user_id="u1",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(days=30),
        )
        await initialized_storage.store_refresh_token(rt)
        await initialized_storage.revoke_refresh_token("rt_revoke")
        fetched = await initialized_storage.get_refresh_token("rt_revoke")
        assert fetched is not None
        assert fetched.revoked is True

    async def test_revoke_token_family(self, initialized_storage: JsonStorageBackend) -> None:
        for i in range(3):
            await initialized_storage.store_refresh_token(
                RefreshToken(
                    token_hash=f"fam_rt_{i}",
                    family_id="fam_shared",
                    user_id="u1",
                    client_id="c1",
                    scope="openid",
                    expires_at=utc_now() + timedelta(days=30),
                )
            )
        await initialized_storage.revoke_token_family("fam_shared")
        tokens = await initialized_storage.get_refresh_tokens_by_family("fam_shared")
        assert all(t.revoked for t in tokens)

    async def test_revoke_tokens_for_client(self, initialized_storage: JsonStorageBackend) -> None:
        await initialized_storage.store_refresh_token(
            RefreshToken(
                token_hash="client_rt",
                family_id="fam_c",
                user_id="u1",
                client_id="target_client",
                scope="openid",
                expires_at=utc_now() + timedelta(days=30),
            )
        )
        await initialized_storage.revoke_tokens_for_client("target_client")
        fetched = await initialized_storage.get_refresh_token("client_rt")
        assert fetched is not None
        assert fetched.revoked is True

    async def test_revoke_tokens_for_user_client(self, initialized_storage: JsonStorageBackend) -> None:
        await initialized_storage.store_refresh_token(
            RefreshToken(
                token_hash="uc_rt",
                family_id="fam_uc",
                user_id="user_x",
                client_id="client_x",
                scope="openid",
                expires_at=utc_now() + timedelta(days=30),
            )
        )
        await initialized_storage.revoke_tokens_for_user_client("user_x", "client_x")
        fetched = await initialized_storage.get_refresh_token("uc_rt")
        assert fetched is not None
        assert fetched.revoked is True


class TestRevocationOperations:
    async def test_store_and_check_revocation(self, initialized_storage: JsonStorageBackend) -> None:
        entry = TokenRevocationEntry(jti="jti-123")
        await initialized_storage.store_revocation(entry)
        assert await initialized_storage.is_token_revoked("jti-123")
        assert not await initialized_storage.is_token_revoked("jti-other")


class TestConsentOperations:
    async def test_create_and_get_consent(self, initialized_storage: JsonStorageBackend) -> None:
        consent = Consent(user_id="u1", client_id="c1", scopes=("openid", "profile"))
        created = await initialized_storage.create_consent(consent)
        fetched = await initialized_storage.get_consent(created.id)
        assert fetched is not None
        assert set(fetched.scopes) == {"openid", "profile"}

    async def test_get_active_consent(self, initialized_storage: JsonStorageBackend) -> None:
        consent = Consent(user_id="u2", client_id="c2", scopes=("openid",))
        await initialized_storage.create_consent(consent)
        active = await initialized_storage.get_active_consent("u2", "c2")
        assert active is not None

    async def test_get_active_consent_none(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_active_consent("nobody", "nothing") is None

    async def test_revoke_consent(self, initialized_storage: JsonStorageBackend) -> None:
        consent = Consent(user_id="u3", client_id="c3", scopes=("openid",))
        created = await initialized_storage.create_consent(consent)
        await initialized_storage.revoke_consent(created.id)
        active = await initialized_storage.get_active_consent("u3", "c3")
        assert active is None

    async def test_get_consents_for_user(self, initialized_storage: JsonStorageBackend) -> None:
        for i in range(3):
            await initialized_storage.create_consent(Consent(user_id="u4", client_id=f"c{i}", scopes=("openid",)))
        consents = await initialized_storage.get_consents_for_user("u4")
        assert len(consents) == 3


class TestDeviceCodeOperations:
    async def test_store_and_get_device_code(self, initialized_storage: JsonStorageBackend) -> None:
        dc = DeviceCode(
            device_code_hash="dc_hash",
            user_code="ABCD1234",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(minutes=15),
        )
        await initialized_storage.store_device_code(dc)
        fetched = await initialized_storage.get_device_code("dc_hash")
        assert fetched is not None
        assert fetched.user_code == "ABCD1234"

    async def test_get_device_code_by_user_code(self, initialized_storage: JsonStorageBackend) -> None:
        dc = DeviceCode(
            device_code_hash="dc_hash2",
            user_code="WXYZ5678",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(minutes=15),
        )
        await initialized_storage.store_device_code(dc)
        fetched = await initialized_storage.get_device_code_by_user_code("WXYZ5678")
        assert fetched is not None

    async def test_update_device_code(self, initialized_storage: JsonStorageBackend) -> None:
        from dataclasses import replace

        dc = DeviceCode(
            device_code_hash="dc_upd",
            user_code="UPDT1234",
            client_id="c1",
            scope="openid",
            expires_at=utc_now() + timedelta(minutes=15),
        )
        await initialized_storage.store_device_code(dc)
        updated = replace(dc, status="approved", user_id="u1")
        await initialized_storage.update_device_code(updated)
        fetched = await initialized_storage.get_device_code("dc_upd")
        assert fetched is not None
        assert fetched.status == "approved"


class TestScopeOperations:
    async def test_create_and_get_scope(self, initialized_storage: JsonStorageBackend) -> None:
        scope = Scope(name="custom:read", description="Custom read access")
        await initialized_storage.create_scope(scope)
        fetched = await initialized_storage.get_scope("custom:read")
        assert fetched is not None
        assert fetched.description == "Custom read access"

    async def test_delete_scope(self, initialized_storage: JsonStorageBackend) -> None:
        scope = Scope(name="deleteme", description="To delete")
        await initialized_storage.create_scope(scope)
        await initialized_storage.delete_scope("deleteme")
        assert await initialized_storage.get_scope("deleteme") is None

    async def test_list_scopes(self, initialized_storage: JsonStorageBackend) -> None:
        scopes = await initialized_storage.list_scopes()
        assert len(scopes) >= 3  # default scopes


class TestSAMLIdPOperations:
    async def test_create_and_get_saml_idp(self, initialized_storage: JsonStorageBackend) -> None:
        idp = SAMLIdPConfig(
            name="Test IdP",
            entity_id="https://idp.test.com",
            sso_url="https://idp.test.com/sso",
            certificate="CERT_DATA",
        )
        created = await initialized_storage.create_saml_idp(idp)
        fetched = await initialized_storage.get_saml_idp(created.id)
        assert fetched is not None
        assert fetched.entity_id == "https://idp.test.com"

    async def test_get_saml_idps(self, initialized_storage: JsonStorageBackend) -> None:
        idp = SAMLIdPConfig(
            name="Listed IdP",
            entity_id="https://idp2.test.com",
            sso_url="https://idp2.test.com/sso",
            certificate="CERT",
        )
        await initialized_storage.create_saml_idp(idp)
        idps = await initialized_storage.get_saml_idps()
        assert len(idps) >= 1

    async def test_get_saml_idp_not_found(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.get_saml_idp("missing") is None


class TestHealthCheck:
    async def test_health_check_after_init(self, initialized_storage: JsonStorageBackend) -> None:
        assert await initialized_storage.health_check()

    async def test_health_check_no_dir(self, tmp_path: Path) -> None:
        storage = JsonStorageBackend(tmp_path / "nonexistent")
        assert not await storage.health_check()
