"""Tests for crypto module: keys, JWT, password, PKCE."""

from __future__ import annotations

from pathlib import Path

import jwt as pyjwt
import pytest

from crypto.jwt_handler import JWTHandler
from crypto.keys import KeyManager, generate_rsa_key_pair
from crypto.password import (
    generate_auth_code,
    generate_client_secret,
    generate_device_user_code,
    generate_opaque_token,
    hash_client_secret,
    hash_password,
    hash_token,
    verify_client_secret,
    verify_password,
)
from crypto.pkce import compute_code_challenge, verify_code_challenge

# ── KeyManager ──


class TestKeyManager:
    def test_generate_key(self) -> None:
        km = KeyManager()
        km.generate_key(kid="k1")
        assert km.current_kid == "k1"

    def test_get_private_key(self, key_manager: KeyManager) -> None:
        key = key_manager.get_private_key()
        assert key is not None

    def test_get_private_key_by_kid(self, key_manager: KeyManager) -> None:
        key = key_manager.get_private_key("test-key-1")
        assert key is not None

    def test_get_private_key_missing(self, key_manager: KeyManager) -> None:
        with pytest.raises(KeyError, match="Key not found"):
            key_manager.get_private_key("nonexistent")

    def test_get_jwks(self, key_manager: KeyManager) -> None:
        jwks = key_manager.get_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        k = jwks["keys"][0]
        assert k["kty"] == "RSA"
        assert k["use"] == "sig"
        assert k["alg"] == "RS256"
        assert k["kid"] == "test-key-1"
        assert "n" in k
        assert "e" in k

    def test_rotate_to(self, key_manager: KeyManager) -> None:
        key_manager.rotate_to("k2")
        assert key_manager.current_kid == "k2"
        jwks = key_manager.get_jwks()
        assert len(jwks["keys"]) == 2

    def test_load_from_files(self, tmp_path: Path) -> None:
        priv = tmp_path / "priv.pem"
        pub = tmp_path / "pub.pem"
        generate_rsa_key_pair(priv, pub)
        km = KeyManager()
        km.load_from_files(priv, kid="file-key")
        assert km.current_kid == "file-key"
        assert km.get_private_key("file-key") is not None


class TestGenerateRsaKeyPair:
    def test_files_created(self, tmp_path: Path) -> None:
        priv = tmp_path / "private.pem"
        pub = tmp_path / "public.pem"
        generate_rsa_key_pair(priv, pub)
        assert priv.exists()
        assert pub.exists()
        assert b"PRIVATE KEY" in priv.read_bytes()
        assert b"PUBLIC KEY" in pub.read_bytes()


# ── JWTHandler ──


class TestJWTHandler:
    def test_create_and_decode_access_token(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token(sub="user-1", scope="openid profile", audience="client-1")
        claims = jwt_handler.decode_token(token, audience="client-1")
        assert claims["sub"] == "user-1"
        assert claims["scope"] == "openid profile"
        assert claims["iss"] == "http://localhost:8000"
        assert "jti" in claims

    def test_create_access_token_with_extra_claims(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token(sub="user-1", scope="openid", extra_claims={"custom": "value"})
        claims = jwt_handler.decode_token(token)
        assert claims["custom"] == "value"

    def test_create_id_token(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_id_token(sub="user-1", audience="client-1", nonce="abc123")
        claims = jwt_handler.decode_token(token, audience="client-1")
        assert claims["sub"] == "user-1"
        assert claims["nonce"] == "abc123"
        assert "auth_time" in claims

    def test_create_id_token_without_nonce(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_id_token(sub="user-1", audience="client-1")
        claims = jwt_handler.decode_token(token, audience="client-1")
        assert "nonce" not in claims

    def test_create_id_token_with_extra_claims(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_id_token(sub="user-1", audience="client-1", extra_claims={"email": "a@b.com"})
        claims = jwt_handler.decode_token(token, audience="client-1")
        assert claims["email"] == "a@b.com"

    def test_decode_token_wrong_audience(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token(sub="user-1", scope="openid", audience="client-1")
        with pytest.raises(pyjwt.InvalidTokenError):
            jwt_handler.decode_token(token, audience="wrong-client")

    def test_decode_token_malformed(self, jwt_handler: JWTHandler) -> None:
        with pytest.raises(pyjwt.InvalidTokenError, match="Malformed"):
            jwt_handler.decode_token("not.a.valid.token.here")

    def test_decode_token_wrong_algorithm(self, jwt_handler: JWTHandler, key_manager: KeyManager) -> None:
        # Create a token with HS256 (wrong algorithm)
        token = pyjwt.encode({"sub": "x"}, "secret", algorithm="HS256")
        with pytest.raises(pyjwt.InvalidTokenError, match="Unsupported algorithm"):
            jwt_handler.decode_token(token)

    def test_decode_token_unknown_kid(self, jwt_handler: JWTHandler, key_manager: KeyManager) -> None:
        private_key = key_manager.get_private_key()
        token = pyjwt.encode(
            {"sub": "x", "iss": "http://localhost:8000"},
            private_key,
            algorithm="RS256",
            headers={"kid": "unknown-kid"},
        )
        with pytest.raises(pyjwt.InvalidTokenError, match="Unknown kid"):
            jwt_handler.decode_token(token)

    def test_extract_jti(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token(sub="user-1", scope="openid")
        jti = jwt_handler.extract_jti(token)
        assert len(jti) > 0

    def test_extract_jti_malformed(self, jwt_handler: JWTHandler) -> None:
        assert jwt_handler.extract_jti("garbage") == ""

    def test_decode_without_audience_verification(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token(sub="user-1", scope="openid", audience="any")
        claims = jwt_handler.decode_token(token)
        assert claims["sub"] == "user-1"


# ── Password / Client Secret / Token Hashing ──


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        h = hash_password("MyPass123")
        assert verify_password("MyPass123", h)

    def test_verify_wrong_password(self) -> None:
        h = hash_password("MyPass123")
        assert not verify_password("WrongPass", h)

    def test_verify_invalid_hash(self) -> None:
        import argon2.exceptions

        with pytest.raises(argon2.exceptions.InvalidHashError):
            verify_password("anything", "not-a-valid-hash")


class TestClientSecretHashing:
    def test_hash_and_verify(self) -> None:
        secret = generate_client_secret()
        h = hash_client_secret(secret)
        assert verify_client_secret(secret, h)

    def test_verify_wrong_secret(self) -> None:
        h = hash_client_secret("correct-secret")
        assert not verify_client_secret("wrong-secret", h)

    def test_verify_invalid_hash(self) -> None:
        assert not verify_client_secret("anything", "invalid")


class TestTokenHashing:
    def test_hash_token_deterministic(self) -> None:
        assert hash_token("abc") == hash_token("abc")

    def test_hash_token_different_inputs(self) -> None:
        assert hash_token("abc") != hash_token("def")


class TestTokenGeneration:
    def test_generate_client_secret_length(self) -> None:
        s = generate_client_secret()
        assert len(s) > 20

    def test_generate_opaque_token_unique(self) -> None:
        t1 = generate_opaque_token()
        t2 = generate_opaque_token()
        assert t1 != t2

    def test_generate_auth_code_length(self) -> None:
        code = generate_auth_code()
        assert len(code) > 10

    def test_generate_device_user_code_format(self) -> None:
        code = generate_device_user_code()
        assert len(code) == 8
        # Should only contain allowed chars
        allowed = set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        assert all(c in allowed for c in code)


# ── PKCE ──


class TestPKCE:
    def test_compute_and_verify(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        assert verify_code_challenge(verifier, challenge, "S256")

    def test_verify_wrong_verifier(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        assert not verify_code_challenge("wrong-verifier", challenge, "S256")

    def test_verify_unsupported_method(self) -> None:
        assert not verify_code_challenge("verifier", "challenge", "plain")

    def test_compute_code_challenge_known_value(self) -> None:
        # RFC 7636 example
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = compute_code_challenge(verifier)
        assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
