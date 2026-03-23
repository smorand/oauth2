"""RSA key management for JWT signing."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


class KeyManager:
    """Manages RSA key pairs for JWT signing with key rotation support."""

    __slots__ = ("_current_kid", "_keys")

    def __init__(self) -> None:
        self._keys: dict[str, rsa.RSAPrivateKey] = {}
        self._current_kid: str = ""

    @property
    def current_kid(self) -> str:
        """Return the current active key ID."""
        return self._current_kid

    def load_from_files(self, private_path: Path, kid: str = "key-1") -> None:
        """Load an RSA private key from a PEM file."""
        key_data = private_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            msg = "Key must be RSA"
            raise TypeError(msg)
        self._keys[kid] = private_key
        self._current_kid = kid
        logger.info("Loaded RSA key with kid=%s", kid)

    def generate_key(self, kid: str = "key-1", key_size: int = 2048) -> None:
        """Generate a new RSA key pair in memory."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self._keys[kid] = private_key
        self._current_kid = kid
        logger.info("Generated RSA key with kid=%s, size=%d", kid, key_size)

    def get_private_key(self, kid: str | None = None) -> rsa.RSAPrivateKey:
        """Get a private key by kid, or the current key."""
        target_kid = kid or self._current_kid
        if target_kid not in self._keys:
            msg = f"Key not found: {target_kid}"
            raise KeyError(msg)
        return self._keys[target_kid]

    def get_jwks(self) -> dict[str, list[dict[str, str]]]:
        """Export all public keys as a JWKS document."""
        keys: list[dict[str, str]] = []
        for kid, private_key in self._keys.items():
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
            e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": _base64url_encode(n_bytes),
                    "e": _base64url_encode(e_bytes),
                }
            )
        return {"keys": keys}

    def rotate_to(self, new_kid: str, key_size: int = 2048) -> None:
        """Generate a new key and set it as current, keeping old keys."""
        self.generate_key(kid=new_kid, key_size=key_size)


def generate_rsa_key_pair(private_path: Path, public_path: Path, key_size: int = 2048) -> None:
    """Generate an RSA key pair and save to PEM files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_path.write_bytes(private_pem)

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_bytes(public_pem)
    logger.info("RSA key pair written to %s and %s", private_path, public_path)


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
