"""PKCE (Proof Key for Code Exchange) utilities."""

from __future__ import annotations

import base64
import hashlib


def verify_code_challenge(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Verify a PKCE code_verifier against code_challenge.

    Only S256 is supported per OAuth 2.1.
    """
    if method != "S256":
        return False

    computed = compute_code_challenge(code_verifier)
    return computed == code_challenge


def compute_code_challenge(code_verifier: str) -> str:
    """Compute S256 code_challenge from code_verifier.

    BASE64URL(SHA256(code_verifier))
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
