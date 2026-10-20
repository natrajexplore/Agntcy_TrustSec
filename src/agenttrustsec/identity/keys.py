"""Agent signing keys — the public key a badge binds (P3, docs/P3-design.md §2).

TrustSec analogy: the key pair behind an EAP-TLS machine certificate. The issuer signs
the key's RFC 7638 thumbprint into the AgentBadge (OASF annotation below); over SLIM the
peer proves possession by signing its identity token with the private key.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

THUMBPRINT_ANNOTATION = "agenttrustsec.key_thumbprint"


def _b64u_int(i: int) -> str:
    return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")


def public_jwk(public_key: Any) -> dict[str, str]:
    """RSA public key (cryptography) -> minimal JWK."""
    n = public_key.public_numbers()
    return {"kty": "RSA", "n": _b64u_int(n.n), "e": _b64u_int(n.e)}


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of an RSA JWK (required members only, sorted)."""
    if jwk.get("kty") != "RSA" or not jwk.get("n") or not jwk.get("e"):
        raise ValueError("only RSA JWKs with n and e are supported")
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
                           separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")
