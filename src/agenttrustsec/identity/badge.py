"""Agent identity verification.

TrustSec analogy: this is 802.1X + certificate validation. The *role* (SGT) comes only
from the verified credential, never from what the caller claims.

LocalDevVerifier is a stand-in for P0/P1: HMAC-signed compact tokens using only the
stdlib. In P2 it is replaced by an AgntcyBadgeVerifier that verifies JOSE-enveloped
Agent Badges via the AGNTCY Identity SDK — same interface, so the Gate doesn't change.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol


class BadgeError(Exception):
    """Raised for any badge problem. The Gate turns this into FAIL -> BLOCK."""


@dataclass(frozen=True)
class VerifiedIdentity:
    agent_id: str
    role: str
    badge_id: str
    key_thumbprint: str | None = None   # RFC 7638; the key the badge binds (P3)
    tools: Any = None                   # item C: the tool list an MCP server badge signs (raw)


class BadgeVerifier(Protocol):
    def verify(self, badge: str | None, claimed_agent_id: str) -> VerifiedIdentity:
        """Return the verified identity or raise BadgeError. Never return a partial."""
        ...


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class LocalDevVerifier:
    """DEV ONLY. Shared-secret HMAC badges. Not a substitute for AGNTCY badges."""

    def __init__(self, secret: bytes, issuer: str = "agenttrustsec-dev"):
        if len(secret) < 32:
            raise ValueError("dev secret must be at least 32 bytes")
        self._secret = secret
        self.issuer = issuer
        self._revoked: set[str] = set()

    # --- issuance (would be the Identity Service in P2) -------------------
    def issue(self, agent_id: str, role: str, ttl_s: int = 3600,
              badge_id: str | None = None, tools: list | None = None) -> str:
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "sub": agent_id,
            "role": role,
            "iat": now,
            "exp": now + ttl_s,
            "jti": badge_id or hashlib.sha256(f"{agent_id}{now}".encode()).hexdigest()[:16],
        }
        if tools is not None:
            payload["tools"] = tools
        body = _b64(json.dumps(payload, sort_keys=True).encode())
        sig = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def revoke(self, badge_id: str) -> None:
        self._revoked.add(badge_id)

    # --- verification ------------------------------------------------------
    def verify(self, badge: str | None, claimed_agent_id: str) -> VerifiedIdentity:
        if not badge:
            raise BadgeError("no badge presented")
        try:
            body, sig = badge.split(".")
        except ValueError:
            raise BadgeError("malformed badge") from None

        expected = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise BadgeError("signature invalid")

        try:
            claims = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            raise BadgeError("badge payload unreadable") from None

        if claims.get("iss") != self.issuer:
            raise BadgeError("untrusted issuer")
        if int(claims.get("exp", 0)) <= int(time.time()):
            raise BadgeError("badge expired")
        if claims.get("jti") in self._revoked:
            raise BadgeError("badge revoked")
        if claims.get("sub") != claimed_agent_id:
            raise BadgeError(
                f"subject mismatch: badge is for {claims.get('sub')!r}, "
                f"caller claims {claimed_agent_id!r}"
            )
        role = claims.get("role")
        if not role:
            raise BadgeError("badge has no role")
        return VerifiedIdentity(agent_id=claims["sub"], role=role, badge_id=claims["jti"],
                                tools=claims.get("tools"))
