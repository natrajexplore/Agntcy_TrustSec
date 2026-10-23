"""Credential broker — short-lived, scoped tokens instead of standing secrets.

TrustSec analogy: ISE pushing a per-session authorization profile / dACL. No agent or
MCP server holds a long-lived key for an external API. After the Gate ALLOWs a call,
the broker mints a token bound to (agent, tool, session, audience) that lives seconds
and is single-use, so a leaked token is useless for any other call (T10).

The broker also *seals* the user Session at intake. Once a session crosses a process
boundary (MCP, SLIM), an agent could otherwise just claim intent=change; a sealed
session cannot be upgraded by the agent carrying it (T11).

Spent token ids live in a `JtiStore` (authz/replay.py): memory by default, SQLite for the
gateway so single use survives a restart (item B).

DEV ONLY: HMAC with a shared secret. Later swapped for AGNTCY-issued credentials /
an RFC 8693 token-exchange service behind the same methods.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from contextvars import ContextVar

from agenttrustsec.identity.badge import _b64, _unb64
from agenttrustsec.authz.replay import JtiStore, MemoryJtiStore
from agenttrustsec.models import Intent, Session

# Token for the tool call currently executing; set by the MCP gate on ALLOW only.
CURRENT_TOKEN: ContextVar[str | None] = ContextVar("agenttrustsec_token", default=None)


class TokenError(Exception):
    """Any token problem. Callers must treat it as deny."""


class TokenBroker:
    def __init__(self, secret: bytes, issuer: str = "agenttrustsec-broker",
                 token_ttl_s: int = 60, jti_store: JtiStore | None = None):
        if len(secret) < 32:
            raise ValueError("broker secret must be at least 32 bytes")
        self._secret = secret
        self.issuer = issuer
        self.token_ttl_s = token_ttl_s
        self._used = jti_store if jti_store is not None else MemoryJtiStore()

    # --- signing primitives ------------------------------------------------
    def _sign(self, claims: dict) -> str:
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def _open(self, token: str | None, typ: str) -> dict:
        if not token or not isinstance(token, str):
            raise TokenError(f"no {typ} token presented")
        try:
            body, sig = token.split(".")
        except ValueError:
            raise TokenError(f"malformed {typ} token") from None
        expected = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise TokenError(f"{typ} token signature invalid")
        try:
            claims = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            raise TokenError(f"{typ} token payload unreadable") from None
        if claims.get("iss") != self.issuer:
            raise TokenError(f"{typ} token from untrusted issuer")
        if claims.get("typ") != typ:
            raise TokenError(f"expected {typ} token, got {claims.get('typ')!r}")
        if int(claims.get("exp", 0)) <= int(time.time()):
            raise TokenError(f"{typ} token expired")
        return claims

    def _claim(self, claims: dict, what: str) -> None:
        """Single use: the store decides atomically; a store error is a TokenError (BLOCK)."""
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise TokenError(f"{what} has no jti")
        if not self._used.claim(jti, int(claims["exp"])):
            raise TokenError(f"{what} already used (replay)")

    # --- sessions (sealed at intake) ----------------------------------------
    def seal_session(self, session: Session, ttl_s: int = 3600) -> str:
        now = int(time.time())
        return self._sign({
            "iss": self.issuer, "typ": "session", "iat": now, "exp": now + ttl_s,
            "sid": session.session_id, "intent": session.intent.value,
            "prompt": session.user_prompt,
        })

    def open_session(self, token: str | None) -> Session:
        c = self._open(token, "session")
        try:
            return Session(user_prompt=c["prompt"], intent=Intent(c["intent"]),
                           session_id=c["sid"])
        except (KeyError, ValueError):
            raise TokenError("session token missing fields") from None

    # --- scoped access tokens for external data -----------------------------
    def mint(self, agent_id: str, tool: str, session_id: str, audience: str) -> str:
        now = int(time.time())
        return self._sign({
            "iss": self.issuer, "typ": "access", "iat": now, "exp": now + self.token_ttl_s,
            "sub": agent_id, "tool": tool, "sid": session_id, "aud": audience,
            "jti": secrets.token_hex(8),
        })

    def redeem(self, token: str | None, audience: str, tool: str) -> dict:
        """Called by the external resource. Single use: a second redeem fails."""
        c = self._open(token, "access")
        if c.get("aud") != audience:
            raise TokenError(f"token audience {c.get('aud')!r} != {audience!r}")
        if c.get("tool") != tool:
            raise TokenError(f"token scoped to tool {c.get('tool')!r}, not {tool!r}")
        self._claim(c, "token")
        return c

    # --- change approvals (P5d, E3) ------------------------------------------
    def mint_approval(self, change_id: str, device: str, lines: list[str], session_id: str,
                      approvers: list[str], ttl_s: int = 900) -> str:
        """Issued by intake only after the reviewer pool approved THIS change. Bound to the
        change, the device, the exact lines and the change session; single use."""
        now = int(time.time())
        return self._sign({
            "iss": self.issuer, "typ": "approval", "iat": now, "exp": now + ttl_s,
            "change_id": change_id, "device": device, "lines": lines_digest(lines),
            "sid": session_id, "approvers": sorted(approvers), "jti": secrets.token_hex(8),
        })

    def redeem_approval(self, token: str | None, device: str, lines: list[str] | None,
                        session_id: str) -> dict:
        """Called by the gate for tools with requires_approval. Any mismatch -> TokenError."""
        c = self._open(token, "approval")
        if c.get("device") != device:
            raise TokenError(f"approval is for device {c.get('device')!r}, not {device!r}")
        if not isinstance(lines, list) or c.get("lines") != lines_digest(lines):
            raise TokenError("lines differ from the approved change")
        if c.get("sid") != session_id:
            raise TokenError("approval belongs to a different session")
        self._claim(c, "approval")
        return c


def lines_digest(lines: list[str]) -> str:
    """SHA-256 over the exact ordered config lines (what the reviewers approved)."""
    return hashlib.sha256(json.dumps(list(lines), separators=(",", ":")).encode()).hexdigest()
