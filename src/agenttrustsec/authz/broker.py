"""Credential broker — short-lived, scoped tokens instead of standing secrets.

TrustSec analogy: ISE pushing a per-session authorization profile / dACL. No agent or
MCP server holds a long-lived key for an external API. After the Gate ALLOWs a call,
the broker mints a token bound to (agent, tool, session, audience) that lives seconds
and is single-use, so a leaked token is useless for any other call (T10).

The broker also *seals* the user Session at intake. Once a session crosses a process
boundary (MCP, SLIM), an agent could otherwise just claim intent=change; a sealed
session cannot be upgraded by the agent carrying it (T11).

DEV ONLY: HMAC with a shared secret. Later swapped for AGNTCY-issued credentials /
an RFC 8693 token-exchange service behind the same methods.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from contextvars import ContextVar

from agenttrustsec.identity.badge import _b64, _unb64
from agenttrustsec.models import Intent, Session

# Token for the tool call currently executing; set by the MCP gate on ALLOW only.
CURRENT_TOKEN: ContextVar[str | None] = ContextVar("agenttrustsec_token", default=None)


class TokenError(Exception):
    """Any token problem. Callers must treat it as deny."""


class TokenBroker:
    def __init__(self, secret: bytes, issuer: str = "agenttrustsec-broker",
                 token_ttl_s: int = 60):
        if len(secret) < 32:
            raise ValueError("broker secret must be at least 32 bytes")
        self._secret = secret
        self.issuer = issuer
        self.token_ttl_s = token_ttl_s
        self._redeemed: set[str] = set()
        self._lock = threading.Lock()

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
        with self._lock:
            if c["jti"] in self._redeemed:
                raise TokenError("token already used (replay)")
            self._redeemed.add(c["jti"])
        return c
