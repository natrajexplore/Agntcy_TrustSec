"""Agent-side MCP wrapper: present credentials, and verify the server before trusting it.

TrustSec analogy: mutual authentication. The endpoint proves itself to the switch
(badge + sealed session in `_meta`), and the switch proves itself back (server badge
on every result). A result from a server that can't prove its identity is discarded
before the agent reads it (T9).

LIMITATION (dev badges): the server badge is a bearer credential, so an impostor that
copied a real server's badge could replay it. P2 fixes this with AGNTCY key-bound
badges (proof of possession over a client nonce).
"""
from __future__ import annotations

from typing import Any

from mcp import Client
from mcp_types import CallToolResult

from agenttrustsec.identity.badge import BadgeError, BadgeVerifier
from agenttrustsec.mcpgate.server import (
    META_AGENT, META_BADGE, META_DECISION, META_SERVER_BADGE, META_SESSION,
)

SERVER_ROLE = "mcp_server"


class ServerAuthError(Exception):
    """The MCP server could not prove its identity. Never use its result."""


class McpBlocked(PermissionError):
    def __init__(self, blocked_by: str, reason: str):
        self.blocked_by = blocked_by
        self.reason = reason
        super().__init__(f"BLOCKED by {blocked_by}: {reason}")


class TrustedClient:
    def __init__(self, client: Client, *, agent_id: str, badge: str | None,
                 session_token: str, verifier: BadgeVerifier, server_id: str):
        self.client = client
        self.agent_id = agent_id
        self.badge = badge
        self.session_token = session_token
        self.verifier = verifier
        self.server_id = server_id

    async def call(self, tool: str, args: dict[str, Any] | None = None) -> CallToolResult:
        meta = {META_AGENT: self.agent_id, META_SESSION: self.session_token}
        if self.badge is not None:
            meta[META_BADGE] = self.badge
        result = await self.client.call_tool(tool, args or {}, meta=meta)
        self._verify_server(result)
        if result.is_error:
            d = (result.meta or {}).get(META_DECISION)
            if d:
                raise McpBlocked(d["blocked_by"], d["reason"])
            raise RuntimeError(_text(result))
        return result

    def _verify_server(self, result: CallToolResult) -> None:
        badge = (result.meta or {}).get(META_SERVER_BADGE)
        try:
            ident = self.verifier.verify(badge, self.server_id)
        except BadgeError as e:
            raise ServerAuthError(f"MCP server {self.server_id!r} not trusted: {e}") from None
        if ident.role != SERVER_ROLE:
            raise ServerAuthError(
                f"{self.server_id!r} badge has role {ident.role!r}, not {SERVER_ROLE!r}")


def _text(result: CallToolResult) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)
