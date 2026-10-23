"""Agent-side MCP wrapper: present credentials, and verify the server before trusting it.

TrustSec analogy: mutual authentication. The endpoint proves itself to the switch
(badge + sealed session in `_meta`), and the switch proves itself back (server badge
on every result). A result from a server that can't prove its identity is discarded
before the agent reads it (T9).

Over SLIM (P3) pass `transport_peer` + `peer_binding`: the gateway must then also prove
it holds the key bound to its badge (D2 table), so a copied server badge is useless.
In-process / dev use without them keeps the bearer-badge limitation (no possession proof).
"""
from __future__ import annotations

from typing import Any

from collections.abc import Callable

from mcp import Client
from mcp_types import CallToolResult

from agenttrustsec.authz.peer import PeerBinding
from agenttrustsec.identity.badge import BadgeError, BadgeVerifier
from agenttrustsec.models import TransportPeer
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
                 session_token: str, verifier: BadgeVerifier, server_id: str,
                 transport_peer: Callable[[], TransportPeer | None] | None = None,
                 peer_binding: PeerBinding | None = None, server_role: str = SERVER_ROLE):
        if (transport_peer is None) != (peer_binding is None):
            raise ValueError("pass both transport_peer and peer_binding, or neither")
        self.server_role = server_role      # P5c: agents are servers too (e.g. role "reader")
        self.transport_peer = transport_peer
        self.peer_binding = peer_binding
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
        if ident.role != self.server_role:
            raise ServerAuthError(
                f"{self.server_id!r} badge has role {ident.role!r}, not {self.server_role!r}")
        if self.peer_binding is not None:
            try:
                r = self.peer_binding.check(self.transport_peer(), ident)
            except Exception as e:  # noqa: BLE001 - any doubt about the server -> distrust
                raise ServerAuthError(f"MCP server {self.server_id!r} peer check error: {e}") from None
            if not r.passed:
                raise ServerAuthError(f"MCP server {self.server_id!r} not trusted: {r.reason}")


def _text(result: CallToolResult) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)
