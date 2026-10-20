"""MCP enforcement point — the Gate as MCP server middleware (CASA-sidecar style).

TrustSec analogy: the switchport. Every `tools/call` is authorized by the same Gate
(badge -> TBAC -> intent -> audit) before the tool runs, and only the methods listed
in _PASSTHROUGH are served at all (deny by default). Each tools/call result is stamped
with this server's own badge so the agent can verify it reached the real server (T9).

Wire contract — request `_meta`:
    agenttrustsec/agent_id     who the caller claims to be
    agenttrustsec/badge        the caller's badge
    agenttrustsec/session      intake-sealed session token (intent can't be self-upgraded)
Result `_meta`:
    agenttrustsec/server_badge this server's badge
    agenttrustsec/decision     verdict + blocked_by (on BLOCK)

Verified against the `mcp` 2.x SDK (MCPServer + ServerMiddleware).
"""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolResult, TextContent
from mcp_types.jsonrpc import METHOD_NOT_FOUND
from pydantic import BaseModel

from agenttrustsec.authz.broker import CURRENT_TOKEN, TokenBroker, TokenError
from agenttrustsec.authz.gate import Gate
from agenttrustsec.models import (
    CheckResult, Decision, Intent, Session, Status, ToolCall, Verdict,
)

META_AGENT = "agenttrustsec/agent_id"
META_BADGE = "agenttrustsec/badge"
META_SESSION = "agenttrustsec/session"
META_SERVER_BADGE = "agenttrustsec/server_badge"
META_DECISION = "agenttrustsec/decision"

# Everything else (resources/*, prompts/*, completion/*, ...) is refused.
_PASSTHROUGH = {"initialize", "server/discover", "ping", "tools/list"}

_UNVERIFIED = Session(user_prompt="<unverified>", intent=Intent.READ,
                      session_id="unverified")


class GateMiddleware:
    def __init__(self, gate: Gate, broker: TokenBroker, server_badge: str):
        self.gate = gate
        self.broker = broker
        self.server_badge = server_badge

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        if ctx.request_id is None:          # notifications carry no tool access
            return await call_next(ctx)
        if ctx.method in _PASSTHROUGH:
            return await call_next(ctx)
        if ctx.method != "tools/call":
            raise MCPError(METHOD_NOT_FOUND, f"{ctx.method!r} not served (deny by default)")
        return self._stamp(await self._tools_call(ctx, call_next))

    async def _tools_call(self, ctx: Any, call_next: Any) -> Any:
        meta = ctx.meta or {}
        params = ctx.params or {}
        agent_id = str(meta.get(META_AGENT) or "<anonymous>")
        badge = meta.get(META_BADGE) if isinstance(meta.get(META_BADGE), str) else None
        tool = str(params.get("name") or "<none>")
        args = params.get("arguments") or {}

        try:
            session = self.broker.open_session(meta.get(META_SESSION))
        except Exception as e:  # noqa: BLE001 - any session problem is a BLOCK
            status = Status.FAIL if isinstance(e, TokenError) else Status.ERROR
            decision = Decision(
                call=ToolCall(agent_id, badge, tool, _UNVERIFIED, args),
                checks=(CheckResult("session", status, str(e)),
                        CheckResult("badge", Status.SKIPPED, "session not verified"),
                        CheckResult("tbac", Status.SKIPPED, "session not verified"),
                        CheckResult("intent", Status.SKIPPED, "session not verified")),
                verdict=Verdict.BLOCK,
                verified_role=None,
            )
            self.gate.audit.write(decision)
            return _blocked(decision)

        decision = self.gate.authorize(ToolCall(agent_id, badge, tool, session, args))
        if decision.verdict is not Verdict.ALLOW:
            return _blocked(decision)

        spec = self.gate.policy.spec(tool)
        token = None
        if spec is not None and spec.audience:
            token = self.broker.mint(agent_id, tool, session.session_id, spec.audience)
        reset = CURRENT_TOKEN.set(token)
        try:
            return await call_next(ctx)
        finally:
            CURRENT_TOKEN.reset(reset)

    def _stamp(self, result: Any) -> Any:
        if isinstance(result, dict):
            result["_meta"] = {**(result.get("_meta") or {}),
                               META_SERVER_BADGE: self.server_badge}
            return result
        if isinstance(result, BaseModel):
            meta = {**(getattr(result, "meta", None) or {}),
                    META_SERVER_BADGE: self.server_badge}
            return result.model_copy(update={"meta": meta})
        return result


def _blocked(d: Decision) -> CallToolResult:
    by = d.blocked_by or "gate"
    bad = next((c for c in d.checks if c.name == d.blocked_by), None)
    reason = bad.reason if bad else "not every check passed"
    return CallToolResult(
        content=[TextContent(type="text", text=f"BLOCKED by {by}: {reason}")],
        is_error=True,
        _meta={META_DECISION: {"verdict": d.verdict.value, "blocked_by": by,
                               "reason": reason}},
    )


def build_server(name: str, gate: Gate, broker: TokenBroker, server_badge: str,
                 registry: dict[str, Callable[..., Any]]) -> MCPServer:
    server = MCPServer(name, middleware=[GateMiddleware(gate, broker, server_badge)])
    for tool_name, fn in registry.items():
        spec = gate.policy.spec(tool_name)
        server.add_tool(fn, name=tool_name, description=spec.description if spec else None)
    return server
