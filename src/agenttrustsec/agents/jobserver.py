"""Authenticated job server for agents (P5c): agent-to-agent calls are MCP over SLIM too.

TrustSec analogy: an SGACL between agents — only the intake SGT may send work to a worker.
A worker acts under ITS OWN badge, so accepting a job from anyone would be a confused deputy:
a rogue could make reader-01 read what the rogue itself may not. Every `tools/call` must pass:

  badge   the caller's AGNTCY badge verifies (node signature, published + not revoked)
  peer    the caller's SLIM token is signed by the key that badge binds (authz/peer.py)
  caller  the verified role may dispatch to this worker (e.g. only `intake`)

Each dispatch is one audit record (the forwarded session token is never logged). The worker
stamps its own badge on every result so the caller verifies the worker (mutual auth). Only
initialize / ping / tools/list / tools/call are served (deny by default).
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import METHOD_NOT_FOUND

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.peer import PeerBinding
from agenttrustsec.identity.badge import BadgeError, BadgeVerifier
from agenttrustsec.mcpgate.server import META_AGENT, META_BADGE, META_SERVER_BADGE, _blocked
from agenttrustsec.models import CheckResult, Decision, Intent, Session, Status, ToolCall, Verdict
from agenttrustsec.transport.peer import CURRENT_PEER

_PASSTHROUGH = {"initialize", "server/discover", "ping", "tools/list"}
SECRET_ARGS = {"session", "approval"}   # forwarded credentials: never written to the audit log


def authorize_caller(worker: str, verifier: BadgeVerifier, binding: PeerBinding,
                     allowed_roles: frozenset[str], claimed: str, badge: str | None,
                     peer: Any, tool: str, args: dict) -> Decision:
    checks: list[CheckResult] = []
    ident = None
    try:
        ident = verifier.verify(badge, claimed)
        checks.append(CheckResult("badge", Status.PASS, f"verified {ident.agent_id} as {ident.role!r}"))
    except BadgeError as e:
        checks.append(CheckResult("badge", Status.FAIL, str(e)))
    except Exception as e:  # noqa: BLE001 - deny on any unexpected error
        checks.append(CheckResult("badge", Status.ERROR, f"{type(e).__name__}: {e}"))
    if ident is None:
        checks.append(CheckResult("peer", Status.SKIPPED, "no verified badge"))
    else:
        try:
            checks.append(binding.check(peer, ident))
        except Exception as e:  # noqa: BLE001
            checks.append(CheckResult("peer", Status.ERROR, f"{type(e).__name__}: {e}"))
    if not all(c.passed for c in checks):
        checks.append(CheckResult("caller", Status.SKIPPED, "earlier check failed"))
    elif ident.role in allowed_roles:
        checks.append(CheckResult("caller", Status.PASS, f"{ident.role!r} may dispatch to {worker}"))
    else:
        checks.append(CheckResult("caller", Status.FAIL,
                                  f"role {ident.role!r} may not dispatch to {worker} "
                                  f"(allowed: {sorted(allowed_roles)})"))
    ok = len(checks) == 3 and all(c.passed for c in checks)
    safe_args = {k: v for k, v in args.items() if k not in SECRET_ARGS}
    return Decision(
        call=ToolCall(claimed, badge, f"dispatch.{tool}", Session(f"dispatch to {worker}", Intent.READ,
                      session_id="dispatch"), safe_args, peer=peer),
        checks=tuple(checks), verdict=Verdict.ALLOW if ok else Verdict.BLOCK,
        verified_role=ident.role if ok else None)


class CallerGateMiddleware:
    def __init__(self, worker: str, own_badge: str, verifier: BadgeVerifier, binding: PeerBinding,
                 allowed_roles: frozenset[str], audit: AuditLog):
        self.worker, self.own_badge = worker, own_badge
        self.verifier, self.binding = verifier, binding
        self.allowed_roles, self.audit = frozenset(allowed_roles), audit

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        if ctx.request_id is None or ctx.method in _PASSTHROUGH:
            return await call_next(ctx)
        if ctx.method != "tools/call":
            raise MCPError(METHOD_NOT_FOUND, f"{ctx.method!r} not served (deny by default)")
        meta, params = ctx.meta or {}, ctx.params or {}
        badge = meta.get(META_BADGE) if isinstance(meta.get(META_BADGE), str) else None
        decision = authorize_caller(self.worker, self.verifier, self.binding, self.allowed_roles,
                                    str(meta.get(META_AGENT) or "<anonymous>"), badge, CURRENT_PEER.get(),
                                    str(params.get("name") or "<none>"), params.get("arguments") or {})
        self.audit.write(decision)
        result = _blocked(decision) if decision.verdict is not Verdict.ALLOW else await call_next(ctx)
        return self._stamp(result)

    def _stamp(self, result: Any) -> Any:
        if isinstance(result, dict):
            result["_meta"] = {**(result.get("_meta") or {}), META_SERVER_BADGE: self.own_badge}
            return result
        meta = {**(getattr(result, "meta", None) or {}), META_SERVER_BADGE: self.own_badge}
        return result.model_copy(update={"meta": meta})


def build_job_server(worker: str, own_badge: str, verifier: BadgeVerifier, binding: PeerBinding,
                     allowed_roles: frozenset[str], audit: AuditLog,
                     tools: dict[str, Callable[..., Any]]) -> MCPServer:
    server = MCPServer(worker, middleware=[CallerGateMiddleware(worker, own_badge, verifier, binding,
                                                                allowed_roles, audit)])
    for name, fn in tools.items():
        server.add_tool(fn, name=name)
    return server
