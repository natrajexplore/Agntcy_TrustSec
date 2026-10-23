"""executor-01 (P5d): applies an APPROVED change with `push_config` through the gated gateway.

Serve mode: a long-running process on SLIM (dials OUT, no port) exposing one MCP tool,
`run_change(device, lines, session, approval)`, behind the caller gate — only a verified
`intake` agent may dispatch (agents/jobserver.py). The executor decides nothing: it forwards
intake's sealed change session and the reviewer-approval token, and the gateway checks
badge -> peer -> TBAC -> intent (scope + local LLM) -> approval (E3) and audits the call.
TrustSec analogy: the switch port that only opens after the CoA for exactly this change.

    python -m agenttrustsec.agents.executor serve [--audit audit/executor-dispatch.jsonl]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from agenttrustsec.agents.runtime import ROOT, AgentRuntime, load_agent, result_body

NAME = "executor-01"
ROLE = "executor"
TOOL = "push_config"
DISPATCHERS = frozenset({"intake"})


async def run_change(rt: AgentRuntime, session_token: str, approval: str, device: str,
                     lines: list[str]) -> Any:
    err = None
    async with rt.gateway(session_token) as gw:
        try:
            return result_body(await gw.call(TOOL, {"device": device, "lines": lines}, approval=approval))
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group
            err = e
    raise err


def change_tool(rt: AgentRuntime):
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError

    async def run_change_tool(device: str, lines: list[str], session: str, approval: str) -> dict:
        """Push the approved lines through the gateway with the forwarded session + approval."""
        try:
            return {"ok": True, "result": await run_change(rt, session, approval, device, lines)}
        except McpBlocked as e:
            return {"ok": False, "blocked_by": e.blocked_by, "reason": e.reason}
        except ServerAuthError as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return run_change_tool


async def serve(audit_path: Path) -> None:
    from agenttrustsec.agents.jobserver import build_job_server
    from agenttrustsec.audit.log import AuditLog
    from agenttrustsec.transport import slim
    rt = await AgentRuntime(load_agent(NAME)).start()
    server = build_job_server(NAME, rt.badge, rt.agent_verifier(), rt.peer_binding(), DISPATCHERS,
                              AuditLog(audit_path), {"run_change": change_tool(rt)})
    print(f"READY {NAME} as {rt.cfg.metadata_id}; dispatch allowed for {sorted(DISPATCHERS)}", flush=True)
    await slim.serve_slim(server, rt.endpoint)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run as a job server on SLIM")
    s.add_argument("--audit", type=Path, default=ROOT / "audit" / "executor-dispatch.jsonl")
    a = ap.parse_args(argv)
    asyncio.run(serve(a.audit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
