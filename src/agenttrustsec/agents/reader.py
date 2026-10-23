"""reader-01 (P5b/P5c): a worker agent that runs read-only jobs through the gated gateway.

Serve mode (P5c): a long-running process on SLIM (dials OUT, no port) exposing one MCP tool,
`run_job(tool, args, session)`, behind the caller gate — only a verified `intake` agent may
dispatch (agents/jobserver.py). The job's sealed session (from intake) is forwarded to the
gateway, which still checks badge -> peer -> TBAC -> intent and audits the call.
The reader only attempts tools its TBAC role allows (defence in depth; the gate decides).

    python -m agenttrustsec.agents.reader serve [--audit audit/reader-dispatch.jsonl]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from agenttrustsec.agents.runtime import ROOT, AgentRuntime, load_agent, result_body
from agenttrustsec.authz.tbac import TbacPolicy

NAME = "reader-01"
ROLE = "reader"
DISPATCHERS = frozenset({"intake"})


class NotAReadTool(PermissionError):
    pass


def allowed_tools(policy: TbacPolicy | None = None) -> set[str]:
    policy = policy or TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")
    return {n for n, s in policy.tools.items() if ROLE in s.allowed_roles and not s.change}


async def run_job(rt: AgentRuntime, session_token: str, tool: str, args: dict[str, Any]) -> Any:
    if tool not in allowed_tools():
        raise NotAReadTool(f"{NAME} does not run {tool!r} (not a read tool for role {ROLE!r})")
    err = None
    async with rt.gateway(session_token) as gw:
        try:
            return result_body(await gw.call(tool, args))
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group,
            err = e             # which would otherwise wrap it in an ExceptionGroup
    raise err


def job_tool(rt: AgentRuntime):
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError

    async def run_job_tool(tool: str, args: dict, session: str) -> dict:
        """Run one read-only job through the gateway with the forwarded sealed session."""
        try:
            return {"ok": True, "result": await run_job(rt, session, tool, args)}
        except McpBlocked as e:
            return {"ok": False, "blocked_by": e.blocked_by, "reason": e.reason}
        except (ServerAuthError, NotAReadTool) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return run_job_tool


async def serve(audit_path: Path) -> None:
    from agenttrustsec.agents.jobserver import build_job_server
    from agenttrustsec.audit.log import AuditLog
    from agenttrustsec.transport import slim
    rt = await AgentRuntime(load_agent(NAME)).start()
    server = build_job_server(NAME, rt.badge, rt.agent_verifier(), rt.peer_binding(), DISPATCHERS,
                              AuditLog(audit_path), {"run_job": job_tool(rt)})
    print(f"READY {NAME} as {rt.cfg.metadata_id}; dispatch allowed for {sorted(DISPATCHERS)}", flush=True)
    await slim.serve_slim(server, rt.endpoint)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run as a job server on SLIM")
    s.add_argument("--audit", type=Path, default=ROOT / "audit" / "reader-dispatch.jsonl")
    a = ap.parse_args(argv)
    asyncio.run(serve(a.audit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
