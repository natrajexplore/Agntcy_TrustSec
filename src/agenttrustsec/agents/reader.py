"""reader-01 (P5b): runs read-only jobs through the gated gateway.

A job is `{tool, args}` — turning the engineer's words into a job is intake's work (P5c).
The reader only attempts tools its role is allowed in policies/tbac.yaml (defence in depth:
the gate still decides every call, and audits it).

One-shot CLI (lab; the session is sealed by the intake stand-in, AGENTTRUSTSEC_BROKER_KEY):

    python -m agenttrustsec.agents.reader --tool show_acl --args '{"device": "edge-fw-01"}' \\
        --prompt "Audit the ACLs on edge-fw-01 for any permit-any rules"
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from agenttrustsec.agents.runtime import ROOT, AgentRuntime, load_agent, result_body
from agenttrustsec.authz.tbac import TbacPolicy

NAME = "reader-01"
ROLE = "reader"


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


def seal_lab_session(prompt: str, intent: str = "read") -> str:
    """Lab intake stand-in until P5c: seal with the shared broker key."""
    from agenttrustsec.authz.broker import TokenBroker
    from agenttrustsec.models import Intent, Session
    key = os.environ.get("AGENTTRUSTSEC_BROKER_KEY")
    if not key:
        raise SystemExit("AGENTTRUSTSEC_BROKER_KEY is not set (lab intake stand-in)")
    return TokenBroker(bytes.fromhex(key)).seal_session(Session(prompt, Intent(intent)))


async def main_async(argv: list[str] | None = None) -> int:
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tool", required=True)
    ap.add_argument("--args", default="{}", help="JSON object of tool arguments")
    ap.add_argument("--prompt", required=True, help="the engineer's request (sealed into the session)")
    a = ap.parse_args(argv)
    rt = await AgentRuntime(load_agent(NAME)).start()
    try:
        out = {"ok": True, "result": await run_job(rt, seal_lab_session(a.prompt), a.tool, json.loads(a.args))}
    except McpBlocked as e:
        out = {"ok": False, "blocked_by": e.blocked_by, "reason": e.reason}
    except (ServerAuthError, NotAReadTool) as e:
        out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(out, default=str), flush=True)
    return 0 if out["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(argv))


if __name__ == "__main__":
    sys.exit(main())
