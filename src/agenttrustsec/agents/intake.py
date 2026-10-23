"""intake-01 (P5c1): takes the engineer's request, binds its intent, plans, dispatches.

TrustSec analogy: the authenticator + posture step at the edge. Intake classifies the request
(`read` / `change`) and SEALS it into a session token with the broker key (intent can't be
upgraded later, T11), turns it into one job deterministically (no LLM, E4), and hands it to
the worker that may run it — over an authenticated MCP-over-SLIM call (agents/jobserver.py),
verifying the worker's badge and key too.

Planner (deny by default): devices only from the lab inventory (whole tokens), IPv4 addresses
validated; exactly one tool group must match and its target must be present — anything else
is refused. Change requests go to the reviewer pool (P5c2/P5d): refused here for now.

    python -m agenttrustsec.agents.intake "Audit the ACLs on edge-fw-01 for any permit-any rules"
    python -m agenttrustsec.agents.intake --dry-run "..."         # plan only, no lab needed
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

from agenttrustsec.authz.intent import classify_intent
from agenttrustsec.models import Intent
from agenttrustsec.tools.netops import DEVICES

NAME = "intake-01"
READER = "reader-01"

# tool -> (trigger words, required target argument). Order does not matter: >1 match = refuse.
TOOL_RULES = {
    "lookup_threat_intel": ({"reputation", "malicious", "threat", "intel", "ioc", "blocklist"}, "ip"),
    "show_bgp_neighbors": ({"bgp", "peering", "neighbor", "neighbors"}, "device"),
    "show_acl": ({"acl", "acls", "access-list", "rules", "rule", "firewall", "permit", "deny"}, "device"),
    "show_running_config": ({"config", "configuration", "running-config", "backup", "ntp", "logging"},
                            "device"),
}
_NAME_CHARS = r"A-Za-z0-9._\-"
_IPV4 = re.compile(rf"(?<![{_NAME_CHARS}])(\d{{1,3}}(?:\.\d{{1,3}}){{3}})(?![{_NAME_CHARS}])")


class PlanError(ValueError):
    """Intake could not turn the request into exactly one safe job."""


@dataclass(frozen=True)
class Job:
    tool: str
    args: dict[str, Any]


def devices_in(request: str) -> list[str]:
    return [d for d in DEVICES
            if re.search(rf"(?<![{_NAME_CHARS}]){re.escape(d)}(?![{_NAME_CHARS}])", request, re.I)]


def ips_in(request: str) -> list[str]:
    out = []
    for m in _IPV4.findall(request):
        try:
            out.append(str(ipaddress.IPv4Address(m)))
        except ValueError:
            continue
    return out


def plan(request: str) -> Job:
    words = set(re.findall(r"[a-z][a-z0-9-]*", request.lower()))
    devices, ips = devices_in(request), ips_in(request)
    # threat intel is about an address: it wins over device tools when an IP and its words appear
    intel_words, _ = TOOL_RULES["lookup_threat_intel"]
    if words & intel_words and ips:
        if len(ips) != 1:
            raise PlanError(f"threat-intel lookups take exactly one IP, found {ips}")
        return Job("lookup_threat_intel", {"ip": ips[0]})
    matched = [t for t, (trigger, target) in TOOL_RULES.items() if target == "device" and words & trigger]
    if not matched:
        raise PlanError("no read tool matches this request")
    if len(matched) > 1:
        raise PlanError(f"ambiguous request: matches {sorted(matched)}")
    if len(devices) != 1:
        raise PlanError(f"{matched[0]} needs exactly one known device, found {devices or 'none'}")
    return Job(matched[0], {"device": devices[0]})


def seal(request: str, intent: Intent) -> str:
    from agenttrustsec.authz.broker import TokenBroker
    from agenttrustsec.models import Session
    key = os.environ.get("AGENTTRUSTSEC_BROKER_KEY")
    if not key:
        raise SystemExit("AGENTTRUSTSEC_BROKER_KEY is not set (intake owns the broker key)")
    return TokenBroker(bytes.fromhex(key)).seal_session(Session(request, intent))


async def dispatch(job: Job, token: str) -> Any:
    from agenttrustsec.agents.runtime import AgentRuntime, load_agent, result_body
    rt = await AgentRuntime(load_agent(NAME)).start()
    reader = load_agent(READER).metadata_id
    err = None
    async with rt.peer_client(reader, "reader", rt.agent_verifier()) as worker:
        try:
            return result_body(await worker.call("run_job", {"tool": job.tool, "args": job.args,
                                                             "session": token}))
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group
            err = e
    raise err


async def handle(request: str, dry_run: bool = False) -> dict:
    intent = classify_intent(request)
    if intent is Intent.CHANGE:
        return {"ok": False, "intent": intent.value,
                "error": "change requests go to the reviewer pool (P5c2/P5d) — not handled yet"}
    try:
        job = plan(request)
    except PlanError as e:
        return {"ok": False, "intent": intent.value, "error": f"cannot plan: {e}"}
    out: dict = {"intent": intent.value, "plan": {"worker": READER, "tool": job.tool, "args": job.args}}
    if dry_run:
        return {"ok": True, **out}
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError
    try:
        res = await dispatch(job, seal(request, intent))
    except McpBlocked as e:
        return {"ok": False, **out, "blocked_by": e.blocked_by, "reason": e.reason}
    except ServerAuthError as e:
        return {"ok": False, **out, "error": f"worker not trusted: {e}"}
    return {"ok": bool(isinstance(res, dict) and res.get("ok")), **out, "worker_result": res}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("request")
    ap.add_argument("--dry-run", action="store_true", help="classify and plan only")
    a = ap.parse_args(argv)
    out = asyncio.run(handle(a.request, a.dry_run))
    print(json.dumps(out, default=str), flush=True)
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
