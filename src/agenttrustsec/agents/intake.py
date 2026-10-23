"""intake-01 (P5c1/P5c2): takes the engineer's request, binds its intent, plans, dispatches.

TrustSec analogy: the authenticator + posture step at the edge. Intake classifies the request
(`read` / `change`) and SEALS it into a session token with the broker key (intent can't be
upgraded later, T11), turns it into one job deterministically (no LLM, E4), and hands it to
the worker that may run it — over an authenticated MCP-over-SLIM call (agents/jobserver.py),
verifying the worker's badge and key too.

Planner (deny by default): devices only from the lab inventory (whole tokens), IPv4 addresses
validated; exactly one tool group must match and its target must be present — anything else
is refused.

Change path (P5c2/P5d, needs --change-file: device + RuleGate change request; the exact lines are
rendered from the request by RuleGate, item A):
intake moderates an attested MLS group of every registered reviewer (transport/slim_group.py),
broadcasts the proposal with a read session sealed for the review, and collects replies. Only
if EVERY admitted reviewer approves the same proposal + lines digest does intake mint a
single-use approval (broker, E3) bound to change_id + device + lines + the change session, and
dispatch {device, lines, session, approval} to executor-01. No reviewer, a reject, a mismatched
or missing reply = no approval, nothing pushed. TrustSec analogy: CoA only after posture passes.

    python -m agenttrustsec.agents.intake "Audit the ACLs on edge-fw-01 for any permit-any rules"
    python -m agenttrustsec.agents.intake --dry-run "..."         # plan only, no lab needed
    python -m agenttrustsec.agents.intake --change-file lab/changes/cr-1001.yaml "Add ... on edge-fw-01"
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agenttrustsec.authz.intent import classify_intent
from agenttrustsec.models import Intent
from agenttrustsec.tools.netops import DEVICES

NAME = "intake-01"
READER = "reader-01"
EXECUTOR = "executor-01"
REVIEW_TIMEOUT_S = 120     # reviewers call RuleGate through the gateway; then: no reply = reject

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


@dataclass(frozen=True)
class ChangeOrder:
    device: str
    lines: list[str]
    change: dict[str, Any]
    rollback: list[str]

    @property
    def change_id(self) -> str:
        return str(self.change["change_id"])


def load_change(path: Path, request: str) -> ChangeOrder:
    """Change file -> ChangeOrder. The device must be in the inventory AND be the one device the
    request names (the gate's scope check would block it anyway; refuse before any contact).
    The lines are RENDERED from the change request (RuleGate, review/render.py), never taken from
    the file: a file that carries its own lines is refused."""
    import yaml
    from agenttrustsec.review.engine import UnknownDevice, review_for_device, staged_lines
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "lines" in raw:
        raise PlanError("change file must not carry lines: they are rendered from the change request")
    if not isinstance(raw, dict) or set(raw) != {"device", "change"}:
        raise PlanError("change file needs exactly: device, change")
    device, change = raw["device"], raw["change"]
    if device not in DEVICES:
        raise PlanError(f"device {device!r} is not in the lab inventory")
    if devices_in(request) != [device]:
        raise PlanError(f"the request must name exactly the change's device {device!r}, found "
                        f"{devices_in(request) or 'none'}")
    if not isinstance(change, dict) or not change.get("change_id"):
        raise PlanError("change must be a RuleGate change request with a change_id")
    change = json.loads(json.dumps(change, default=str))      # dates -> ISO strings (JSON-safe)
    try:
        staged = staged_lines(review_for_device(device, change))
    except UnknownDevice as e:
        raise PlanError(f"cannot render config: {e}") from None
    return ChangeOrder(device, staged["lines"], change, staged["rollback"])


def broker():
    from agenttrustsec.authz.broker import TokenBroker
    key = os.environ.get("AGENTTRUSTSEC_BROKER_KEY")
    if not key:
        raise SystemExit("AGENTTRUSTSEC_BROKER_KEY is not set (intake owns the broker key)")
    return TokenBroker(bytes.fromhex(key))


def seal(request: str, intent: Intent) -> str:
    from agenttrustsec.models import Session
    return broker().seal_session(Session(request, intent))


def reviewer_pool() -> list[str]:
    """Every registered agent whose badge subject the authorization map gives role reviewer."""
    import yaml

    from agenttrustsec.agents.runtime import IDENTITIES, REGISTRY
    from agenttrustsec.identity.agntcy import load_role_map
    roles = load_role_map(IDENTITIES, "agents")
    agents = yaml.safe_load(REGISTRY.read_text(encoding="utf-8")).get("agents") or {}
    return sorted(mid for mid in agents.values() if roles.get(mid) == "reviewer")


def tally(proposal: dict[str, Any], admitted: list[str], replies: dict[str, dict]) -> tuple[bool, str]:
    """Unanimous, for THIS proposal and these lines. Deny by default."""
    if not admitted:
        return False, "no reviewer was admitted to the group"
    for mid in admitted:
        r = replies.get(mid)
        if r is None:
            return False, f"no reply from {mid}"
        if r.get("proposal_id") != proposal["proposal_id"] or r.get("lines_digest") != proposal["lines_digest"]:
            return False, f"{mid} replied for a different proposal or lines"
        if r.get("approve") is not True:
            return False, f"{mid} rejected: {r.get('reason')}"
    return True, f"approved by {admitted}"


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


async def propose(rt: Any, proposal: dict[str, Any], audit_path: Path) -> tuple[list[str], dict[str, dict]]:
    """Moderate the attested reviewer group: admit, broadcast, collect one reply per member."""
    from agenttrustsec.agents.reviewer import CHANNEL, GROUPS
    from agenttrustsec.audit.log import AuditLog
    from agenttrustsec.authz.groups import GroupPolicy
    from agenttrustsec.transport.slim_group import AttestedGroup
    group = AttestedGroup(rt.endpoint, GroupPolicy.from_yaml(GROUPS).channel(CHANNEL), rt.cfg.metadata_id,
                          rt.badge, rt.agent_verifier(), rt.peer_binding(), AuditLog(audit_path))
    replies: dict[str, dict] = {}
    try:
        await group.open()
        results = await group.admit_members(reviewer_pool())
        admitted = [mid for mid, r in results.items() if r == "admitted"]
        if admitted:
            await group.broadcast(json.dumps(proposal))
            loop = asyncio.get_running_loop()
            deadline = loop.time() + REVIEW_TIMEOUT_S
            while len(replies) < len(admitted) and (left := deadline - loop.time()) > 0:
                try:
                    mid, data = await group.receive(left)
                except Exception:  # noqa: BLE001 - timeout: missing replies count as rejects
                    break
                try:
                    replies.setdefault(mid, json.loads(data))      # first reply per member counts
                except ValueError:
                    replies.setdefault(mid, {"approve": False, "reason": "unreadable reply"})
        return admitted, replies
    finally:
        await group.close()


async def handle_change(request: str, change_path: Path, dry_run: bool = False,
                        audit_path: Path | None = None) -> dict:
    from agenttrustsec.authz.broker import lines_digest
    from agenttrustsec.models import Session
    intent = classify_intent(request)
    if intent is not Intent.CHANGE:
        return {"ok": False, "intent": intent.value, "error": "a change file needs a change request"}
    try:
        order = load_change(change_path, request)
    except (PlanError, OSError, ValueError) as e:
        return {"ok": False, "intent": intent.value, "error": f"cannot plan: {e}"}
    out: dict = {"intent": intent.value, "change_id": order.change_id,
                 "plan": {"reviewers": reviewer_pool(), "worker": EXECUTOR, "tool": "push_config",
                          "args": {"device": order.device, "lines": order.lines},
                          "rollback": order.rollback}}
    if dry_run:
        return {"ok": True, **out}
    from agenttrustsec.agents.runtime import ROOT, AgentRuntime, load_agent, result_body
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError
    b = broker()
    change_session = Session(request, Intent.CHANGE)
    review_session = Session(f"Review change {order.change_id} on {order.device}: {request}", Intent.READ)
    proposal = {"proposal_id": secrets.token_hex(8), "change_id": order.change_id, "device": order.device,
                "lines": order.lines, "lines_digest": lines_digest(order.lines), "change": order.change,
                "session": b.seal_session(review_session)}
    rt = await AgentRuntime(load_agent(NAME)).start()
    admitted, replies = await propose(rt, proposal, audit_path or ROOT / "audit" / "intake-group.jsonl")
    approved, why = tally(proposal, admitted, replies)
    out["review"] = {"admitted": admitted, "approved": approved, "reason": why,
                     "replies": {m: {k: r.get(k) for k in ("approve", "reason", "decision", "risk_score")}
                                 for m, r in replies.items()}}
    if not approved:
        return {"ok": False, **out, "error": f"not approved: {why}"}
    approval = b.mint_approval(order.change_id, order.device, order.lines, change_session.session_id, admitted)
    err = None
    async with rt.peer_client(load_agent(EXECUTOR).metadata_id, "executor", rt.agent_verifier()) as worker:
        try:
            res = result_body(await worker.call("run_change", {
                "device": order.device, "lines": order.lines,
                "session": b.seal_session(change_session), "approval": approval}))
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group
            err = e
    if isinstance(err, McpBlocked):
        return {"ok": False, **out, "blocked_by": err.blocked_by, "reason": err.reason}
    if isinstance(err, ServerAuthError):
        return {"ok": False, **out, "error": f"worker not trusted: {err}"}
    if err is not None:
        raise err
    return {"ok": bool(isinstance(res, dict) and res.get("ok")), **out, "worker_result": res}


async def handle(request: str, dry_run: bool = False) -> dict:
    intent = classify_intent(request)
    if intent is Intent.CHANGE:
        return {"ok": False, "intent": intent.value,
                "error": "change requests need --change-file (device + RuleGate change request)"}
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
    ap.add_argument("--change-file", type=Path, help="change order: device + RuleGate change request")
    ap.add_argument("--audit", type=Path, help="group admission audit (change path)")
    a = ap.parse_args(argv)
    if a.change_file:
        out = asyncio.run(handle_change(a.request, a.change_file, a.dry_run, a.audit))
    else:
        out = asyncio.run(handle(a.request, a.dry_run))
    print(json.dumps(out, default=str), flush=True)
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
