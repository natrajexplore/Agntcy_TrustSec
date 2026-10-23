"""reviewer-01 (P5d): a member of the attested reviewer group that risk-reviews proposed changes.

TrustSec analogy: the posture assessment before a CoA. The reviewer joins intake's MLS group
on `agenttrustsec/lab/reviewers` only after verifying intake's badge, key and moderator role
(transport/slim_group.py), and attests with its own. For each proposal it calls RuleGate's
`review_change` THROUGH the gateway (badge -> peer -> TBAC -> intent, audited) with the read
session intake sealed for the review, then replies to intake only (reviews stay independent).

Approves only a clean RuleGate verdict: decision APPROVE, no human review, the reviewed
change_id is the proposed one, and the lines digest matches the lines it was shown. Anything
else — conditions, errors, a blocked call, a malformed proposal — is a reject (deny by default).
The reply carries the lines digest, so intake can bind its approval to exactly what was seen.

    python -m agenttrustsec.agents.reviewer serve [--audit audit/reviewer-group.jsonl]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from agenttrustsec.agents.runtime import ROOT, AgentRuntime, load_agent, result_body
from agenttrustsec.authz.broker import lines_digest

NAME = "reviewer-01"
ROLE = "reviewer"
CHANNEL = "agenttrustsec/lab/reviewers"
GROUPS = ROOT / "policies" / "groups.yaml"
PROPOSAL_FIELDS = ("proposal_id", "change_id", "device", "lines", "lines_digest", "change", "session")


class BadProposal(ValueError):
    pass


def parse_proposal(raw: str) -> dict[str, Any]:
    try:
        p = json.loads(raw)
    except ValueError:
        raise BadProposal("proposal is not JSON") from None
    if not isinstance(p, dict) or any(k not in p for k in PROPOSAL_FIELDS):
        raise BadProposal(f"proposal needs {list(PROPOSAL_FIELDS)}")
    lines = p["lines"]
    if not isinstance(lines, list) or not lines or not all(isinstance(x, str) for x in lines):
        raise BadProposal("lines must be a non-empty list of strings")
    if lines_digest(lines) != p["lines_digest"]:
        raise BadProposal("lines digest does not match the lines")
    if not isinstance(p["change"], dict):
        raise BadProposal("change must be a RuleGate change request")
    return p


def verdict(proposal: dict[str, Any], summary: Any) -> dict[str, Any]:
    """Reply for intake. approve only on a clean RuleGate result for THIS change."""
    s = summary if isinstance(summary, dict) else {}
    reasons = []
    if s.get("decision") != "APPROVE":
        reasons.append(f"RuleGate decision {s.get('decision')!r}")
    if s.get("needs_human_review") is not False:
        reasons.append("needs human review")
    if s.get("change_id") != proposal["change_id"]:
        reasons.append(f"reviewed {s.get('change_id')!r}, proposed {proposal['change_id']!r}")
    return {"proposal_id": proposal["proposal_id"], "change_id": proposal["change_id"],
            "lines_digest": proposal["lines_digest"], "approve": not reasons,
            "reason": "; ".join(reasons) or "RuleGate APPROVE, no findings needing review",
            "decision": s.get("decision"), "risk_score": s.get("risk_score"),
            "check_ids": s.get("check_ids", [])}


def reject(proposal_id: Any, reason: str) -> dict[str, Any]:
    return {"proposal_id": proposal_id, "approve": False, "reason": reason}


async def review(rt: AgentRuntime, raw: str) -> dict[str, Any]:
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError
    try:
        p = parse_proposal(raw)
    except BadProposal as e:
        pid = None
        try:
            pid = json.loads(raw).get("proposal_id")
        except (ValueError, AttributeError):
            pass
        return reject(pid, f"bad proposal: {e}")
    err = None
    async with rt.gateway(p["session"]) as gw:
        try:
            summary = result_body(await gw.call("review_change", {"device": p["device"], "change": p["change"]}))
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group
            err = e
    if isinstance(err, McpBlocked):
        return reject(p["proposal_id"], f"review_change BLOCKED by {err.blocked_by}: {err.reason}")
    if isinstance(err, ServerAuthError):
        return reject(p["proposal_id"], f"gateway not trusted: {err}")
    if err is not None:
        return reject(p["proposal_id"], f"review failed: {type(err).__name__}: {str(err)[:160]}")
    return verdict(p, summary)


async def serve(audit_path: Path, proposal_timeout_s: float = 60) -> None:
    from agenttrustsec.audit.log import AuditLog
    from agenttrustsec.authz.groups import GroupPolicy, GroupPolicyError
    from agenttrustsec.transport.slim_group import GroupMember, ModeratorRejected
    rt = await AgentRuntime(load_agent(NAME)).start()
    policy, audit = GroupPolicy.from_yaml(GROUPS), AuditLog(audit_path)
    print(f"READY {NAME} as {rt.cfg.metadata_id}; waiting for invites on {CHANNEL}", flush=True)
    while True:                                 # one group session per proposal
        m = GroupMember(rt.endpoint, policy, rt.cfg.metadata_id, rt.badge, rt.agent_verifier(),
                        rt.peer_binding(), audit)
        try:
            moderator = await m.join(timeout=3600)
        except TimeoutError:
            continue
        except (ModeratorRejected, GroupPolicyError) as e:
            print(f"REFUSED invite: {e}", flush=True)
            continue
        except Exception as e:  # noqa: BLE001 - listen timed out / session torn down
            print(f"invite not joined: {type(e).__name__}: {str(e)[:120]}", flush=True)
            continue
        try:
            reply = await review(rt, await m.receive(timeout=proposal_timeout_s))
            await m.reply(json.dumps(reply))
            print(f"REVIEWED for {moderator}: approve={reply['approve']} ({reply['reason']})", flush=True)
            while True:                         # stay until intake closes the group
                await m.receive(timeout=proposal_timeout_s)
        except Exception as e:  # noqa: BLE001 - timeout or the moderator closed the session
            print(f"group ended: {type(e).__name__}", flush=True)
        finally:
            await m.leave()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="wait for intake's group invites on SLIM")
    s.add_argument("--audit", type=Path, default=ROOT / "audit" / "reviewer-group.jsonl")
    a = ap.parse_args(argv)
    asyncio.run(serve(a.audit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
