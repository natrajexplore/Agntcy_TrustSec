"""P5c1: intake's deterministic planner (deny by default) and the agents' caller gate."""
import asyncio
import json

import pytest
import yaml

from agenttrustsec.agents import reader
from agenttrustsec.agents.intake import Job, PlanError, handle, plan
from agenttrustsec.agents.jobserver import authorize_caller
from agenttrustsec.identity.badge import BadgeError, VerifiedIdentity
from agenttrustsec.models import CheckResult, Status, Verdict

from conftest import ROOT

CASES = yaml.safe_load((ROOT / "eval" / "netops_cases.yaml").read_text(encoding="utf-8"))["cases"]
READ_CORE = [c for c in CASES if c["category"] == "core" and c["intent"] == "read"
             and c["tool"] in reader.allowed_tools()]


@pytest.mark.parametrize("case", READ_CORE, ids=[c["id"] for c in READ_CORE])
def test_planner_reproduces_every_legitimate_read_case(case):
    assert plan(case["task"]) == Job(case["tool"], case["args"])


@pytest.mark.parametrize("request_text,why", [
    ("Audit the ACLs for permit-any rules", "exactly one known device"),
    ("Compare the ACLs on edge-fw-01 and edge-fw-02", "exactly one known device"),
    ("Audit the ACLs on edge-fw-99", "exactly one known device"),          # not in the inventory
    ("Show the ACL and the BGP neighbors on edge-fw-01", "ambiguous"),
    ("Book a meeting room for Thursday", "no read tool"),
    ("Show the ACL rules for change CR-1003", "exactly one known device"),  # CR id is not a device
    ("Is 999.1.1.1 malicious?", "no read tool"),                           # not a valid IPv4
    ("Is 203.0.113.66 or 198.51.100.7 malicious?", "exactly one IP"),
])
def test_planner_refuses_what_it_cannot_map_safely(request_text, why):
    with pytest.raises(PlanError, match=why):
        plan(request_text)


def test_change_requests_need_a_change_file():
    out = asyncio.run(handle("Remove the 'permit ip any any' entry from the ACL on edge-fw-01"))
    assert out["ok"] is False and out["intent"] == "change" and "--change-file" in out["error"]


def test_dry_run_plans_without_touching_the_lab():
    out = asyncio.run(handle("Are all BGP sessions on core-rtr-02 established?", dry_run=True))
    assert out == {"ok": True, "intent": "read",
                   "plan": {"worker": "reader-01", "tool": "show_bgp_neighbors", "args": {"device": "core-rtr-02"}}}


# --- caller gate (agents/jobserver.py) ----------------------------------------------------

class Verifier:
    def __init__(self, role="intake", fail=False):
        self.role, self.fail = role, fail

    def verify(self, badge, claimed):
        if self.fail:
            raise BadgeError("revoked")
        return VerifiedIdentity(claimed, self.role, "vc-1", "thumb")


class Binding:
    def __init__(self, ok=True):
        self.ok = ok

    def check(self, peer, ident):
        return CheckResult("peer", Status.PASS if self.ok else Status.FAIL, "x")


ARGS = {"tool": "show_acl", "args": {"device": "edge-fw-01"}, "session": "SEALED-SECRET"}


def decide(verifier=None, binding=None):
    return authorize_caller("reader-01", verifier or Verifier(), binding or Binding(), frozenset({"intake"}),
                            "AGNTCY-intake", "badge", None, "run_job", ARGS)


def test_intake_may_dispatch():
    d = decide()
    assert d.verdict is Verdict.ALLOW and [c.name for c in d.checks] == ["badge", "peer", "caller"]
    assert d.call.tool == "dispatch.run_job"


@pytest.mark.parametrize("kw,blocked_by", [
    ({"verifier": Verifier(role="executor")}, "caller"),       # valid agent, wrong role
    ({"verifier": Verifier(role="reader")}, "caller"),         # a worker can't dispatch to a worker
    ({"verifier": Verifier(fail=True)}, "badge"),
    ({"binding": Binding(ok=False)}, "peer"),                  # copied badge, wrong key
])
def test_everyone_else_is_refused(kw, blocked_by):
    d = decide(**kw)
    assert d.verdict is Verdict.BLOCK and d.blocked_by == blocked_by and d.verified_role is None


def test_forwarded_session_token_is_never_audited():
    rec = decide().to_audit_record()
    assert "SEALED-SECRET" not in json.dumps(rec) and rec["args"] == {"tool": "show_acl",
                                                                       "args": {"device": "edge-fw-01"}}
