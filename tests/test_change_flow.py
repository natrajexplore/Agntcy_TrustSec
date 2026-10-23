"""P5c2/P5d offline: intake's change order + unanimous tally, the reviewer's approve rules.
Deny by default everywhere: anything but a clean RuleGate APPROVE for THESE lines is no approval."""
import asyncio
import json

import pytest
import yaml

from agenttrustsec.agents import intake, reviewer
from agenttrustsec.agents.intake import PlanError, handle_change, load_change, tally
from agenttrustsec.authz.broker import lines_digest
from agenttrustsec.review.engine import review_for_device, summary

from conftest import ROOT

CR1001 = ROOT / "lab" / "changes" / "cr-1001.yaml"
CR1003 = ROOT / "lab" / "changes" / "cr-1003.yaml"
REQ = "Add a rule on edge-fw-01 so the payments API in web-dmz can query the transaction DB (CR-1001)"


def write(tmp_path, **raw):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return p


def test_lab_change_orders_load():
    o = load_change(CR1001, REQ)
    assert o.device == "edge-fw-01" and o.change_id == "CR-1001" and len(o.lines) == 1
    o3 = load_change(CR1003, "Add the any/any troubleshooting rule on edge-fw-01")
    json.dumps(o3.change)                                          # expiry date made JSON-safe


@pytest.mark.parametrize("raw,request_text,why", [
    ({"device": "edge-fw-01", "lines": ["x"]}, REQ, "exactly: device, lines, change"),
    ({"device": "edge-fw-01", "lines": ["x"], "change": {"change_id": "C"}, "extra": 1}, REQ, "exactly"),
    ({"device": "edge-fw-99", "lines": ["x"], "change": {"change_id": "C"}}, REQ, "inventory"),
    ({"device": "edge-fw-02", "lines": ["x"], "change": {"change_id": "C"}}, REQ, "name exactly"),
    ({"device": "edge-fw-01", "lines": ["x"], "change": {"change_id": "C"}},
     "Add a rule on edge-fw-01 and edge-fw-02", "name exactly"),
    ({"device": "edge-fw-01", "lines": [], "change": {"change_id": "C"}}, REQ, "non-empty"),
    ({"device": "edge-fw-01", "lines": ["ok", "  "], "change": {"change_id": "C"}}, REQ, "non-empty"),
    ({"device": "edge-fw-01", "lines": "set x", "change": {"change_id": "C"}}, REQ, "non-empty"),
    ({"device": "edge-fw-01", "lines": ["x"], "change": {"request": {}}}, REQ, "change_id"),
])
def test_bad_change_orders_are_refused(tmp_path, raw, request_text, why):
    with pytest.raises(PlanError, match=why):
        load_change(write(tmp_path, **raw), request_text)


def test_change_file_needs_a_change_request():
    out = asyncio.run(handle_change("Audit the ACLs on edge-fw-01", CR1001, dry_run=True))
    assert out["ok"] is False and out["intent"] == "read"


def test_dry_run_change_plan():
    out = asyncio.run(handle_change(REQ, CR1001, dry_run=True))
    assert out["ok"] and out["change_id"] == "CR-1001"
    assert out["plan"]["worker"] == "executor-01" and out["plan"]["tool"] == "push_config"
    assert out["plan"]["reviewers"] == intake.reviewer_pool() and out["plan"]["reviewers"]


def test_reviewer_pool_is_the_reviewer_role_only():
    from agenttrustsec.agents.runtime import load_agent
    assert intake.reviewer_pool() == [load_agent("reviewer-01").metadata_id]


# --- tally (intake) -------------------------------------------------------------------------

P = {"proposal_id": "p1", "lines_digest": lines_digest(["a"])}
OK = {"proposal_id": "p1", "lines_digest": lines_digest(["a"]), "approve": True}


@pytest.mark.parametrize("admitted,replies,why", [
    ([], {}, "no reviewer"),
    (["r1"], {}, "no reply"),
    (["r1", "r2"], {"r1": OK}, "no reply from r2"),
    (["r1"], {"r1": {**OK, "approve": False, "reason": "REJECT"}}, "rejected"),
    (["r1"], {"r1": {**OK, "approve": "yes"}}, "rejected"),               # truthy is not True
    (["r1"], {"r1": {**OK, "proposal_id": "p0"}}, "different proposal"),   # stale reply
    (["r1"], {"r1": {**OK, "lines_digest": lines_digest(["b"])}}, "different proposal or lines"),
])
def test_anything_but_unanimous_approval_is_no(admitted, replies, why):
    ok, reason = tally(P, admitted, replies)
    assert ok is False and why in reason


def test_unanimous_approval():
    assert tally(P, ["r1", "r2"], {"r1": OK, "r2": OK}) == (True, "approved by ['r1', 'r2']")


# --- reviewer rules -------------------------------------------------------------------------

def proposal(path=CR1001, **over):
    o = load_change(path, REQ if path == CR1001 else "Add the any/any rule on edge-fw-01")
    p = {"proposal_id": "p1", "change_id": o.change_id, "device": o.device, "lines": o.lines,
         "lines_digest": lines_digest(o.lines), "change": o.change, "session": "sealed"}
    return {**p, **over}


def rulegate(p):
    return summary(review_for_device(p["device"], p["change"]))


def test_reviewer_approves_a_clean_change():
    p = proposal()
    r = reviewer.verdict(p, rulegate(p))
    assert r["approve"] is True and r["decision"] == "APPROVE" and r["lines_digest"] == p["lines_digest"]


def test_reviewer_rejects_any_any():
    p = proposal(CR1003)
    r = reviewer.verdict(p, rulegate(p))
    assert r["approve"] is False and "REJECT" in r["reason"] and r["risk_score"] == 100


@pytest.mark.parametrize("summ,why", [
    ({"decision": "APPROVE_WITH_CONDITIONS", "needs_human_review": False, "change_id": "CR-1001"}, "decision"),
    ({"decision": "APPROVE", "needs_human_review": True, "change_id": "CR-1001"}, "human review"),
    ({"decision": "APPROVE", "change_id": "CR-1001"}, "human review"),            # missing = not clean
    ({"decision": "APPROVE", "needs_human_review": False, "change_id": "CR-9999"}, "reviewed"),
    ("not json", "decision"),
])
def test_reviewer_rejects_anything_not_clean(summ, why):
    r = reviewer.verdict(proposal(), summ)
    assert r["approve"] is False and why in r["reason"]


@pytest.mark.parametrize("mutate,why", [
    (lambda p: "{not json", "not JSON"),
    (lambda p: json.dumps({k: v for k, v in p.items() if k != "session"}), "proposal needs"),
    (lambda p: json.dumps({**p, "lines": p["lines"] + ["permit ip any any"]}), "digest"),   # lines swapped
    (lambda p: json.dumps({**p, "lines": []}), "non-empty"),
    (lambda p: json.dumps({**p, "change": "CR-1001"}), "change request"),
])
def test_reviewer_refuses_bad_proposals(mutate, why):
    with pytest.raises(reviewer.BadProposal, match=why):
        reviewer.parse_proposal(mutate(proposal()))


def test_bad_proposal_gets_a_reject_reply_without_gateway_contact():
    class NoGateway:
        def gateway(self, *a):
            raise AssertionError("must not contact the gateway")
    raw = json.dumps({**proposal(), "lines_digest": "0" * 64})
    r = asyncio.run(reviewer.review(NoGateway(), raw))
    assert r == {"proposal_id": "p1", "approve": False, "reason": "bad proposal: lines digest does not match the lines"}
