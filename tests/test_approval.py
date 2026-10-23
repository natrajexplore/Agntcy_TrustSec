"""P5d (E3): push_config needs a single-use reviewer approval bound to device + lines + session.
TrustSec analogy: a CoA that authorizes exactly one change for one session. Never loosen."""
import secrets

import pytest

from agenttrustsec.authz.broker import TokenBroker, TokenError
from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.tbac import PolicyError, TbacPolicy
from agenttrustsec.models import Intent, Session, Status, ToolCall, Verdict
from agenttrustsec.tools import netops

LINES = ["no permit ip any any"]
PUSH = {"device": "edge-fw-01", "lines": LINES}
CHANGE = Session("Remove the permit ip any any rule from the ACL on edge-fw-01", Intent.CHANGE)


def mint(broker, device="edge-fw-01", lines=LINES, sid=None, ttl_s=900):
    return broker.mint_approval("CR-1001", device, lines, sid or CHANGE.session_id, ["reviewer-01"],
                                ttl_s=ttl_s)


def push(gate, verifier, approval, args=PUSH, session=CHANGE):
    return gate.authorize(ToolCall("executor-01", verifier.issue("executor-01", "executor"),
                                   "push_config", session, args, approval=approval))


def test_every_change_tool_requires_approval(policy):
    change = [n for n, s in policy.tools.items() if s.change]
    assert change and all(policy.spec(n).requires_approval for n in change)


def test_approved_change_is_allowed_once(gate, verifier, broker, audit):
    tok = mint(broker)
    d = push(gate, verifier, tok)
    assert d.verdict is Verdict.ALLOW and d.checks[-1].name == "approval"
    assert "CR-1001" in d.checks[-1].reason and "reviewer-01" in d.checks[-1].reason
    d2 = push(gate, verifier, tok)                                     # replay
    assert d2.verdict is Verdict.BLOCK and d2.blocked_by == "approval" and "replay" in d2.checks[-1].reason
    rec = audit.read_all()[0]
    assert rec["approval_presented"] is True and tok not in str(rec)   # token itself never logged


@pytest.mark.parametrize("make,args,session,why", [
    (lambda b: None, PUSH, CHANGE, "no approval token"),
    (lambda b: mint(b, lines=["permit ip any any"]), PUSH, CHANGE, "lines differ"),
    (lambda b: mint(b), {"device": "edge-fw-01", "lines": LINES + ["permit ip any any"]}, CHANGE,
     "lines differ"),                                                   # extra line smuggled in
    (lambda b: mint(b, device="edge-fw-02"), PUSH, CHANGE, "device"),
    (lambda b: mint(b, sid="other-session"), PUSH, CHANGE, "different session"),
    (lambda b: mint(b, ttl_s=-1), PUSH, CHANGE, "expired"),
    (lambda b: mint(TokenBroker(secrets.token_bytes(32))), PUSH, CHANGE, "signature"),  # self-minted
    (lambda b: b.seal_session(CHANGE), PUSH, CHANGE, "expected approval"),               # wrong type
])
def test_anything_but_the_approved_change_is_blocked(gate, verifier, broker, make, args, session, why):
    d = push(gate, verifier, make(broker), args, session)
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "approval" and why in d.checks[-1].reason


def test_no_approval_authority_blocks(policy, verifier, audit, broker):
    g = Gate(verifier, policy, BaselineIntentChecker(), audit)        # approvals=None
    d = push(g, verifier, mint(broker))
    assert d.verdict is Verdict.BLOCK and "no approval authority" in d.checks[-1].reason


def test_approval_not_consumed_when_an_earlier_check_fails(gate, verifier, broker):
    tok = mint(broker)
    read = Session(CHANGE.user_prompt, Intent.READ, session_id=CHANGE.session_id)
    d = push(gate, verifier, tok, session=read)                        # intent fails first
    assert d.blocked_by == "intent" and d.checks[-1].status is Status.SKIPPED
    assert push(gate, verifier, tok).verdict is Verdict.ALLOW          # still redeemable


def test_blocked_push_never_reaches_the_device(gate, verifier):
    with pytest.raises(Exception):
        gate.execute(ToolCall("executor-01", verifier.issue("executor-01", "executor"),
                              "push_config", CHANGE, PUSH), netops.REGISTRY)
    assert netops.PUSHED == []


def test_approval_error_is_block(policy, verifier, audit):
    class Broken:
        def redeem_approval(self, *a):
            raise RuntimeError("store down")
    d = push(Gate(verifier, policy, BaselineIntentChecker(), audit, approvals=Broken()), verifier, "x")
    assert d.verdict is Verdict.BLOCK and d.checks[-1].status is Status.ERROR


def test_requires_approval_must_be_boolean(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("tools:\n  x:\n    change: true\n    allowed_roles: [executor]\n    requires_approval: 'yes'\n")
    with pytest.raises(PolicyError, match="requires_approval"):
        TbacPolicy.from_yaml(p)
