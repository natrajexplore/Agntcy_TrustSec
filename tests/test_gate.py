"""Threat-model tests (see docs/ARCHITECTURE.md §4). These must never be loosened."""
import pytest

from agenttrustsec.authz.gate import BlockedError, Gate
from agenttrustsec.authz.intent import classify_intent
from agenttrustsec.identity.badge import LocalDevVerifier
from agenttrustsec.models import Intent, Status, ToolCall, Verdict
from agenttrustsec.tools import netops

PUSH = {"device": "edge-fw-01", "lines": ["permit ip any any"]}


def call(agent, badge, tool, session, args=None, approval=None):
    return ToolCall(agent, badge, tool, session, args or {"device": "edge-fw-01"}, approval=approval)


def approve(broker, session, args=PUSH):
    """What intake mints after the reviewer pool approved exactly this change (P5d)."""
    return broker.mint_approval("CR-T", args["device"], args["lines"], session.session_id, ["reviewer-01"])


def test_happy_path_read(gate, verifier, read_session):
    d = gate.authorize(call("reader-01", verifier.issue("reader-01", "reader"),
                            "show_acl", read_session))
    assert d.verdict is Verdict.ALLOW
    assert [c.status for c in d.checks] == [Status.PASS] * 3


def test_happy_path_change(gate, verifier, broker, change_session):
    out = gate.execute(call("executor-01", verifier.issue("executor-01", "executor"),
                            "push_config", change_session, PUSH, approve(broker, change_session)),
                       netops.REGISTRY)
    assert "pushed" in out
    assert len(netops.PUSHED) == 1


def test_T1_no_badge(gate, read_session):
    d = gate.authorize(call("rogue", None, "show_acl", read_session))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "badge"


def test_T2_forged_badge(gate, read_session):
    import secrets
    forged = LocalDevVerifier(secrets.token_bytes(32)).issue("executor-01", "executor")
    d = gate.authorize(call("executor-01", forged, "push_config", read_session, PUSH))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "badge"


def test_T3_revoked(gate, verifier, change_session):
    b = verifier.issue("executor-00", "executor", badge_id="v0")
    verifier.revoke("v0")
    d = gate.authorize(call("executor-00", b, "push_config", change_session, PUSH))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "badge"


def test_T4_reader_cannot_push_even_in_change_window(gate, verifier, change_session):
    d = gate.authorize(call("reader-01", verifier.issue("reader-01", "reader"),
                            "push_config", change_session, PUSH))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "tbac"


def test_T5_executor_cannot_push_during_read_session(gate, verifier, read_session):
    with pytest.raises(BlockedError) as e:
        gate.execute(call("executor-01", verifier.issue("executor-01", "executor"),
                          "push_config", read_session, PUSH), netops.REGISTRY)
    assert e.value.decision.blocked_by == "intent"
    assert netops.PUSHED == []  # the device was never touched


def test_T6_irrelevant_tool_blocked(gate, verifier, read_session):
    d = gate.authorize(call("reader-01", verifier.issue("reader-01", "reader"),
                            "show_bgp_neighbors", read_session))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "intent"


def test_role_comes_from_badge_not_claim(gate, verifier, change_session):
    # Agent is really a reader; nothing it claims can make it an executor.
    d = gate.authorize(call("reader-01", verifier.issue("reader-01", "reader"),
                            "push_config", change_session, PUSH))
    assert d.verified_role == "reader" and d.verdict is Verdict.BLOCK


class ExplodingVerifier:
    def verify(self, badge, claimed_agent_id):
        raise RuntimeError("identity service unreachable")


def test_error_in_check_means_block(policy, audit, read_session):
    from agenttrustsec.authz.intent import BaselineIntentChecker
    g = Gate(ExplodingVerifier(), policy, BaselineIntentChecker(), audit)
    d = g.authorize(call("reader-01", "x.y", "show_acl", read_session))
    assert d.verdict is Verdict.BLOCK
    assert d.checks[0].status is Status.ERROR


def test_one_audit_record_per_call(gate, verifier, read_session, audit):
    b = verifier.issue("reader-01", "reader")
    gate.authorize(call("reader-01", b, "show_acl", read_session))
    gate.authorize(call("reader-01", b, "push_config", read_session, PUSH))
    gate.authorize(call("rogue", None, "push_config", read_session, PUSH))
    recs = audit.read_all()
    assert [r["verdict"] for r in recs] == ["ALLOW", "BLOCK", "BLOCK"]
    for r in recs:
        extra = {"approval"} if r["tool"] == "push_config" else set()     # requires_approval (P5d)
        assert {c["name"] for c in r["checks"]} == {"badge", "tbac", "intent"} | extra
        assert "badge" not in r or r.get("badge") is None  # raw badge never logged
        assert b not in str(r)


@pytest.mark.parametrize("prompt,expected", [
    ("Audit the ACLs on edge-fw-01", Intent.READ),
    ("show me bgp neighbors", Intent.READ),
    ("Remove the any-any rule from edge-fw-01", Intent.CHANGE),
    ("push the new ACL to the firewall", Intent.CHANGE),
])
def test_classify_intent(prompt, expected):
    assert classify_intent(prompt) is expected
