"""P4b scope check (T6): a tool call's target (device / IP) must be named in the sealed
user request. Deny by default when a tool declares no scoped_args (D5). Never loosen."""
import inspect

import pytest

from agenttrustsec.authz.intent import BaselineIntentChecker, check_scope, named_in
from agenttrustsec.authz.tbac import PolicyError, TbacPolicy, ToolSpec
from agenttrustsec.models import Intent, Session, Status, ToolCall, Verdict
from agenttrustsec.tools import extdata, netops

from conftest import ROOT


@pytest.mark.parametrize("value,prompt,expected", [
    ("edge-fw-01", "Audit the ACLs on edge-fw-01 today", True),
    ("EDGE-FW-01", "audit edge-fw-01", True),                       # case-insensitive
    ("edge-fw-01", "Audit edge-fw-010", False),                     # longer name
    ("edge-fw-01", "Audit core-edge-fw-01", False),                 # name continues before
    ("10.0.0.1", "is 10.0.0.10 malicious?", False),                 # longer IP
    ("10.0.0.1", "is 10.0.0.1 malicious?", True),
    ("10.0.0.1", "check 10.0.0.1, then report", True),              # punctuation ends a name
    ("203.0.113.66", "check reputation (203.0.113.66)", True),
])
def test_named_in_is_whole_token(value, prompt, expected):
    assert named_in(value, prompt) is expected


def spec(scoped=("device",), change=False):
    return ToolSpec("show_acl", change, frozenset({"reader"}), frozenset({"acl", "audit"}),
                    "List ACL entries", scoped_args=scoped)


PROMPT = "Audit the ACLs on edge-fw-01"


@pytest.mark.parametrize("s,args,reason", [
    (spec(scoped=None), {"device": "edge-fw-01"}, "declares no scoped_args"),       # D5
    (spec(), None, "not available"),
    (spec(), {}, "missing"),
    (spec(), {"device": ""}, "non-empty string"),
    (spec(), {"device": {"name": "edge-fw-01"}}, "non-empty string"),
    (spec(), {"device": "edge-fw-02"}, "not named in the request"),
    (spec(), {"device": ["edge-fw-01", "core-rtr-09"]}, "core-rtr-09"),
])
def test_scope_refusals(s, args, reason):
    assert reason in check_scope(PROMPT, s, args)


@pytest.mark.parametrize("s,args", [
    (spec(), {"device": "edge-fw-01"}),
    (spec(), {"device": ["edge-fw-01", "EDGE-FW-01 "]}),
    (spec(scoped=()), {"anything": "goes"}),                          # explicitly no targets
])
def test_scope_passes(s, args):
    assert check_scope(PROMPT, s, args) is None


def test_intent_order_change_gate_then_scope_then_relevance():
    c = BaselineIntentChecker()
    read = Session(PROMPT, Intent.READ)
    assert "change tool" in c.check(read, spec(change=True), {"device": "edge-fw-02"}).reason
    r = c.check(read, spec(), {"device": "edge-fw-02"})
    assert r.status is Status.FAIL and r.reason.startswith("scope:")
    ok = c.check(read, spec(), {"device": "edge-fw-01"})
    assert ok.passed and "scope ok (device='edge-fw-01')" in ok.reason


def test_gate_blocks_t6_and_audits_scope_reason(gate, verifier, read_session, audit):
    d = gate.authorize(ToolCall("reader-01", verifier.issue("reader-01", "reader"),
                                "show_running_config", read_session, {"device": "core-rtr-02"}))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "intent"
    rec, = audit.read_all()
    assert "scope: device='core-rtr-02' is not named" in rec["checks"][-1]["reason"]


# --- policy -------------------------------------------------------------------------------

POLICY = TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")
SIGNATURES = {**{n: inspect.signature(f) for n, f in netops.REGISTRY.items()},
              "lookup_threat_intel": inspect.signature(
                  extdata.make_registry(extdata.ThreatIntelAPI(None))["lookup_threat_intel"])}


@pytest.mark.parametrize("name", sorted(POLICY.tools))
def test_every_tool_declares_scope_matching_its_signature(name):
    s = POLICY.spec(name)
    assert s.scoped_args is not None, f"{name}: undeclared scoped_args would BLOCK every call"
    assert set(s.scoped_args) <= set(SIGNATURES[name].parameters), f"{name}: typo in scoped_args?"


@pytest.mark.parametrize("value", ["device", "['*']", "[any]", "['']", "[1]"])
def test_bad_scoped_args_rejected(tmp_path, value):
    f = tmp_path / "tbac.yaml"
    f.write_text(f"tools:\n  t:\n    change: false\n    allowed_roles: [reader]\n    scoped_args: {value}\n")
    with pytest.raises(PolicyError, match="scoped_args"):
        TbacPolicy.from_yaml(f)
