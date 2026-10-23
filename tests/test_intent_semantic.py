"""P4e (D4 = change tools only): change tools are judged by the semantic matcher (local LLM);
read tools keep the keyword check. Order: change gate -> scope -> semantic. Never loosen."""
import pytest

from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.semantic import MatchResult
from agenttrustsec.mcpgate import serve
from agenttrustsec.models import Intent, Session, Status, ToolCall, Verdict

PUSH = {"device": "edge-fw-01", "lines": ["no permit ip any any"]}
CHANGE = Session("Remove the 'permit ip any any' entry from the ACL on edge-fw-01", Intent.CHANGE)
READ = Session("Audit the ACLs on edge-fw-01 for any permit-any rules", Intent.READ)


class FakeMatcher:
    def __init__(self, allow=True, error=None):
        self.allow, self.error, self.calls = allow, error, []

    def match(self, task, tool, server_tools=()):
        self.calls.append((task, tool))
        if self.error:
            raise self.error
        return MatchResult(self.allow, 1.0, f"llm {'allow' if self.allow else 'deny'}: fake")


def check(policy, matcher, session, tool, args):
    return BaselineIntentChecker(matcher).check(session, policy.spec(tool), args)


def test_change_tool_allowed_by_llm(policy):
    m = FakeMatcher(allow=True)
    r = check(policy, m, CHANGE, "push_config", PUSH)
    assert r.status is Status.PASS and "semantic: llm allow" in r.reason
    (task, tool), = m.calls
    assert task == CHANGE.user_prompt and tool.name == "push_config"
    assert tool.description == policy.spec("push_config").description      # OUR text, not the server's


def test_change_tool_denied_by_llm(policy):
    r = check(policy, FakeMatcher(allow=False), CHANGE, "push_config", PUSH)
    assert r.status is Status.FAIL and "semantic: llm deny" in r.reason


@pytest.mark.parametrize("session,args,why", [
    (READ, PUSH, "change tool"),                                         # change gate first
    (CHANGE, {"device": "edge-fw-02", "lines": ["x"]}, "scope:"),          # then scope
])
def test_llm_never_consulted_after_an_earlier_failure(policy, session, args, why):
    m = FakeMatcher()
    r = check(policy, m, session, "push_config", args)
    assert r.status is Status.FAIL and why in r.reason and m.calls == []


def test_read_tools_keep_the_keyword_check(policy):
    m = FakeMatcher(allow=False)
    r = check(policy, m, READ, "show_acl", {"device": "edge-fw-01"})
    assert r.passed and "matches request on" in r.reason and m.calls == []


def test_llm_error_is_gate_error_block(policy, verifier, audit):
    # no approval authority: the intent ERROR must block on its own (approval is SKIPPED)
    g = Gate(verifier, policy, BaselineIntentChecker(FakeMatcher(error=TimeoutError("ollama"))), audit)
    d = g.authorize(ToolCall("executor-01", verifier.issue("executor-01", "executor"),
                             "push_config", CHANGE, PUSH))
    intent = next(c for c in d.checks if c.name == "intent")
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "intent" and intent.status is Status.ERROR
    rec = next(c for c in audit.read_all()[0]["checks"] if c["name"] == "intent")
    assert "TimeoutError" in rec["reason"]


def test_gate_allows_change_only_with_llm_pass(policy, verifier, audit, broker):
    g = Gate(verifier, policy, BaselineIntentChecker(FakeMatcher(allow=True)), audit, approvals=broker)
    ok = broker.mint_approval("CR-T", PUSH["device"], PUSH["lines"], CHANGE.session_id, ["reviewer-01"])
    d = g.authorize(ToolCall("executor-01", verifier.issue("executor-01", "executor"),
                             "push_config", CHANGE, PUSH, approval=ok))
    assert d.verdict is Verdict.ALLOW


@pytest.mark.parametrize("err", [OSError("connection refused"), RuntimeError("digest != pinned")])
def test_gateway_refuses_to_start_without_the_local_llm(monkeypatch, err):
    from agenttrustsec.authz import semantic

    def broken(*a, **kw):
        raise err
    monkeypatch.setattr(semantic, "ollama_judge", broken)
    with pytest.raises(serve.LlmUnavailable, match="unavailable"):
        serve.local_llm_matcher()
