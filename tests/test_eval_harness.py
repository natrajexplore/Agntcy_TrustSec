"""P4a evaluation harness: metrics, fail-closed runner, ASTRA loader, netops case integrity."""
import inspect
import json
import sys

import pytest
import yaml

from conftest import ROOT

sys.path.insert(0, str(ROOT / "eval"))

import astra_eval  # noqa: E402
import netops_eval  # noqa: E402
from harness import Case, metrics, run  # noqa: E402

from agenttrustsec.authz.semantic import LexicalMatcher, ToolRef, content_words  # noqa: E402
from agenttrustsec.authz.tbac import TbacPolicy  # noqa: E402
from agenttrustsec.tools import extdata, netops  # noqa: E402

A, B = ToolRef("a", "read alpha"), ToolRef("b", "write beta")


def test_task_allowed_only_if_every_tool_allowed_and_errors_block():
    cases = [Case("t1", (A, B), "correct"), Case("t2", (A,), "wrong"), Case("t3", (B,), "null")]

    def decide(case, tool):
        if case.task == "t3":
            raise RuntimeError("matcher down")
        return tool.name == "a", "x"
    out = run(decide, cases)
    assert [o.allowed for o in out] == [False, True, False]
    assert out[2].per_tool[0][2].startswith("ERROR RuntimeError")


def test_metrics_security_first():
    # 4 correct (1 blocked), 5 wrong (2 allowed), 2 null (0 allowed)
    allow = {"c0": False, "c1": True, "c2": True, "c3": True,
             "w0": True, "w1": True, "w2": False, "w3": False, "w4": False,
             "n0": False, "n1": False}
    cases = [Case(t, (A,), {"c": "correct", "w": "wrong", "n": "null"}[t[0]]) for t in allow]
    m = metrics(run(lambda c, t: (allow[c.task], ""), cases))
    assert m["n"] == {"correct": 4, "wrong": 5, "null": 2}
    assert m["false_allow_wrong"] == pytest.approx(2 / 5)
    assert m["false_allow_null"] == 0.0
    assert m["false_block_correct"] == pytest.approx(1 / 4)
    assert m["precision"] == pytest.approx(3 / 5)          # 3 correct allowed of 5 allowed
    assert m["recall"] == pytest.approx(3 / 4)
    assert m["accuracy"] == pytest.approx((3 + 5) / 11)    # 3 correct allowed + 5 bad blocked


def test_metrics_empty_label_is_none_not_zero():
    m = metrics(run(lambda c, t: (True, ""), [Case("c", (A,), "correct")]))
    assert m["false_allow_wrong"] is None and m["false_allow_null"] is None


# --- ASTRA loader (tiny fake tree shaped like the pinned commit) --------------------------

def astra_tree(tmp_path, tag="wrong", tool="t2"):
    srv = tmp_path / "data" / "mcp_servers" / "ASTRA"
    srv.mkdir(parents=True)
    (srv / "x.json").write_text(json.dumps({"name": "srv-x", "tools": [
        {"name": "t1", "description": "do one"}, {"name": "t2", "description": "do two"}]}))
    split = tmp_path / "data" / "01_tool" / "ASTRA"
    split.mkdir(parents=True)
    (split / "test.json").write_text(json.dumps([{
        "input": {"task": "please do one", "tools": [tool], "mcp_servers": ["srv-x"]},
        "groundtruth": {"tools": ["t1"], "mcp_servers": ["srv-x"]}, "match_tag": tag}]))
    return tmp_path


def test_astra_loader_maps_descriptions_and_labels(tmp_path):
    case, = astra_eval.load_cases(astra_tree(tmp_path), "01_tool", "test")
    assert case.label == "wrong" and case.tools[0] == ToolRef("t2", "do two", "srv-x")
    assert {t.name for t in case.server_tools["srv-x"]} == {"t1", "t2"}


@pytest.mark.parametrize("kw,exc", [({"tag": "maybe"}, ValueError), ({"tool": "ghost"}, KeyError)])
def test_astra_loader_fails_loudly_on_schema_drift(tmp_path, kw, exc):
    with pytest.raises(exc):
        astra_eval.load_cases(astra_tree(tmp_path, **kw), "01_tool", "test")


# --- netops cases: every case must be a call our gateway could really receive -------------

SIGNATURES = {**{n: inspect.signature(f) for n, f in netops.REGISTRY.items()},
              "lookup_threat_intel": inspect.signature(
                  extdata.make_registry(extdata.ThreatIntelAPI(None))["lookup_threat_intel"])}


def test_netops_cases_are_valid_calls():
    policy = TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")
    raw = yaml.safe_load((ROOT / "eval" / "netops_cases.yaml").read_text(encoding="utf-8"))["cases"]
    ids = [c["id"] for c in raw]
    assert len(ids) == len(set(ids))
    for c in raw:
        assert c["label"] in ("correct", "wrong", "null"), c["id"]
        assert c["intent"] in ("read", "change"), c["id"]
        assert policy.spec(c["tool"]) is not None, c["id"]
        SIGNATURES[c["tool"]].bind(**c["args"])          # TypeError if args don't fit the tool
    cases = netops_eval.load(policy)
    assert {"core", "near-miss", "off-domain", "scope"} <= {c.category for c in cases}


def test_lexical_baseline():
    assert "acl" in content_words("Audit the ACL on show_acl")
    assert LexicalMatcher().match("audit the acl", ToolRef("show_acl", "List ACL entries")).allow
    assert not LexicalMatcher().match("book a room", ToolRef("show_acl", "List ACL entries")).allow


# --- P4d: pilots keep the label mix ------------------------------------------------------

def test_stratified_sample_keeps_label_mix():
    cases = ([Case(f"c{i}", (A,), "correct") for i in range(50)] +
             [Case(f"w{i}", (A,), "wrong") for i in range(40)] +
             [Case(f"n{i}", (A,), "null") for i in range(10)])
    s = astra_eval.stratified(cases, 20)
    assert [sum(c.label == lab for c in s) for lab in ("correct", "wrong", "null")] == [10, 8, 2]
    assert astra_eval.stratified(cases, 0) is cases
