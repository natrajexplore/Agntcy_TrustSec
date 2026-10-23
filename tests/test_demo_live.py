"""P5e: the live end-to-end demo (agenttrustsec.demo_live) and the rogue agent's CLI.
Offline parts always run; the demo itself only with the lab + Ollama up."""
import json
import os
import subprocess
import sys

import pytest

from agenttrustsec import demo_live
from agenttrustsec.agents import rogue
from agenttrustsec.demo_live import Outcome, from_gateway, from_intake, live_logs

from conftest import ROOT


@pytest.mark.parametrize("result,expected", [
    ({"ok": True}, Outcome("ALLOW", "-", "all checks passed")),
    ({"blocked_by": "peer", "reason": "x"}, Outcome("BLOCK", "peer", "x")),
    ({"calls": [{"ok": True}, {"blocked_by": "approval", "reason": "replay"}]},
     Outcome("BLOCK", "approval", "replay")),
])
def test_gateway_outcomes(result, expected):
    assert from_gateway(result) == expected


@pytest.mark.parametrize("result", [
    {"session_error": "SessionError: failed to add participant"},
    {"calls": [{"blocked_by": "intent", "reason": "x"}, {"blocked_by": "approval", "reason": "replay"}]},
])
def test_anything_unexpected_is_an_error_not_a_block(result):
    # a replay only counts if the first use was allowed; transport failures prove nothing
    assert from_gateway(result).verdict == "ERROR"


@pytest.mark.parametrize("result,verdict,by", [
    ({"ok": True, "review": {"approved": True}}, "ALLOW", "-"),
    ({"ok": False, "review": {"approved": False, "reason": "r1 rejected"}, "error": "not approved"}, "BLOCK", "review"),
    ({"ok": False, "blocked_by": "approval", "reason": "x"}, "BLOCK", "approval"),
    ({"ok": False, "error": "cannot plan: x"}, "ERROR", "-"),
])
def test_intake_outcomes(result, verdict, by):
    o = from_intake(result)
    assert (o.verdict, o.by) == (verdict, by)


def test_story_covers_every_rogue_scenario_and_both_changes():
    labels = " ".join(s.label for s in demo_live.STEPS)
    assert all(f"#{i} " in labels for i in range(1, 8))                       # P5-design §5
    assert {(s.expect, s.expect_by) for s in demo_live.STEPS if "CR-1001" in s.label} == {("ALLOW", "-")}
    assert {(s.expect, s.expect_by) for s in demo_live.STEPS if "CR-1003" in s.label} == {("BLOCK", "review")}
    assert all(s.expect_by != "-" for s in demo_live.STEPS if s.label.startswith("#"))


def test_quick_skips_only_the_extra_llm_attacks():
    assert [s.label[:2] for s in demo_live.STEPS if s.slow] == ["#4", "#5"]


def test_impersonation_attacks_run_before_the_impersonated_agent_starts():
    # SLIM routes by name: an attack using an agent's name must run while that agent is offline
    acts = [s.act for s in demo_live.STEPS]
    started = {"reader-01": acts.index("4 all agents up"), "reviewer-01": acts.index("4 all agents up"),
               "executor-01": acts.index("3 executor up")}
    for i, s in enumerate(demo_live.STEPS):
        if s.label.startswith(("#1", "#2", "#7", "reader-01 gives")):
            assert i < started["reader-01"], s.label
        if s.label.startswith(("#3", "#4", "#5")):
            assert i < started["executor-01"], s.label
        if s.label.startswith("#6"):
            assert i < started["reviewer-01"], s.label


def test_live_logs_marks_unverified_identities(tmp_path):
    p = tmp_path / "gw.jsonl"
    recs = [{"timestamp": "2026-10-23T06:54:42+00:00", "agent_id": "A1", "tool": "show_acl", "verdict": "BLOCK",
             "blocked_by": "peer", "verified_role": None,
             "checks": [{"name": "peer", "status": "FAIL", "reason": "not the badge holder"}]},
            {"timestamp": "2026-10-23T06:54:43+00:00", "agent_id": "A2", "tool": "push_config", "verdict": "ALLOW",
             "blocked_by": None, "verified_role": "executor", "checks": []}]
    p.write_text("\n".join(json.dumps(r) for r in recs))
    rows = live_logs(p, {"A1": "reader-01", "A2": "executor-01"})
    assert "reader-01*" in rows[0] and "not the badge holder" in rows[0]
    assert "executor-01 " in rows[1] and "ALLOW" in rows[1]


def test_memory_probe_reports_megabytes():
    mb = demo_live.memory_in_use_mb()
    assert mb is None or 100 < mb < 10_000_000


def test_rogue_named_attacks_resolve_from_the_registry():
    for name in rogue.ATTACKS:
        cfg = rogue.attack_cfg(name)
        assert cfg["key"] and cfg["claim"] and cfg["tool"]


def test_rogue_rejects_unknown_commands():
    out = subprocess.run([sys.executable, "-m", "agenttrustsec.agents.rogue", "attack", "nope"],
                         capture_output=True, text=True)
    assert out.returncode != 0 and "attacks:" in out.stderr


def test_demo_refuses_to_start_without_the_lab(monkeypatch, capsys):
    monkeypatch.setattr(demo_live, "preflight", lambda: ["SLIM node (127.0.0.1:46357)"])
    assert demo_live.run(quick=True) == 2
    assert "Lab not ready" in capsys.readouterr().out


# --- live ------------------------------------------------------------------------------------

def test_quick_demo_meets_every_expectation_on_the_live_lab(tmp_path):
    missing = demo_live.preflight()
    if missing:
        pytest.skip(f"needs the live lab: {missing}")
    out = subprocess.run([sys.executable, "-m", "agenttrustsec.demo_live", "--quick", "--audit-dir", str(tmp_path)],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900,
                         cwd=ROOT, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-1000:]
    assert "RESULT: all expectations met" in out.stdout
    assert "skipped (--quick)" in out.stdout and "ISE Live Logs" in out.stdout
