"""P3 PR5 end to end: attested reviewer-pool groups over the lab SLIM node with real
badges and keys. Each scenario = one member process + one moderator process (intake-01).
docs/P3-design.md §8.3 threat table. Skipped unless the lab is up."""
import json
import subprocess
import sys
import time
import uuid

import pytest

from test_gateway_slim_live import ENV, EXECUTOR, KEYS, READER, REVOKED, ROOT, pytestmark  # noqa: F401

from agenttrustsec.authz.peer import slim_name

INTAKE = "AGNTCY-7787aa23-dfa1-4600-b664-0c728b88fd27"
REVIEWER = "AGNTCY-c55ca3ee-802d-4209-8352-343197d644ae"
SECRET = "proposal-42: remove 'permit ip any any' on edge-fw-01"
CHILD = str(ROOT / "tests" / "_group_children.py")


@pytest.fixture
def channel(tmp_path):
    name = f"agenttrustsec/lab/reviewers-{uuid.uuid4().hex[:8]}"
    policy = tmp_path / "groups.yaml"
    policy.write_text(f"channels:\n  {name}:\n    moderator_roles: [intake]\n"
                      f"    member_roles: [reviewer]\n    attest_timeout_s: 6\n")
    return name, str(policy), tmp_path / "audit.jsonl"


def _result(proc_or_out):
    text = proc_or_out if isinstance(proc_or_out, str) else proc_or_out.stdout
    line = next((ln for ln in text.splitlines() if ln.startswith("RESULT ")), None)
    assert line, f"no RESULT in: {text[-800:]}"
    return json.loads(line[7:])


def scenario(channel, *, member, moderator_key="intake-01", moderator_id=INTAKE, invite=None):
    """Run one member + one moderator; return (member result, moderator result, audit records)."""
    name, policy, audit = channel
    mcfg = {"policy": policy, **member}
    mp = subprocess.Popen([sys.executable, CHILD, "member", json.dumps(mcfg)], env=ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          encoding="utf-8", errors="replace")
    deadline, seen = time.time() + 60, []
    while time.time() < deadline:
        seen.append(mp.stdout.readline())
        if "LISTENING" in seen[-1]:
            break
        assert mp.poll() is None, "".join(seen)[-800:] + mp.stdout.read()[-800:]
    ocfg = {"key": moderator_key, "agent_id": moderator_id, "channel": name, "policy": policy,
            "audit": str(audit), "secret": SECRET,
            "members": [invite or member.get("claim")]}
    mod = subprocess.run([sys.executable, CHILD, "moderator", json.dumps(ocfg)], env=ENV,
                         capture_output=True, text=True, encoding="utf-8", errors="replace",
                         timeout=150)
    mem_out, _ = mp.communicate(timeout=90)
    records = [json.loads(ln) for ln in audit.read_text().splitlines()] if audit.exists() else []
    return _result(mem_out), _result(mod), records


def saw_secret(member_result):
    return any(SECRET in r for r in member_result.get("raw", []))


def test_genuine_reviewer_admitted_receives_and_replies(channel):
    mem, mod, audit = scenario(channel, member={"key": "reviewer-01", "claim": REVIEWER,
                                                "badge_id": REVIEWER})
    assert mem["moderator"] == INTAKE
    assert mod["results"] == {REVIEWER: "admitted"} and mod["broadcast"] == "sent"
    assert saw_secret(mem)
    assert mod["replies"] == [[REVIEWER, f"LGTM from {REVIEWER[-6:]}"]]
    rec, = audit
    assert rec["tool"] == "group.join" and rec["verdict"] == "ALLOW"
    assert [c["name"] for c in rec["checks"]] == ["badge", "peer", "group"]


def test_q7_impostor_under_reviewer_name_removed_before_any_broadcast(channel):
    # reader-01's TRUSTED key, registered as the reviewer's SLIM name, with a copy of the
    # reviewer's badge — the exact probe Q7 attack that used to read the next broadcast.
    mem, mod, audit = scenario(channel, member={"key": "reader-01", "slim_name": slim_name(REVIEWER),
                                                "claim": REVIEWER, "badge_id": REVIEWER})
    assert mod["results"] == {REVIEWER: "refused by peer"}
    assert mod["broadcast"] == "sent"          # the secret DID go out — after the removal
    assert not saw_secret(mem), mem
    assert audit[0]["verdict"] == "BLOCK" and audit[0]["blocked_by"] == "peer"


def test_valid_agent_with_wrong_role_removed(channel):
    mem, mod, audit = scenario(channel, member={"key": "executor-01", "claim": EXECUTOR,
                                                "badge_id": EXECUTOR})
    assert mod["results"] == {EXECUTOR: "refused by group"}
    assert mod["broadcast"] == "sent" and not saw_secret(mem)
    assert "may not join" in audit[0]["checks"][2]["reason"]


def test_revoked_agent_removed(channel):
    mem, mod, audit = scenario(channel, member={"key": "reader-01", "claim": REVOKED,
                                                "badge_id": REVOKED})
    assert mod["results"] == {REVOKED: "refused by badge"}
    assert mod["broadcast"] == "sent" and not saw_secret(mem)
    assert "revoked" in audit[0]["checks"][0]["reason"]


def test_impostor_moderator_gets_no_attestation(channel):
    # executor-01 is genuine but not allowed to moderate: the reviewer must refuse it
    # BEFORE attesting, so the fake moderator never learns the reviewer's badge.
    mem, mod, audit = scenario(channel, member={"key": "reviewer-01", "claim": REVIEWER,
                                                "badge_id": REVIEWER},
                               moderator_key="executor-01", moderator_id=EXECUTOR)
    assert "may not moderate" in mem.get("moderator_rejected", ""), mem
    assert mod.get("results") == {REVIEWER: "no attestation within 6s"}, mod
    assert audit[0]["checks"][2]["reason"] == "no attestation within 6s"
