"""P3 end to end: the REAL gateway process (serve.py --transport slim) and agent
processes over the lab SLIM node, real badges (lab Identity Node), real agent keys.
Attack matrix from docs/P3-design.md §4. Skipped unless everything is up locally."""
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("slim_bindings")
pytest.importorskip("agntcyidentity.sdk")

ROOT = Path(__file__).resolve().parents[1]
KEYS = Path.home() / ".agenttrustsec" / "keys"
GW = "AGNTCY-2e3bc5c0-7bc2-4c5f-a055-ff6ae74d0add"
READER = "AGNTCY-13cbc3cf-89ae-43d6-b5b4-b0681092b8fb"
EXECUTOR = "AGNTCY-f3f8503b-43e7-4cd1-8822-2ff32a78db84"
REVOKED = "AGNTCY-ad860353-453a-4d71-9190-e1f32ca0947a"   # revoke-test-01
ACL = {"device": "edge-fw-01"}
PUSH = {"device": "edge-fw-01", "lines": ["permit ip any any"]}


def _up(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not (_up(46357) and _up(4000) and _up(4001) and (KEYS / "netops-mcp.pem").exists()),
    reason="needs lab SLIM node, lab Identity Node and the lab keys")

from agenttrustsec.authz.peer import slim_name  # noqa: E402

BROKER_KEY = secrets.token_hex(32)
ENV = {**os.environ, "AGENTTRUSTSEC_BROKER_KEY": BROKER_KEY,
       "IDENTITY_NODE_GRPC_SERVER_URL": "localhost:4001", "IDENTITY_NODE_USE_SSL": "0",
       "PYTHONPATH": str(ROOT / "src")}


@pytest.fixture(scope="module")
def audit_path(tmp_path_factory):
    return tmp_path_factory.mktemp("gw") / "decisions.jsonl"


@pytest.fixture(scope="module", autouse=True)
def gateway(audit_path):
    proc = subprocess.Popen(
        [sys.executable, "-m", "agenttrustsec.mcpgate.serve", "--transport", "slim",
         "--server-id", GW, "--audit", str(audit_path)],
        env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
        errors="replace")
    deadline = time.time() + 60
    while time.time() < deadline:
        line = proc.stdout.readline()
        if "peer-check=ON" in line:
            break
        if proc.poll() is not None:
            pytest.fail(f"gateway exited: {line} {proc.stdout.read()[-800:]}")
    else:
        proc.kill()
        pytest.fail("gateway did not come up")
    yield proc
    proc.terminate()
    proc.wait(10)


def agent(**cfg):
    cfg = {"gateway_id": GW, **cfg}
    out = subprocess.run([sys.executable, str(ROOT / "tests" / "_slim_agent_child.py"),
                          json.dumps(cfg)], env=ENV, capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=120)
    line = next((ln for ln in out.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line, f"agent produced no result: {out.stdout[-600:]} {out.stderr[-600:]}"
    return json.loads(line[7:])


def last_audit(audit_path):
    return json.loads(audit_path.read_text().splitlines()[-1])


def test_genuine_reader_allowed_and_peer_audited(audit_path):
    r = agent(key="reader-01", slim_name=slim_name(READER), claim=READER, badge_id=READER,
              tool="show_acl", args=ACL)
    assert r.get("ok"), r
    rec = last_audit(audit_path)
    assert rec["verdict"] == "ALLOW"
    assert [c["name"] for c in rec["checks"]] == ["badge", "peer", "tbac", "intent"]
    assert rec["peer"]["subject"] == slim_name(READER)


def test_trusted_key_with_copied_badge_and_name_blocked_by_peer(audit_path):
    # executor's key is in the trust JWKS; it uses reader's SLIM name AND reader's badge
    r = agent(key="executor-01", slim_name=slim_name(READER), claim=READER, badge_id=READER,
              tool="show_acl", args=ACL)
    assert r.get("blocked_by") == "peer" and "not signed by the badge's key" in r["reason"], r
    assert last_audit(audit_path)["verified_role"] is None


def test_own_key_presenting_someone_elses_badge_blocked_by_peer():
    r = agent(key="reader-01", slim_name=slim_name(READER), claim=EXECUTOR, badge_id=EXECUTOR,
              tool="push_config", args=PUSH, intent="change",
              prompt="Remove the permit any any rule on edge-fw-01")
    assert r.get("blocked_by") == "peer" and "not the badge holder" in r["reason"], r


def test_spoofed_token_subject_blocked_by_peer():
    r = agent(key="reader-01", slim_name=slim_name(READER), sub="agenttrustsec/lab/executor-admin",
              claim=READER, badge_id=READER, tool="show_acl", args=ACL)
    assert r.get("blocked_by") == "peer" and "identity mismatch" in r["reason"], r


def test_key_outside_trust_never_reaches_the_gate(audit_path):
    before = len(audit_path.read_text().splitlines())
    r = agent(key="__ephemeral__", slim_name=slim_name(READER), claim=READER, badge_id=READER,
              tool="show_acl", args=ACL)
    assert "failed to add participant" in r.get("session_error", ""), r
    assert len(audit_path.read_text().splitlines()) == before     # SLIM dropped it first


def test_revoked_agent_blocked_by_badge():
    r = agent(key="reader-01", slim_name=slim_name(REVOKED), claim=REVOKED, badge_id=REVOKED,
              tool="show_acl", args=ACL)
    assert r.get("blocked_by") == "badge" and "revoked" in r["reason"], r


def test_genuine_executor_still_needs_change_intent():
    # peer passes; the layers behind it still apply (T5)
    r = agent(key="executor-01", slim_name=slim_name(EXECUTOR), claim=EXECUTOR, badge_id=EXECUTOR,
              tool="push_config", args=PUSH, intent="read")
    assert r.get("blocked_by") == "intent", r


def test_legitimate_change_judged_by_local_llm(audit_path):
    # P4e (D4): a change tool in a change session reaches the local LLM verifier in the real
    # gateway; ALLOW requires its verdict, which is recorded in the audit reason.
    r = agent(key="executor-01", slim_name=slim_name(EXECUTOR), claim=EXECUTOR, badge_id=EXECUTOR,
              tool="push_config", args={"device": "edge-fw-01", "lines": ["no permit ip any any"]},
              intent="change", prompt="Remove the 'permit ip any any' entry from the ACL on edge-fw-01")
    assert r.get("ok"), r
    rec = last_audit(audit_path)
    assert rec["verdict"] == "ALLOW" and rec["tool"] == "push_config"
    assert "semantic: llm allow" in rec["checks"][-1]["reason"], rec["checks"][-1]
