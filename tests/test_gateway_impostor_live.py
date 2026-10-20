"""P3 mutual auth, agent side (T9 replay): an impostor gateway with a COPY of the real
MCPServerBadge, under the real gateway's SLIM name, signing with another trusted key.
The agent must refuse its results. Runs in its own module so it never overlaps the
real gateway of test_gateway_slim_live.py."""
import subprocess
import sys
import time

import pytest

pytest.importorskip("slim_bindings")
pytest.importorskip("agntcyidentity.sdk")

from test_gateway_slim_live import ACL, ENV, GW, READER, ROOT, agent, pytestmark  # noqa: E402,F401

from agenttrustsec.authz.peer import slim_name  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def impostor(tmp_path_factory):
    audit = tmp_path_factory.mktemp("imp") / "decisions.jsonl"
    proc = subprocess.Popen([sys.executable, str(ROOT / "tests" / "_slim_impostor_child.py"),
                             GW, str(audit)], env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    deadline = time.time() + 60
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("READY"):
            break
        if proc.poll() is not None:
            pytest.fail(f"impostor exited: {proc.stdout.read()[-800:]}")
    yield proc
    proc.terminate()
    proc.wait(10)


def test_agent_rejects_gateway_holding_a_copied_badge():
    r = agent(key="reader-01", slim_name=slim_name(READER), claim=READER, badge_id=READER,
              tool="show_acl", args=ACL)
    assert "not signed by the badge's key" in r.get("server_auth_error", ""), r
