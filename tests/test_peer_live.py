"""`peer` check end to end: REAL SLIM tokens (lab SLIM node) against REAL badges (lab
Identity Node), signed with the real agent keys in ~/.agenttrustsec/keys/.
Skipped unless both nodes run and the keys exist on this machine."""
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("slim_bindings")
pytest.importorskip("agntcyidentity.sdk")


def _up(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


KEYS = Path.home() / ".agenttrustsec" / "keys"
pytestmark = pytest.mark.skipif(
    not (_up(46357) and _up(4000) and _up(4001) and (KEYS / "reader-01.pem").exists()),
    reason="needs lab SLIM node, lab Identity Node and the lab agent keys")

from cryptography.hazmat.primitives import serialization  # noqa: E402

from agenttrustsec.authz.peer import PeerBinding, slim_name  # noqa: E402
from agenttrustsec.identity.agntcy import AgntcyBadgeVerifier  # noqa: E402
from agenttrustsec.identity.keys import trust_jwk  # noqa: E402
from agenttrustsec.models import Status, TransportPeer  # noqa: E402

from test_agntcy_live import BY_ROLE, ROLES, node_env, published_badge  # noqa: E402,F401


def pem(name):
    return (KEYS / f"{name}.pem").read_text()


def jwk(name):
    k = serialization.load_pem_private_key(pem(name).encode(), password=None)
    return trust_jwk(k.public_key())


def trust():
    # Lazy: never touch key files at import (CI and other machines have none).
    return [jwk(n) for n in ("reader-01", "reviewer-01", "executor-01", "netops-mcp")]


_CHILD = """
import json, sys
sys.path[:0] = sys.argv[3:]
from test_peer_live import trust, pem
from test_slim_transport import run_exchange
_, seen, *_ = run_exchange(pem(sys.argv[1]), lambda n: n, trust(), agent_name=sys.argv[2])
p = seen[0]
print("PEER " + json.dumps([p.source_name, p.subject, p.token]))
"""


def peer_seen_by_gateway(signing_key, as_metadata_id):
    # Fresh process per exchange: re-using a SLIM name inside one process after a
    # session fails (stale routing to the old instance; observed, not root-caused).
    tests_dir = str(Path(__file__).parent)
    src_dir = str(Path(__file__).parents[1] / "src")
    out = subprocess.run([sys.executable, "-c", _CHILD, signing_key, slim_name(as_metadata_id),
                          tests_dir, src_dir], capture_output=True, text=True, timeout=120)
    line = next((ln for ln in out.stdout.splitlines() if ln.startswith("PEER ")), None)
    assert line, f"exchange failed: {out.stdout[-500:]} {out.stderr[-500:]}"
    return TransportPeer(*json.loads(line[5:]))


@pytest.fixture(scope="module")
def reader_ident():
    reader = BY_ROLE["reader"]
    return AgntcyBadgeVerifier(ROLES).verify(published_badge(reader), reader)


def test_real_reader_proves_its_badge_key(reader_ident):
    r = PeerBinding(trust()).check(peer_seen_by_gateway("reader-01", BY_ROLE["reader"]), reader_ident)
    assert r.status is Status.PASS, r.reason


def test_executor_key_presenting_reader_badge_is_blocked(reader_ident):
    # executor-01's key is TRUSTED by SLIM, it uses reader-01's SLIM name and badge:
    # SLIM lets the session form; only the badge-bound key check stops it.
    r = PeerBinding(trust()).check(peer_seen_by_gateway("executor-01", BY_ROLE["reader"]), reader_ident)
    assert r.status is Status.FAIL and "not signed by the badge's key" in r.reason
