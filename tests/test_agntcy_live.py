"""AgntcyBadgeVerifier against the REAL lab Identity Node (docs/notes-p1.md, Identity
runbook). Skipped unless the SDK is installed and the node answers on :4000 / :4001.
Uses the real badges published for the ids in policies/identities.yaml."""
import json
import os
import socket
import urllib.request

import pytest

pytest.importorskip("agntcyidentity.sdk")

from agenttrustsec.authz.gate import Gate  # noqa: E402
from agenttrustsec.authz.intent import BaselineIntentChecker  # noqa: E402
from agenttrustsec.identity.agntcy import AgntcyBadgeVerifier, load_role_map  # noqa: E402
from agenttrustsec.identity.badge import BadgeError  # noqa: E402
from agenttrustsec.models import ToolCall, Verdict  # noqa: E402

from conftest import ROOT  # noqa: E402

NODE_HTTP = "http://localhost:4000"
PUSH = {"device": "edge-fw-01", "lines": ["permit ip any any"]}


def _port_open(port):
    try:
        socket.create_connection(("localhost", port), timeout=1).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not (_port_open(4000) and _port_open(4001)),
                                reason="lab Identity Node not running")

ROLES = load_role_map(ROOT / "policies" / "identities.yaml", "agents")
BY_ROLE = {role: ident for ident, role in ROLES.items()}


@pytest.fixture(scope="module", autouse=True)
def node_env():
    os.environ.setdefault("IDENTITY_NODE_GRPC_SERVER_URL", "localhost:4001")
    os.environ.setdefault("IDENTITY_NODE_USE_SSL", "0")


def published_badge(ident):
    url = f"{NODE_HTTP}/v1alpha1/vc/{ident}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.load(r)["vcs"][0]["value"]


@pytest.fixture(scope="module")
def live():
    return AgntcyBadgeVerifier(ROLES)


@pytest.mark.parametrize("ident,role", sorted(ROLES.items()))
def test_every_mapped_agent_verifies(live, ident, role):
    got = live.verify(published_badge(ident), ident)
    assert (got.agent_id, got.role) == (ident, role)


def test_tampered_signature_rejected_by_node(live):
    jose = published_badge(BY_ROLE["reader"])
    head, payload, sig = jose.split(".")
    flipped = sig[:-4] + ("AAAA" if sig[-4:] != "AAAA" else "BBBB")
    with pytest.raises(BadgeError, match="identity node rejected"):
        live.verify(f"{head}.{payload}.{flipped}", BY_ROLE["reader"])


def test_replayed_badge_for_other_agent_rejected(live):
    with pytest.raises(BadgeError, match="subject mismatch"):
        live.verify(published_badge(BY_ROLE["reader"]), BY_ROLE["executor"])


def test_gate_with_real_badges(live, policy, audit, read_session, change_session):
    g = Gate(live, policy, BaselineIntentChecker(), audit)
    reader, executor = BY_ROLE["reader"], BY_ROLE["executor"]
    rb, eb = published_badge(reader), published_badge(executor)

    d = g.authorize(ToolCall(reader, rb, "show_acl", read_session, {"device": "edge-fw-01"}))
    assert d.verdict is Verdict.ALLOW and d.verified_role == "reader"

    d = g.authorize(ToolCall(reader, rb, "push_config", change_session, PUSH))
    assert d.verdict is Verdict.BLOCK      # TBAC: reader may not change

    d = g.authorize(ToolCall(executor, eb, "push_config", read_session, PUSH))
    assert d.verdict is Verdict.BLOCK      # change tool in a read session
