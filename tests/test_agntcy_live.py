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
from agenttrustsec.identity.agntcy import (  # noqa: E402
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_role_map,
)
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


# --- Revocation (docs/notes-p1.md step 8): throwaway badge, revoked on the node -------

REVOKED_ID = "AGNTCY-ad860353-453a-4d71-9190-e1f32ca0947a"   # revoke-test-01; no role
ORIGINAL = (ROOT / "tests" / "fixtures" / "revoke-test-01.original.jose").read_text().strip()


@pytest.fixture(scope="module")
def revoked_published():
    try:
        return published_badge(REVOKED_ID)
    except Exception:  # noqa: BLE001 - a different lab node never issued it
        pytest.skip("revoke-test-01 not on this node")


@pytest.mark.parametrize("which", ["published", "original"])
def test_revoked_badge_blocked_whichever_copy_is_presented(revoked_published, which):
    jose = revoked_published if which == "published" else ORIGINAL
    v = AgntcyBadgeVerifier({REVOKED_ID: "reader"})   # test-only map
    with pytest.raises(BadgeError, match="revoked"):
        v.verify(jose, REVOKED_ID)


# --- MCP mutual auth with real badges: agent AgentBadge <-> server MCPServerBadge ---

SERVERS = load_role_map(ROOT / "policies" / "identities.yaml", "mcp_servers")
SERVER_ID, = SERVERS


def _mcp_call(gate, server_badge, agent_id, read_session, server_id=SERVER_ID):
    import asyncio
    import secrets

    from mcp import Client

    from agenttrustsec.authz.broker import TokenBroker
    from agenttrustsec.mcpgate.client import TrustedClient
    from agenttrustsec.mcpgate.server import build_server
    from agenttrustsec.tools import netops

    broker = TokenBroker(secrets.token_bytes(32))
    srv = build_server("netops-mcp", gate, broker, server_badge, netops.REGISTRY)
    server_verifier = AgntcyBadgeVerifier(SERVERS, badge_type=MCP_SERVER_BADGE)

    async def go():
        async with Client(srv) as c:
            tc = TrustedClient(c, agent_id=agent_id, badge=published_badge(agent_id),
                               session_token=broker.seal_session(read_session),
                               verifier=server_verifier, server_id=server_id)
            try:
                return await tc.call("show_acl", {"device": "edge-fw-01"})
            except Exception as e:  # re-raise outside the client's task group
                err = e
        raise err
    return asyncio.run(go())


def test_mcp_mutual_auth_with_real_badges(live, policy, audit, read_session):
    from agenttrustsec.mcpgate.serve import fetch_server_badge
    gate = Gate(live, policy, BaselineIntentChecker(), audit)
    r = _mcp_call(gate, fetch_server_badge(NODE_HTTP, SERVER_ID), BY_ROLE["reader"],
                  read_session)
    assert not r.is_error
    assert [x["verdict"] for x in audit.read_all()] == ["ALLOW"]


def test_mcp_agent_badge_cannot_pose_as_server(live, policy, audit, read_session):
    from agenttrustsec.mcpgate.client import ServerAuthError
    gate = Gate(live, policy, BaselineIntentChecker(), audit)
    executor = BY_ROLE["executor"]
    with pytest.raises(ServerAuthError, match="expected MCPServerBadge"):
        _mcp_call(gate, published_badge(executor), BY_ROLE["reader"], read_session,
                  server_id=executor)
