"""AgntcyBadgeVerifier against the REAL lab Identity Node (docs/notes-p1.md, Identity
runbook). Skipped unless the SDK is installed and the node answers on :4000 / :4001.
Uses the real badges published for the ids in policies/identities.yaml."""
import base64
import json
import os
import socket
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("agntcyidentity.sdk")

from agenttrustsec.authz.gate import Gate  # noqa: E402
from agenttrustsec.authz.intent import BaselineIntentChecker  # noqa: E402
from agenttrustsec.identity.agntcy import (  # noqa: E402
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_role_map,
)
from agenttrustsec.identity.badge import BadgeError  # noqa: E402
from agenttrustsec.identity.keys import (  # noqa: E402
    THUMBPRINT_ANNOTATION, jwk_thumbprint, public_jwk,
)
from agenttrustsec.models import ToolCall, Verdict  # noqa: E402

from conftest import ROOT  # noqa: E402

NODE_HTTP = "http://localhost:4000"
KEY_DIR = Path.home() / ".agenttrustsec" / "keys"
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


def published_vcs(ident):
    url = f"{NODE_HTTP}/v1alpha1/vc/{ident}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        return [v["value"] for v in json.load(r)["vcs"]]


def payload(jose):
    part = jose.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def published_badge(ident):
    """The subject's current badge: the one published copy that is not revoked."""
    live = [j for j in published_vcs(ident) if not payload(j).get("credentialStatus")]
    assert len(live) == 1, f"{ident}: expected one unrevoked badge, found {len(live)}"
    return live[0]


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


# --- P3 PR1: every current agent badge binds the agent's signing key -----------------

@pytest.mark.parametrize("ident", sorted(ROLES))
def test_current_badge_binds_a_key_thumbprint(ident):
    oasf = json.loads(payload(published_badge(ident))["credentialSubject"]["badge"])
    thumb = oasf.get("annotations", {}).get(THUMBPRINT_ANNOTATION)
    assert thumb and len(thumb) == 43        # b64url SHA-256, issuer-signed
    key_file = KEY_DIR / f"{oasf['name'].split('/')[-1]}.pem"
    if key_file.exists():                    # only on the machine holding the keys
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        assert jwk_thumbprint(public_jwk(key.public_key())) == thumb


@pytest.mark.parametrize("ident", sorted(ROLES))
def test_old_keyless_badges_are_revoked(live, ident):
    for jose in published_vcs(ident):
        oasf = json.loads(payload(jose)["credentialSubject"]["badge"])
        if THUMBPRINT_ANNOTATION not in oasf.get("annotations", {}):
            with pytest.raises(BadgeError, match="revoked"):
                live.verify(jose, ident)


# --- Revocation (docs/notes-p1.md step 8): throwaway badge, revoked on the node -------

REVOKED_ID = "AGNTCY-ad860353-453a-4d71-9190-e1f32ca0947a"   # revoke-test-01; no role
ORIGINAL = (ROOT / "tests" / "fixtures" / "revoke-test-01.original.jose").read_text().strip()


@pytest.fixture(scope="module")
def revoked_published():
    try:
        return published_vcs(REVOKED_ID)[0]
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


def _gateway_tools(gate):
    import asyncio
    import secrets

    from agenttrustsec.authz.broker import TokenBroker
    from agenttrustsec.mcpgate import inventory, serve
    from agenttrustsec.mcpgate.server import build_server
    b = TokenBroker(secrets.token_bytes(32))
    return asyncio.run(inventory.served(build_server("netops-mcp", gate, b, None, serve._registry(b))))


def test_mcp_mutual_auth_with_real_badges(live, policy, audit, read_session):
    from agenttrustsec.mcpgate.serve import fetch_server_badge
    gate = Gate(live, policy, BaselineIntentChecker(), audit)
    r = _mcp_call(gate, fetch_server_badge(NODE_HTTP, SERVER_ID, _gateway_tools(gate)), BY_ROLE["reader"],
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


def test_C_gateway_badge_signs_what_it_serves_and_the_stale_one_is_revoked(live, policy, audit):
    # item C (2026-10-23): VC 49479d21 re-issued from the live tools/list; 3abc3ccf (stale
    # review_change) revoked. The verified badge's signed inventory == what the gateway serves.
    from agenttrustsec.mcpgate import inventory
    from agenttrustsec.mcpgate.serve import fetch_server_badge
    gate = Gate(live, policy, BaselineIntentChecker(), audit)
    verifier = AgntcyBadgeVerifier(SERVERS, badge_type=MCP_SERVER_BADGE)
    ident = verifier.verify(fetch_server_badge(NODE_HTTP, SERVER_ID, _gateway_tools(gate)), SERVER_ID)
    assert ident.badge_id == "49479d21-e220-4ed6-86e4-e7c9a2eacb94"
    assert inventory.drift(inventory.from_badge({"tools": ident.tools}), _gateway_tools(gate)) == []
    url = f"{NODE_HTTP}/v1alpha1/vc/{SERVER_ID}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        vcs = [vc["value"] for vc in json.load(r)["vcs"]]
    stale = [v for v in vcs if _vc_id(v) == "3abc3ccf-d9e0-4a3d-9a64-fd48532953df"]
    assert len(stale) == 1
    with pytest.raises(BadgeError, match="revoked"):
        verifier.verify(stale[0], SERVER_ID)


def _vc_id(jose):
    part = jose.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("id")
