"""MCP over SLIM against the REAL lab SLIM node (lab/slim/). Skipped unless
slim-bindings is installed and the node answers on 127.0.0.1:46357.

Proves the adapter carries MCP over an MLS session and REPORTS the peer faithfully —
including a spoofed subject, which SLIM accepts and the gate must reject (PR3)."""
import asyncio
import base64
import json
import socket
import uuid

import pytest

pytest.importorskip("slim_bindings")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

from agenttrustsec.identity.keys import public_jwk  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402


def _node_up():
    try:
        socket.create_connection(("127.0.0.1", 46357), timeout=1).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _node_up(), reason="lab SLIM node not running")


def keypair(kid):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return pem, {**public_jwk(k.public_key()), "kid": kid, "alg": "RS256", "use": "sig"}


def claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class RecordPeer:
    """Stands in for GateMiddleware: records the SLIM peer each tools/call arrives with."""
    def __init__(self):
        self.seen = []

    async def __call__(self, ctx, call_next):
        if ctx.method == "tools/call":
            self.seen.append(slim.PEER.get())
        return await call_next(ctx)


def run_exchange(agent_pem, agent_sub, trust, *, agent_name=None):
    """Gateway + agent on the lab node; returns (tool text, gateway-side peers, client-side peer)."""
    tag = uuid.uuid4().hex[:8]                     # unique names per test run
    gw_name, ag_name = f"agenttrustsec/lab/gw-{tag}", agent_name or f"agenttrustsec/lab/ag-{tag}"
    gw_pem, gw_jwk = keypair("gw")
    trust = trust + [gw_jwk]
    rec = RecordPeer()
    server = MCPServer("echo", middleware=[rec])
    server.add_tool(lambda text: f"echo:{text}", name="echo")

    async def go():
        gw = await slim.connect(gw_name, slim.jwt_identity(gw_pem, gw_name, trust))
        sub = agent_sub(ag_name) if callable(agent_sub) else agent_sub
        ag = await slim.connect(ag_name, slim.jwt_identity(agent_pem, sub, trust))
        serving = asyncio.create_task(slim.serve_slim(server, gw))
        try:
            transport = slim.SlimClientTransport(ag, gw_name)
            async with Client(transport) as c:
                r = await c.call_tool("echo", {"text": "hi"})
            return r.content[0].text, rec.seen, transport.peer, ag_name, gw_name
        finally:
            serving.cancel()
            for ep in (gw, ag):     # free the names for the next exchange in this process
                try:
                    await ep.app.unsubscribe_async(ep.app.name(), ep.conn_id)
                except Exception as e:  # noqa: BLE001 - best-effort test teardown
                    print(f"unsubscribe {ep.name}: {e}")
    return asyncio.run(asyncio.wait_for(go(), 60))


def test_mcp_round_trip_over_mls_reports_both_peers():
    pem, jwk = keypair("agent")
    text, seen, gw_peer, ag_name, gw_name = run_exchange(pem, lambda n: n, [jwk])
    assert text == "echo:hi"
    peer, = seen
    assert peer.subject == peer.source_name == ag_name
    assert claims(peer.token)["sub"] == ag_name            # the signed token the gate re-verifies
    assert gw_peer.subject == gw_peer.source_name == gw_name


def test_agent_key_not_in_trust_jwks_cannot_reach_gateway():
    # Gateway drops it (InvalidSignature); the agent's session never forms.
    pem, _ = keypair("rogue")
    _, trusted = keypair("someone-else")
    with pytest.raises(slim.sb.SlimError.SessionError, match="failed to add participant"):
        run_exchange(pem, lambda n: n, [trusted])


def test_spoofed_subject_is_reported_not_hidden():
    # SLIM accepts a trusted key claiming another name (P3-design §1). The adapter must
    # surface the mismatch so the gate's `peer` check can BLOCK it (PR3).
    pem, jwk = keypair("agent")
    _, seen, _, ag_name, _ = run_exchange(pem, "agenttrustsec/lab/executor-admin", [jwk])
    peer, = seen
    assert peer.source_name == ag_name and peer.subject == "agenttrustsec/lab/executor-admin"


def test_trust_jwk_without_alg_refused():
    # SLIM would silently skip it and the agent could never connect — fail loudly.
    pem, jwk = keypair("x")
    with pytest.raises(ValueError, match="alg=RS256"):
        slim.jwt_identity(pem, "agenttrustsec/lab/x", [{k: v for k, v in jwk.items() if k != "alg"}])


def test_empty_trust_jwks_refused():
    pem, _ = keypair("x")
    with pytest.raises(ValueError, match="trust no one"):
        slim.jwt_identity(pem, "agenttrustsec/lab/x", [])
