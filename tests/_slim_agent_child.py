"""One agent process calling the SLIM gateway (used by test_gateway_slim_live.py).

argv[1] = JSON config: key (name in ~/.agenttrustsec/keys or "__ephemeral__"),
slim_name, sub (token subject, default slim_name), claim (agent_id claimed in _meta),
badge_id (whose current badge to present) or badge_jose, tool, args, intent, gateway_id,
approve (mint a reviewer approval for these args, as intake does after the pool approves),
approve_lines (approve OTHER lines than the ones pushed), repeat (call N times, same approval).
Prints one line: RESULT {...}.
"""
import asyncio
import base64
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from mcp import Client  # noqa: E402

from agenttrustsec.authz.broker import TokenBroker  # noqa: E402
from agenttrustsec.authz.peer import PeerBinding, slim_name  # noqa: E402
from agenttrustsec.identity.agntcy import (  # noqa: E402
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_key_thumbprints, load_role_map,
)
from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError, TrustedClient  # noqa: E402
from agenttrustsec.mcpgate.serve import IDENTITIES, TRUST_JWKS, load_trust_jwks  # noqa: E402
from agenttrustsec.models import Intent, Session  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402

KEYS = Path.home() / ".agenttrustsec" / "keys"


def current_badge(ident: str) -> str:
    url = f"http://localhost:4000/v1alpha1/vc/{ident}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        vcs = [v["value"] for v in json.load(r)["vcs"]]

    def status(j):
        part = j.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("credentialStatus")
    live = [j for j in vcs if not status(j)]
    return live[0] if live else vcs[0]


def private_pem(key: str) -> str:
    if key == "__ephemeral__":
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode()
    return (KEYS / f"{key}.pem").read_text()


async def main(cfg: dict) -> dict:
    trust = load_trust_jwks(TRUST_JWKS)
    name = cfg["slim_name"]
    ep = await slim.connect(name, slim.jwt_identity(private_pem(cfg["key"]), cfg.get("sub", name), trust))
    badge = cfg.get("badge_jose") or current_badge(cfg["badge_id"])
    broker = TokenBroker(bytes.fromhex(os.environ["AGENTTRUSTSEC_BROKER_KEY"]))  # lab intake stand-in
    session = Session(cfg.get("prompt", "Audit the ACLs on edge-fw-01"), Intent(cfg.get("intent", "read")))
    token = broker.seal_session(session)
    approval = None
    if cfg.get("approve"):
        a = cfg.get("args", {})
        approval = broker.mint_approval("CR-LIVE", a["device"], cfg.get("approve_lines", a["lines"]),
                                        session.session_id, ["reviewer-01"])
    gw = cfg["gateway_id"]
    server_verifier = AgntcyBadgeVerifier(load_role_map(IDENTITIES, "mcp_servers"),
                                          badge_type=MCP_SERVER_BADGE,
                                          key_thumbprints=load_key_thumbprints(IDENTITIES))
    transport = slim.SlimClientTransport(ep, slim_name(gw))
    async with Client(transport) as c:
        tc = TrustedClient(c, agent_id=cfg["claim"], badge=badge, session_token=token,
                           verifier=server_verifier, server_id=gw,
                           transport_peer=lambda: transport.peer, peer_binding=PeerBinding(trust))
        out = []
        for _ in range(cfg.get("repeat", 1)):
            try:
                r = await tc.call(cfg["tool"], cfg.get("args", {}), approval=approval)
                out.append({"ok": True, "text": r.content[0].text if r.content else ""})
            except McpBlocked as e:
                out.append({"blocked_by": e.blocked_by, "reason": e.reason})
            except ServerAuthError as e:
                out.append({"server_auth_error": str(e)})
        return out[0] if len(out) == 1 else {"calls": out}


if __name__ == "__main__":
    try:
        out = asyncio.run(asyncio.wait_for(main(json.loads(sys.argv[1])), 60))
    except Exception as e:  # noqa: BLE001 - report, the test decides
        out = {"session_error": f"{type(e).__name__}: {e}"[:300]}
    print("RESULT " + json.dumps(out), flush=True)
