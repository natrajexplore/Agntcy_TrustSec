"""Moderator / member processes for test_group_live.py (one SLIM app per process).

    python _group_children.py moderator '<json cfg>'
    python _group_children.py member    '<json cfg>'

Members print LISTENING once subscribed, then one RESULT line. A member records EVERY raw
payload SLIM hands it (not only what GroupMember passes up), so the test can prove a
refused member never saw the secret.
"""
import asyncio
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))


from agenttrustsec.agents.rogue import current_badge, private_pem  # noqa: E402
from agenttrustsec.audit.log import AuditLog  # noqa: E402
from agenttrustsec.authz.groups import GroupPolicy  # noqa: E402
from agenttrustsec.authz.peer import PeerBinding, slim_name  # noqa: E402
from agenttrustsec.identity.agntcy import (  # noqa: E402
    AgntcyBadgeVerifier, load_key_thumbprints, load_role_map,
)
from agenttrustsec.mcpgate.serve import IDENTITIES, TRUST_JWKS, load_trust_jwks  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402
from agenttrustsec.transport.slim_group import (  # noqa: E402
    AttestedGroup, GroupNotReady, GroupMember, ModeratorRejected,
)


def verifier():
    return AgntcyBadgeVerifier(load_role_map(IDENTITIES, "agents"),
                               key_thumbprints=load_key_thumbprints(IDENTITIES))


async def connect(cfg, trust):
    name = cfg.get("slim_name") or slim_name(cfg.get("agent_id") or cfg["claim"])
    return await slim.connect(name, slim.jwt_identity(private_pem(cfg["key"]), name, trust))


async def moderator(cfg):
    trust = load_trust_jwks(TRUST_JWKS)
    ep = await connect(cfg, trust)
    policy = GroupPolicy.from_yaml(cfg["policy"]).channel(cfg["channel"])
    g = AttestedGroup(ep, policy, cfg["agent_id"], current_badge(cfg["agent_id"]), verifier(),
                      PeerBinding(trust), AuditLog(Path(cfg["audit"])))
    await g.open()
    out = {"results": await g.admit_members(cfg["members"])}
    try:
        await g.broadcast(cfg["secret"])
        out["broadcast"] = "sent"
    except GroupNotReady as e:
        out["broadcast"] = f"refused: {e}"
    out["replies"] = []
    for _ in g.admitted:
        try:
            out["replies"].append(list(await g.receive(15)))
        except TimeoutError:
            break
    await asyncio.sleep(1)
    await g.close()
    return out


async def member(cfg):
    trust = load_trust_jwks(TRUST_JWKS)
    ep = await connect(cfg, trust)
    m = GroupMember(ep, GroupPolicy.from_yaml(cfg["policy"]), cfg["claim"],
                    current_badge(cfg["badge_id"]), verifier(), PeerBinding(trust))
    print("LISTENING", flush=True)
    out = {"raw": []}
    try:
        out["moderator"] = await m.join(60)
    except ModeratorRejected as e:
        out["moderator_rejected"] = str(e)
        return out
    # record everything SLIM delivers until the session closes or goes quiet
    while True:
        try:
            msg = await m.session.get_message_async(timeout=datetime.timedelta(seconds=12))
        except Exception as e:  # noqa: BLE001
            out["ended"] = str(e)[:60]
            break
        body = json.loads(msg.payload)
        out["raw"].append(body.get("type") + ":" + str(body.get("data", "")))
        if body.get("type") == "broadcast":
            m._mod_ctx = msg.context
            await m.reply(f"LGTM from {cfg['claim'][-6:]}")
    return out


if __name__ == "__main__":
    role, cfg = sys.argv[1], json.loads(sys.argv[2])
    try:
        res = asyncio.run(asyncio.wait_for((moderator if role == "moderator" else member)(cfg), 120))
    except Exception as e:  # noqa: BLE001
        res = {"error": f"{type(e).__name__}: {e}"[:300]}
    print("RESULT " + json.dumps(res), flush=True)
