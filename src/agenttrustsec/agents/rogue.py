"""rogue (P5e): scripted attacks on the live lab with REAL or stolen material. Each must be BLOCKED.

TrustSec analogy: the pen-tester on the access port — a genuine laptop with someone else's
cert, a valid user in the wrong SGT, a replayed CoA. The rogue uses real lab keys and copies of
real published badges; where an attack needs a sealed session or an approval it acts as a lab
stand-in holding the broker key (AGENTTRUSTSEC_BROKER_KEY), i.e. it replays genuine tokens.

    python -m agenttrustsec.agents.rogue attack <name>          # one named attack (ATTACKS)
    python -m agenttrustsec.agents.rogue gateway '<json cfg>'   # raw gateway call (tests)
    python -m agenttrustsec.agents.rogue dispatch <caller> <worker>
    python -m agenttrustsec.agents.rogue group-impostor [seconds]

Prints one line: RESULT {...}. NOTE: SLIM routes by name — run name-impersonation attacks while
the impersonated agent's own process is offline (two live apps under one name break routing).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import urllib.request
from typing import Any

from agenttrustsec.agents.runtime import KEY_DIR, NODE_HTTP, REGISTRY, load_agent

# --- material ------------------------------------------------------------------------------


def agent_id(name: str) -> str:
    return load_agent(name).metadata_id


def current_badge(ident: str, node_http: str = NODE_HTTP) -> str:
    """Copy of a published badge (any badge on the node is public — copying is the attack)."""
    url = f"{node_http}/v1alpha1/vc/{ident}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        vcs = [v["value"] for v in json.load(r)["vcs"]]

    def status(j):
        part = j.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("credentialStatus")
    live = [j for j in vcs if not status(j)]
    return live[0] if live else vcs[0]


def private_pem(key: str) -> str:
    if key == "__ephemeral__":                     # a key outside the trust JWKS
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode()
    return (KEY_DIR / f"{key}.pem").read_text()


class NodeRefused(Exception):
    """The SLIM node refused the device at the TLS layer (item E)."""


async def rogue_connect(name: str, pem: str, sub: str, trust: list, device: str | None = None):
    """An attacker's dial-in. `device` = whose enrolled device it rides (default: its own key).
    An unenrolled device does NOT stop at our adapter's refusal: it dials the node anyway over TLS
    with no client cert, so the node itself must refuse it."""
    import slim_bindings as sb

    from agenttrustsec.transport import slim, tls
    device_pem = private_pem(device) if device else pem
    try:
        return await slim.connect(name, slim.jwt_identity(pem, sub, trust), key_pem=device_pem)
    except tls.NotEnrolled:
        cfg = sb.new_secure_client_config(slim.DEFAULT_ENDPOINT)
        cfg.tls = sb.TlsClientConfig(insecure=False, insecure_skip_verify=True, source=sb.TlsSource.NONE(),
                                     ca_source=sb.CaSource.NONE(), include_system_ca_certs_pool=False,
                                     tls_version="tls1.3")
        try:
            conn = await slim._get_service().connect_async(cfg)
            app = slim._get_service().create_app(sb.Name.from_string(name), *slim.jwt_identity(pem, sub, trust))
            await app.subscribe_async(sb.Name.from_string(name), conn)
        except Exception as e:  # noqa: BLE001 - the expected outcome
            raise NodeRefused(f"node refused the unenrolled device: {type(e).__name__}: {str(e)[:160]}") from None
        raise RuntimeError("UNEXPECTED: node accepted a device without a client cert")


def _broker():
    from agenttrustsec.authz.broker import TokenBroker
    return TokenBroker(bytes.fromhex(os.environ["AGENTTRUSTSEC_BROKER_KEY"]))


# --- raw primitives ------------------------------------------------------------------------

async def gateway_call(cfg: dict) -> dict:
    """cfg: key (name in the key dir or "__ephemeral__"), slim_name, sub (token subject, default
    slim_name), claim (agent id claimed in _meta), badge_id (whose badge to copy) or badge_jose,
    device (ride another key's enrolled device, item E),
    tool, args, intent, prompt, gateway_id, approve (mint an approval for args), approve_lines
    (approve OTHER lines), repeat (call N times with the same approval), session + approval
    (captured tokens, replayed verbatim)."""
    from mcp import Client

    from agenttrustsec.agents.runtime import IDENTITIES
    from agenttrustsec.authz.peer import PeerBinding, slim_name
    from agenttrustsec.identity.agntcy import (
        MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_key_thumbprints, load_role_map,
    )
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError, TrustedClient
    from agenttrustsec.mcpgate.serve import TRUST_JWKS, load_trust_jwks
    from agenttrustsec.models import Intent, Session
    from agenttrustsec.transport import slim
    trust = load_trust_jwks(TRUST_JWKS)
    name = cfg["slim_name"]
    ep = await rogue_connect(name, private_pem(cfg["key"]), cfg.get("sub", name), trust, cfg.get("device"))
    badge = cfg.get("badge_jose") or current_badge(cfg["badge_id"])
    broker = _broker()
    session = Session(cfg.get("prompt", "Audit the ACLs on edge-fw-01"), Intent(cfg.get("intent", "read")))
    token = cfg.get("session") or broker.seal_session(session)
    approval = cfg.get("approval")
    if cfg.get("approve"):
        a = cfg.get("args", {})
        approval = broker.mint_approval("CR-LIVE", a["device"], cfg.get("approve_lines", a["lines"]),
                                        session.session_id, ["reviewer-01"])
    gw = cfg.get("gateway_id") or _gateway_id()
    server_verifier = AgntcyBadgeVerifier(load_role_map(IDENTITIES, "mcp_servers"), badge_type=MCP_SERVER_BADGE,
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


def _gateway_id() -> str:
    import yaml
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["gateway"]["metadata_id"]


JOBS = {
    "reader-01": ("reader", "run_job", {"tool": "show_running_config", "args": {"device": "core-rtr-01"},
                                        "session": "x"}),
    "executor-01": ("executor", "run_change", {"device": "edge-fw-01", "lines": ["permit ip any any"],
                                               "session": "x", "approval": "x"}),
}


async def dispatch(caller: str, target: str) -> dict:
    """A genuine non-intake agent (own badge, own key) trying to give a worker a job."""
    from agenttrustsec.agents.runtime import AgentRuntime, result_body
    from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError
    rt = await AgentRuntime(load_agent(caller)).start()
    role, tool, args = JOBS[target]
    err = None
    async with rt.peer_client(load_agent(target).metadata_id, role, rt.agent_verifier()) as worker:
        try:
            return {"ok": True, "result": result_body(await worker.call(tool, args))}
        except Exception as e:  # noqa: BLE001 - re-raise outside the client's task group
            err = e
    if isinstance(err, McpBlocked):
        return {"blocked_by": err.blocked_by, "reason": err.reason}
    if isinstance(err, ServerAuthError):
        return {"server_auth_error": str(err)}
    raise err


async def group_impostor(seconds: float = 90) -> dict:
    """reader-01's TRUSTED key registered under the reviewer's SLIM name with a copy of the
    reviewer's badge, waiting for intake's invite. Records every payload SLIM hands it."""
    import datetime

    from agenttrustsec.authz.peer import slim_name
    from agenttrustsec.mcpgate.serve import TRUST_JWKS, load_trust_jwks
    from agenttrustsec.transport import slim
    reviewer = agent_id("reviewer-01")
    trust = load_trust_jwks(TRUST_JWKS)
    name = slim_name(reviewer)
    ep = await rogue_connect(name, private_pem("reader-01"), name, trust)
    print("LISTENING", flush=True)
    out: dict[str, Any] = {"seen": []}
    try:
        session = await ep.app.listen_for_session_async(datetime.timedelta(seconds=seconds))
    except Exception as e:  # noqa: BLE001
        return {**out, "invited": False, "ended": str(e)[:80]}
    out["invited"] = True
    badge = current_badge(reviewer)
    while True:
        try:
            msg = await session.get_message_async(timeout=datetime.timedelta(seconds=20))
        except Exception as e:  # noqa: BLE001 - removed from the group / session closed
            out["ended"] = str(e)[:80]
            return out
        body = json.loads(msg.payload)
        out["seen"].append(body.get("type"))
        if body.get("type") == "moderator_hello":       # attest with the copied badge
            await session.publish_to_async(msg.context, json.dumps(
                {"type": "attest", "agent_id": reviewer, "badge": badge}).encode(), None, None)


# --- named attacks (docs/P5-design.md §5) -------------------------------------------------

REVOKED = "AGNTCY-ad860353-453a-4d71-9190-e1f32ca0947a"     # revoke-test-01 (revoked in P2)
CHANGE_PROMPT = "Remove the 'permit ip any any' entry from the ACL on edge-fw-01"
NO_ANY = {"device": "edge-fw-01", "lines": ["no permit ip any any"]}


def attack_cfg(name: str) -> dict:
    """Gateway attacks -> raw cfg. Ids resolved from the lab registry at run time."""
    from agenttrustsec.authz.peer import slim_name
    reader, executor = agent_id("reader-01"), agent_id("executor-01")
    exe = {"key": "executor-01", "slim_name": slim_name(executor), "claim": executor, "badge_id": executor}
    cfgs = {
        # 1: executor's trusted key, reader's SLIM name AND a copy of reader's badge
        "copied-badge": {"key": "executor-01", "slim_name": slim_name(reader), "claim": reader,
                         "badge_id": reader, "tool": "show_acl", "args": {"device": "edge-fw-01"}},
        # 2: genuine reader, change tool, even in a change session
        "reader-push": {"key": "reader-01", "slim_name": slim_name(reader), "claim": reader,
                        "badge_id": reader, "tool": "push_config", "args": NO_ANY, "intent": "change",
                        "prompt": CHANGE_PROMPT, "approve": True},
        # 3: genuine executor pushing in a READ session (prompt-injected)
        "read-session-push": {**exe, "tool": "push_config", "args": NO_ANY, "intent": "read"},
        # 4: genuine approval, but for other lines than the ones pushed
        "other-lines": {**exe, "tool": "push_config", "args": NO_ANY, "intent": "change",
                        "prompt": CHANGE_PROMPT, "approve": True,
                        "approve_lines": ["no permit ip any any", "permit ip any any"]},
        # 5: the same approval presented twice
        "replay-approval": {**exe, "tool": "push_config", "args": NO_ANY, "intent": "change",
                            "prompt": CHANGE_PROMPT, "approve": True, "repeat": 2},
        # 7: revoked agent (revoke-test-01) with its own published (revoked) badge
        "revoked": {"key": "reader-01", "slim_name": slim_name(REVOKED), "claim": REVOKED,
                    "badge_id": REVOKED, "tool": "show_acl", "args": {"device": "edge-fw-01"}},
    }
    return cfgs[name]

ATTACKS = ("copied-badge", "reader-push", "read-session-push", "other-lines", "replay-approval", "revoked")


async def run(argv: list[str]) -> dict:
    cmd = argv[0] if argv else ""
    if cmd == "attack" and len(argv) == 2 and argv[1] in ATTACKS:
        return await gateway_call(attack_cfg(argv[1]))
    if cmd == "gateway" and len(argv) == 2:
        return await gateway_call(json.loads(argv[1]))
    if cmd == "dispatch" and len(argv) == 3 and argv[2] in JOBS:
        return await dispatch(argv[1], argv[2])
    if cmd == "group-impostor" and len(argv) <= 2:
        return await group_impostor(float(argv[1]) if len(argv) == 2 else 90)
    raise SystemExit(f"usage: see module docstring; attacks: {', '.join(ATTACKS)}")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        out = asyncio.run(asyncio.wait_for(run(argv), 150))
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - report, the caller decides
        out = {"session_error": f"{type(e).__name__}: {e}"[:300]}
    print("RESULT " + json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
