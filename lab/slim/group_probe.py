"""Probe SLIM GROUP sessions with MLS for the P3 PR5 design (reviewer pool). LAB ONLY.

    python lab/slim/group_probe.py          # needs the lab SLIM node (lab/slim/)

One process, fresh names per run, JWT identity with a fresh key per app. Moderator M
creates a GROUP session on channel C (MLS on) and invites R1, R2. Questions answered:
  Q1 do invited members get broadcasts, and which sender identity do they see?
  Q2 does an UNINVITED app with a TRUSTED key (O) see anything — even subscribed to C?
  Q3 can a non-moderator (R1) invite (R3) or remove (R2)?
  Q4 after M removes R2, does R2 still receive?
  Q5 can M invite an app whose key is NOT in the trust JWKS (X)?
  Q6 what does participants_list report?
  Q7 an IMPOSTOR registers name r4 with r3's TRUSTED key; M invites "r4" — does it join and
     read? Can M tell from the impostor's token which key really signed?
"""
import asyncio
import datetime
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from agenttrustsec.identity.keys import trust_jwk  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402

sb = slim.sb
TAG = uuid.uuid4().hex[:6]
NS = f"agenttrustsec/probe{TAG}"
SECONDS = datetime.timedelta(seconds=2)


def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return pem, trust_jwk(k.public_key())


async def main():
    keys = {n: key() for n in ("m", "r1", "r2", "r3", "o", "x")}
    keys["r4"] = keys["r3"]                                   # Q7 impostor: r3's key, r4's name
    trust = [keys[n][1] for n in ("m", "r1", "r2", "r3", "o")]          # x is NOT trusted
    apps = {}
    for n, (pem, _) in keys.items():
        name = f"{NS}/{n}"
        apps[n] = await slim.connect(name, slim.jwt_identity(pem, name, trust))
    channel = sb.Name.from_string(f"{NS}/reviewers")
    got: dict[str, list[str]] = {n: [] for n in apps}
    sessions: dict[str, object] = {}

    async def member(n):
        s = await apps[n].app.listen_for_session_async(None)
        sessions[n] = s
        while True:
            try:
                m = await s.get_message_async(timeout=datetime.timedelta(seconds=60))
            except Exception as e:  # noqa: BLE001
                got[n].append(f"<closed: {str(e)[:40]}>")
                return
            got[n].append(f"{m.payload.decode()} from {m.context.metadata.get('slim-peer-subject','?').split('/')[-1]}")

    listeners = {n: asyncio.create_task(member(n)) for n in ("r1", "r2", "r3", "o", "x", "r4")}
    # Q2 extra: outsider O also subscribes to the channel name itself
    await apps["o"].app.subscribe_async(channel, apps["o"].conn_id)

    m = apps["m"]
    cfg = sb.SessionConfig(session_type=sb.SessionType.GROUP, max_retries=3, interval=SECONDS,
                           metadata={}, mls_settings=sb.MlsSettings(
                               header_integrity_validation_percent=100,
                               max_seen_control_message_ids_size=None))
    ctx = await m.app.create_session_async(cfg, channel)
    await ctx.completion.wait_async()
    group = ctx.session

    async def invite(by_session, by_app, who):
        name = sb.Name.from_string(f"{NS}/{who}")
        await by_app.app.set_route_async(name, by_app.conn_id)
        h = await by_session.invite_async(name)
        await h.wait_async()

    for who in ("r1", "r2"):
        await invite(group, m, who)
    await asyncio.sleep(1)
    plist = await group.participants_list_async()
    print("Q6 participants after invites:", [str(p) for p in plist][:6])

    await group.publish_async(b"msg1", None, None)
    await asyncio.sleep(1.5)
    if "r1" in sessions:
        await sessions["r1"].publish_async(b"msg2-from-r1", None, None)
    await asyncio.sleep(1.5)

    # Q3 non-moderator invite / remove
    for label, op in (("R1 invites R3", lambda: invite(sessions["r1"], apps["r1"], "r3")),
                      ("R1 removes R2", lambda: sessions["r1"].remove_async(sb.Name.from_string(f"{NS}/r2")))):
        try:
            r = await asyncio.wait_for(op(), 15)
            if r is not None and hasattr(r, "wait_async"):
                await asyncio.wait_for(r.wait_async(), 15)
            print(f"Q3 {label}: SUCCEEDED")
        except Exception as e:  # noqa: BLE001
            print(f"Q3 {label}: refused -> {type(e).__name__}: {str(e)[:120]}")

    # Q4 remove R2 then broadcast
    h = await group.remove_async(sb.Name.from_string(f"{NS}/r2"))
    await h.wait_async()
    await asyncio.sleep(1)
    await group.publish_async(b"msg3-after-r2-removed", None, None)
    await asyncio.sleep(2)

    # Q5 invite an untrusted key
    try:
        await asyncio.wait_for(invite(group, m, "x"), 30)
        print("Q5 invite untrusted X: SUCCEEDED")
    except Exception as e:  # noqa: BLE001
        print(f"Q5 invite untrusted X: refused -> {type(e).__name__}: {str(e)[:120]}")
    await group.publish_async(b"msg4", None, None)
    await asyncio.sleep(2)

    # Q7 impostor admission
    try:
        await asyncio.wait_for(invite(group, m, "r4"), 30)
        print("Q7 invite 'r4' (impostor holding r3's key): SUCCEEDED")
    except Exception as e:  # noqa: BLE001
        print(f"Q7 invite 'r4': refused -> {type(e).__name__}: {str(e)[:120]}")
    await asyncio.sleep(1)
    await group.publish_async(b"msg5-secret-review", None, None)
    await asyncio.sleep(1.5)
    if "r4" in sessions:
        await sessions["r4"].publish_async(b"hello-from-r4", None, None)
        try:
            while True:                       # skip earlier queued broadcasts
                msg = await group.get_message_async(timeout=datetime.timedelta(seconds=10))
                if msg.payload == b"hello-from-r4":
                    break
            import jwt
            from jwt.algorithms import RSAAlgorithm
            import json as _j
            signer = "?"
            for n, (_, jwk) in keys.items():
                try:
                    jwt.decode(msg.context.identity, RSAAlgorithm.from_jwk(_j.dumps(jwk)),
                               algorithms=["RS256"], options={"verify_aud": False})
                    signer = n
                    break
                except jwt.InvalidTokenError:
                    pass
            print(f"Q7 M sees '{msg.payload.decode()}' sub={msg.context.metadata.get('slim-peer-subject')} "
                  f"-> token actually signed by the key of: {signer}")
        except Exception as e:  # noqa: BLE001
            print(f"Q7 M got no message from r4: {e}")

    plist = await group.participants_list_async()
    print("Q6 participants at end:", [str(p) for p in plist][:6])
    for n in ("r1", "r2", "r3", "o", "x", "r4"):
        print(f"RECV {n:<3} {got[n]}")
    for t in listeners.values():
        t.cancel()


asyncio.run(asyncio.wait_for(main(), 180))
