r"""Probe: what does MessageContext.identity carry, and does SLIM JWT mode bind key->name?

Usage (repo root):
  uvx --python 3.12 --with slim-bindings==3.3.6 --with cryptography \
      python -I lab/slim/identity_probe.py <mode>
Modes:
  secret        alice+bob shared secret
  jwt           alice+bob each sign with own RSA key; verifier JWKS has both
  jwt-mallory   sender signs with a key NOT in the JWKS
  jwt-spoof     bob signs with HIS key but claims subject agntcy/ns/alice-admin
"""
import asyncio
import base64
import datetime
import json
import secrets
import sys

import slim_bindings as sb
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

EP = "http://127.0.0.1:46357"
ISS, AUD = "agenttrustsec-lab", ["agenttrustsec"]


def keypair(kid):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    n = k.public_key().public_numbers()
    b = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    return pem, {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b(n.n), "e": b(n.e)}


def jwt_cfg(pem, subject, jwks):
    enc = sb.JwtKeyConfig(algorithm=sb.JwtAlgorithm.RS256, format=sb.JwtKeyFormat.PEM,
                          key=sb.JwtKeyData.DATA(value=pem))
    dec = sb.JwtKeyConfig(algorithm=sb.JwtAlgorithm.RS256, format=sb.JwtKeyFormat.JWKS,
                          key=sb.JwtKeyData.DATA(value=json.dumps({"keys": jwks})))
    hour = datetime.timedelta(seconds=3600)
    prov = sb.IdentityProviderConfig.JWT(config=sb.ClientJwtAuth(
        key=sb.JwtKeyType.ENCODING(key=enc), audience=AUD, issuer=ISS, subject=subject, duration=hour))
    ver = sb.IdentityVerifierConfig.JWT(config=sb.JwtAuth(
        key=sb.JwtKeyType.DECODING(key=dec), audience=AUD, issuer=ISS, subject=None, duration=hour))
    return prov, ver


async def main(mode):
    sb.initialize_with_configs(tracing_config=sb.new_tracing_config(),
                               runtime_config=sb.new_runtime_config(),
                               service_config=[sb.new_service_config()])
    svc = sb.get_global_service()
    conn = await svc.connect_async(sb.new_insecure_client_config(EP))
    alice_n, bob_n = sb.Name.from_string("agntcy/ns/alice"), sb.Name.from_string("agntcy/ns/bob")

    if mode == "secret":
        s = secrets.token_hex(16)
        alice, bob = svc.create_app_with_secret(alice_n, s), svc.create_app_with_secret(bob_n, s)
    else:
        a_pem, a_jwk = keypair("alice-key")
        b_pem, b_jwk = keypair("bob-key")
        m_pem, _ = keypair("mallory-key")
        jwks = [a_jwk, b_jwk]
        alice = svc.create_app(alice_n, *jwt_cfg(a_pem, "agntcy/ns/alice", jwks))
        sender_pem, sender_sub = {
            "jwt": (b_pem, "agntcy/ns/bob"),
            "jwt-mallory": (m_pem, "agntcy/ns/bob"),
            "jwt-spoof": (b_pem, "agntcy/ns/alice-admin"),
        }[mode]
        bob = svc.create_app(bob_n, *jwt_cfg(sender_pem, sender_sub, jwks))

    for app, n in ((alice, alice_n), (bob, bob_n)):
        await app.subscribe_async(n, conn)
    await bob.set_route_async(alice_n, conn)

    async def listen():
        sess = await alice.listen_for_session_async(None)
        msg = await sess.get_message_async(timeout=datetime.timedelta(seconds=20))
        c = msg.context
        print(f"[alice] payload={msg.payload.decode()!r}")
        print(f"[alice] source_name={'/'.join(c.source_name.components()) if hasattr(c.source_name,'components') else c.source_name}")
        print(f"[alice] identity={c.identity[:400]!r}")
        print(f"[alice] metadata={c.metadata}")
        await sess.publish_async(b"ack", None, None)

    t = asyncio.create_task(listen())
    cfg = sb.SessionConfig(session_type=sb.SessionType.POINT_TO_POINT, max_retries=2,
                           interval=datetime.timedelta(seconds=3), metadata={},
                           mls_settings=sb.MlsSettings(header_integrity_validation_percent=100,
                                                       max_seen_control_message_ids_size=None))
    try:
        sc = await bob.create_session_async(cfg, alice_n)
        await sc.completion.wait_async()
        await sc.session.publish_async(b"hello from sender", None, None)
        r = await sc.session.get_message_async(timeout=datetime.timedelta(seconds=20))
        print(f"[bob] got {r.payload.decode()!r}  identity seen by bob={r.context.identity[:200]!r}")
        await asyncio.wait_for(t, 5)
        print("RESULT: ACCEPTED")
    except Exception as e:
        print(f"RESULT: REJECTED -> {str(e)[:200]}")
        t.cancel()


asyncio.run(main(sys.argv[1]))
