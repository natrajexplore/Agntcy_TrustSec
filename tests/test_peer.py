"""The `peer` check: transport identity must hold the key the verified badge binds (P3).
Tokens are shaped like SLIM's JWT identity (header kid = sub; iss/sub/aud/exp/iat/nbf).
These must never be loosened."""
import json
import time
from types import SimpleNamespace as NS

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.peer import PeerBinding, slim_name
from agenttrustsec.identity.agntcy import (
    AgntcyBadgeVerifier, _badge_thumbprint, load_key_thumbprints,
)
from agenttrustsec.identity.badge import BadgeError, VerifiedIdentity
from agenttrustsec.identity.keys import THUMBPRINT_ANNOTATION, jwk_thumbprint, public_jwk
from agenttrustsec.models import Status, ToolCall, TransportPeer, Verdict

MID = "AGNTCY-13cbc3cf-89ae-43d6-b5b4-b0681092b8fb"
NAME = slim_name(MID)


def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k, public_jwk(k.public_key())


READER_KEY, READER_JWK = key()
OTHER_KEY, OTHER_JWK = key()          # another TRUSTED agent's key
TRUST = [READER_JWK, OTHER_JWK]
THUMB = jwk_thumbprint(READER_JWK)


def token(signer=READER_KEY, sub=NAME, iss="agenttrustsec-lab", aud=("agenttrustsec",),
          exp_in=3600):
    now = int(time.time())
    return jwt.encode({"iss": iss, "sub": sub, "aud": list(aud), "iat": now, "nbf": now,
                       "exp": now + exp_in}, signer, algorithm="RS256", headers={"kid": sub})


def peer(tok=None, subject=NAME, source=NAME):
    return TransportPeer(source_name=source, subject=subject, token=token() if tok is None else tok)


IDENT = VerifiedIdentity(agent_id=MID, role="reader", badge_id="vc-1", key_thumbprint=THUMB)
binding = PeerBinding(TRUST)


def test_holder_of_badge_key_passes():
    r = binding.check(peer(), IDENT)
    assert r.status is Status.PASS and "proved possession" in r.reason


@pytest.mark.parametrize("p,match", [
    (None, "no transport identity"),
    (TransportPeer(NAME, NAME, ""), "no transport identity"),
    (peer(tok="not.a.jwt"), "unreadable"),
    # SLIM accepts this (P3-design §1): trusted key, token claims another name
    (peer(tok=token(sub="agenttrustsec/lab/executor-admin"), subject="agenttrustsec/lab/executor-admin"),
     "identity mismatch"),
    (peer(subject="agenttrustsec/lab/someone"), "identity mismatch"),          # SLIM metadata disagrees
    (peer(source="agenttrustsec/lab/relay"), "identity mismatch"),            # routed from elsewhere
    # another trusted agent presents the reader's (copied) badge under its own SLIM name
    (peer(tok=token(signer=OTHER_KEY, sub="agenttrustsec/lab/other"),
          subject="agenttrustsec/lab/other", source="agenttrustsec/lab/other"), "not the badge holder"),
    # copied badge, attacker claims the right name but signs with its own trusted key
    (peer(tok=token(signer=OTHER_KEY)), "not signed by the badge's key"),
    (peer(tok=token(exp_in=-10)), "not signed by the badge's key or invalid"),
    (peer(tok=token(iss="evil")), "invalid"),
    (peer(tok=token(aud=("other",))), "invalid"),
])
def test_peer_failures(p, match):
    r = binding.check(p, IDENT)
    assert r.status is Status.FAIL and match in r.reason


def test_badge_without_key_fails():
    r = binding.check(peer(), VerifiedIdentity(MID, "reader", "vc-1", key_thumbprint=None))
    assert r.status is Status.FAIL and "binds no key" in r.reason


def test_badge_key_outside_trust_jwks_fails():
    r = PeerBinding([OTHER_JWK]).check(peer(), IDENT)
    assert r.status is Status.FAIL and "not in the trust JWKS" in r.reason


def test_empty_trust_refused():
    with pytest.raises(ValueError, match="empty trust"):
        PeerBinding([])


# --- Gate integration ------------------------------------------------------------------

class FixedVerifier:
    def __init__(self, ident):
        self.ident = ident

    def verify(self, badge, claimed):
        if badge != "good":
            raise BadgeError("bad badge")
        return self.ident


def gate(policy, audit, ident=IDENT):
    return Gate(FixedVerifier(ident), policy, BaselineIntentChecker(), audit, peer=binding)


def call(read_session, p, badge="good"):
    return ToolCall(MID, badge, "show_acl", read_session, {"device": "edge-fw-01"}, peer=p)


def test_gate_allows_bound_peer_and_audits_it(policy, audit, read_session):
    d = gate(policy, audit).authorize(call(read_session, peer()))
    assert d.verdict is Verdict.ALLOW
    assert [c.name for c in d.checks] == ["badge", "peer", "tbac", "intent"]
    rec, = audit.read_all()
    assert rec["peer"] == {"source_name": NAME, "subject": NAME}
    assert "token" not in json.dumps(rec)                 # the peer's token is never audited


@pytest.mark.parametrize("p", [None, peer(tok=token(signer=OTHER_KEY))])
def test_gate_blocks_unbound_peer_and_drops_role(policy, audit, read_session, p):
    d = gate(policy, audit).authorize(call(read_session, p))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "peer"
    assert d.verified_role is None
    assert [c.status for c in d.checks[2:]] == [Status.SKIPPED, Status.SKIPPED]


def test_gate_peer_skipped_when_badge_fails(policy, audit, read_session):
    d = gate(policy, audit).authorize(call(read_session, peer(), badge="forged"))
    assert d.blocked_by == "badge" and d.checks[1].status is Status.SKIPPED


def test_gate_peer_error_blocks(policy, audit, read_session):
    class Boom(PeerBinding):
        def check(self, p, ident):
            raise RuntimeError("boom")
    g = Gate(FixedVerifier(IDENT), policy, BaselineIntentChecker(), audit, peer=Boom(TRUST))
    d = g.authorize(call(read_session, peer()))
    assert d.verdict is Verdict.BLOCK and d.checks[1].status is Status.ERROR


# --- Verifier: which key does a verified badge bind? ------------------------------------

def content(annotations):
    return {"id": MID, "badge": json.dumps({"name": "agenttrustsec/reader-01",
                                            "annotations": annotations})}


def test_thumbprint_read_from_signed_badge():
    assert _badge_thumbprint(content({THUMBPRINT_ANNOTATION: THUMB})) == THUMB


@pytest.mark.parametrize("c", [content({}), {"id": MID}, {"id": MID, "badge": "not json"},
                               {"id": MID, "badge": "[]"}, content({THUMBPRINT_ANNOTATION: ""})])
def test_no_thumbprint_means_no_key(c):
    assert _badge_thumbprint(c) is None


def verifier_with(annotations, key_map=None):
    doc = NS(type=["AgentBadge"], content=content(annotations), expiration_date="", id="vc-1")
    res = NS(status=True, document=doc, errors=[], warnings=[])
    pub = "h." + __import__("base64").urlsafe_b64encode(b'{"id":"vc-1"}').decode().rstrip("=") + ".s"
    return AgntcyBadgeVerifier({MID: "reader"}, node=lambda j: res, published=lambda s: [pub],
                               key_thumbprints=key_map)


def test_verifier_returns_badge_bound_key():
    assert verifier_with({THUMBPRINT_ANNOTATION: THUMB}).verify("jose", MID).key_thumbprint == THUMB


def test_verifier_uses_d2_table_only_when_badge_has_no_key():
    assert verifier_with({}, {MID: THUMB}).verify("jose", MID).key_thumbprint == THUMB


def test_verifier_rejects_conflicting_key_sources():
    with pytest.raises(BadgeError, match="key conflict"):
        verifier_with({THUMBPRINT_ANNOTATION: THUMB}, {MID: "different"}).verify("jose", MID)


def test_key_table_rejects_wildcards(tmp_path):
    f = tmp_path / "ids.yaml"
    f.write_text("key_thumbprints:\n  '*': abc\n")
    with pytest.raises(ValueError, match="wildcard"):
        load_key_thumbprints(f)
