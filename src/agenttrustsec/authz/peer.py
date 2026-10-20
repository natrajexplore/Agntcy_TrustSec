"""The `peer` check — bind the transport identity to the verified badge's key (P3).

TrustSec analogy: EAP-TLS doesn't just check the certificate chain; it checks that the
peer holds the private key (CertificateVerify) and that the cert names this endpoint.
SLIM proves "signed by SOME key in the trust JWKS" but binds neither key<->name nor
routing name<->subject (docs/P3-design.md §1). This check closes both:

  1. a transport peer is present with a signed token
  2. token `sub` == SLIM-reported subject == routing name (no spoofed sub, no relay)
  3. that name == the SLIM name of the badge's verified subject
  4. the verified badge binds a key (RFC 7638 thumbprint)
  5. the token verifies with THAT key (+ exp, nbf, iss, aud) — a copied badge or another
     trusted agent's key cannot produce it

Any failure -> FAIL; any unexpected error -> the Gate records ERROR. Both BLOCK.
"""
from __future__ import annotations

import json
from collections.abc import Callable

import jwt
from jwt.algorithms import RSAAlgorithm

from agenttrustsec.identity.badge import VerifiedIdentity
from agenttrustsec.identity.keys import jwk_thumbprint
from agenttrustsec.models import CheckResult, Status, TransportPeer

ISSUER = "agenttrustsec-lab"
AUDIENCE = "agenttrustsec"
SLIM_ORG_NS = "agenttrustsec/lab"


def slim_name(verified_id: str) -> str:
    """Our naming convention: the SLIM name of a badge subject (metadata id)."""
    return f"{SLIM_ORG_NS}/{verified_id.lower()}"


class PeerBinding:
    def __init__(self, trust_jwks: list[dict[str, str]], *, issuer: str = ISSUER,
                 audience: str = AUDIENCE, name_for: Callable[[str], str] = slim_name):
        if not trust_jwks:
            raise ValueError("empty trust JWKS — refusing (deny by default)")
        self._by_thumb = {jwk_thumbprint(k): k for k in trust_jwks}
        self.issuer = issuer
        self.audience = audience
        self.name_for = name_for

    def check(self, peer: TransportPeer | None, ident: VerifiedIdentity) -> CheckResult:
        if peer is None or not peer.token:
            return _fail("no transport identity (call did not arrive over SLIM)")
        try:
            unverified = jwt.decode(peer.token, options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            return _fail(f"peer token unreadable: {e}")
        sub = unverified.get("sub")
        if not (sub == peer.subject == peer.source_name):
            return _fail(f"identity mismatch: token sub {sub!r}, SLIM subject "
                         f"{peer.subject!r}, routing name {peer.source_name!r}")
        expected = self.name_for(ident.agent_id)
        if sub != expected:
            return _fail(f"peer {sub!r} is not the badge holder {expected!r}")
        if not ident.key_thumbprint:
            return _fail(f"badge for {ident.agent_id!r} binds no key")
        jwk = self._by_thumb.get(ident.key_thumbprint)
        if jwk is None:
            return _fail(f"badge key {ident.key_thumbprint} is not in the trust JWKS")
        try:
            jwt.decode(peer.token, RSAAlgorithm.from_jwk(json.dumps(jwk)), algorithms=["RS256"],
                       audience=self.audience, issuer=self.issuer,
                       options={"require": ["exp", "iss", "aud", "sub"]})
        except jwt.InvalidTokenError as e:
            return _fail(f"peer token not signed by the badge's key or invalid: {e}")
        return CheckResult("peer", Status.PASS,
                           f"{sub} proved possession of the key bound in badge {ident.badge_id}")


def _fail(reason: str) -> CheckResult:
    return CheckResult("peer", Status.FAIL, reason)
