import secrets

import pytest

from agenttrustsec.identity.badge import BadgeError, LocalDevVerifier


def test_valid_badge_yields_role(verifier):
    b = verifier.issue("reader-01", "reader")
    ident = verifier.verify(b, "reader-01")
    assert ident.role == "reader"


@pytest.mark.parametrize("badge", [None, "", "not-a-badge", "a.b.c"])
def test_missing_or_malformed(verifier, badge):
    with pytest.raises(BadgeError):
        verifier.verify(badge, "reader-01")


def test_forged_signature(verifier):
    other = LocalDevVerifier(secrets.token_bytes(32))
    with pytest.raises(BadgeError, match="signature"):
        verifier.verify(other.issue("executor-01", "executor"), "executor-01")


def test_tampered_payload(verifier):
    b = verifier.issue("reader-01", "reader")
    body, sig = b.split(".")
    tampered = body[:-2] + ("AA" if body[-2:] != "AA" else "BB")
    with pytest.raises(BadgeError):
        verifier.verify(f"{tampered}.{sig}", "reader-01")


def test_subject_mismatch_stolen_badge(verifier):
    b = verifier.issue("executor-01", "executor")
    with pytest.raises(BadgeError, match="subject mismatch"):
        verifier.verify(b, "rogue-99")


def test_expired(verifier):
    b = verifier.issue("reader-01", "reader", ttl_s=-1)
    with pytest.raises(BadgeError, match="expired"):
        verifier.verify(b, "reader-01")


def test_revoked(verifier):
    b = verifier.issue("executor-00", "executor", badge_id="old")
    verifier.revoke("old")
    with pytest.raises(BadgeError, match="revoked"):
        verifier.verify(b, "executor-00")


def test_short_secret_rejected():
    with pytest.raises(ValueError):
        LocalDevVerifier(b"short")
