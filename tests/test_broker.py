import secrets

import pytest

from agenttrustsec.authz.broker import TokenBroker, TokenError
from agenttrustsec.models import Intent, Session

AUD = "threat-intel-api"
TOOL = "lookup_threat_intel"


@pytest.fixture
def broker():
    return TokenBroker(secrets.token_bytes(32))


def test_session_roundtrip(broker):
    s = Session("Audit the ACLs", Intent.READ)
    assert broker.open_session(broker.seal_session(s)) == s


def test_T11_session_intent_cannot_be_upgraded(broker):
    token = broker.seal_session(Session("Audit the ACLs", Intent.READ))
    other = TokenBroker(secrets.token_bytes(32))  # agent's self-made "change" session
    with pytest.raises(TokenError, match="signature"):
        broker.open_session(other.seal_session(Session("Audit the ACLs", Intent.CHANGE)))
    body, sig = token.split(".")
    with pytest.raises(TokenError):
        broker.open_session(f"{body[:-2]}AA.{sig}")


def test_expired_session(broker):
    with pytest.raises(TokenError, match="expired"):
        broker.open_session(broker.seal_session(Session("x", Intent.READ), ttl_s=-1))


def test_access_token_single_use(broker):
    t = broker.mint("reader-01", TOOL, "sid", AUD)
    assert broker.redeem(t, AUD, TOOL)["sub"] == "reader-01"
    with pytest.raises(TokenError, match="replay"):
        broker.redeem(t, AUD, TOOL)


def test_T10_token_wrong_audience_or_tool(broker):
    with pytest.raises(TokenError, match="audience"):
        broker.redeem(broker.mint("reader-01", TOOL, "sid", AUD), "cmdb-api", TOOL)
    with pytest.raises(TokenError, match="scoped"):
        broker.redeem(broker.mint("reader-01", TOOL, "sid", AUD), AUD, "export_all")


def test_access_token_expired():
    b = TokenBroker(secrets.token_bytes(32), token_ttl_s=-1)
    with pytest.raises(TokenError, match="expired"):
        b.redeem(b.mint("reader-01", TOOL, "sid", AUD), AUD, TOOL)


def test_session_token_is_not_an_access_token(broker):
    s = broker.seal_session(Session("x", Intent.READ))
    with pytest.raises(TokenError, match="expected access"):
        broker.redeem(s, AUD, TOOL)


@pytest.mark.parametrize("token", [None, "", "garbage", "a.b.c"])
def test_missing_or_malformed(broker, token):
    with pytest.raises(TokenError):
        broker.redeem(token, AUD, TOOL)
