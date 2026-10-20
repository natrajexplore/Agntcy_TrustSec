"""RFC 7638 thumbprints — the value the issuer signs into each AgentBadge."""
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agenttrustsec.identity.keys import jwk_thumbprint, public_jwk

# RFC 7638 §3.1 example key and its published thumbprint.
RFC_N = ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJE"
         "CPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
         "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6"
         "WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
RFC_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_rfc7638_vector():
    assert jwk_thumbprint({"kty": "RSA", "n": RFC_N, "e": "AQAB", "alg": "RS256",
                           "kid": "2011-04-29"}) == RFC_THUMBPRINT


def test_thumbprint_differs_per_key():
    a, b = (public_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
            for _ in range(2))
    assert jwk_thumbprint(a) != jwk_thumbprint(b)


@pytest.mark.parametrize("jwk", [{}, {"kty": "EC", "x": "a", "y": "b"}, {"kty": "RSA", "n": "x"}])
def test_rejects_non_rsa_or_incomplete(jwk):
    with pytest.raises(ValueError):
        jwk_thumbprint(jwk)
