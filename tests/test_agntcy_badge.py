"""AgntcyBadgeVerifier against a fake Identity Node shaped like the SDK's
VerificationResult (agntcy-identity-sdk 0.0.26). These must never be loosened."""
import base64
import json
from types import SimpleNamespace as NS

import pytest

from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.identity.agntcy import (
    MCP_SERVER_BADGE, REVOKED, AgntcyBadgeVerifier, load_role_map,
)
from agenttrustsec.identity.badge import BadgeError
from agenttrustsec.models import Status, ToolCall, Verdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ROLES = {"reader-01": "reader", "executor-01": "executor"}


def result(subject="reader-01", status=True, types=("VerifiableCredential", "AgentBadge"),
           exp="2999-01-01T00:00:00Z", errors=(), warnings=(), vc_id="vc-1"):
    doc = NS(type=list(types), content={"id": subject, "badge": "{}"},
             expiration_date=exp, id=vc_id)
    return NS(status=status, document=doc, errors=list(errors), warnings=list(warnings))


def jose_of(vc: dict) -> str:
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc(vc)}.sig"


PUBLISHED_OK = [jose_of({"id": "vc-1"})]


def verifier(res, roles=ROLES, published=None, **kw):
    pub = PUBLISHED_OK if published is None else published
    return AgntcyBadgeVerifier(roles, node=lambda jose: res,
                               published=pub if callable(pub) else (lambda subject: pub), **kw)


def test_valid_badge_role_from_map():
    ident = verifier(result()).verify("jose", "reader-01")
    assert (ident.agent_id, ident.role, ident.badge_id) == ("reader-01", "reader", "vc-1")


def test_T3_revoked_is_rejected_even_with_document():
    # Node returns status=False, document filled, reason in warnings.
    revoked = result(status=False, warnings=[NS(message="The Verifiable Credential is revoked.")])
    with pytest.raises(BadgeError, match="revoked"):
        verifier(revoked).verify("jose", "reader-01")


@pytest.mark.parametrize("kw", [
    {"status": False},
    {"errors": [NS(message="signature invalid")]},
    {"warnings": [NS(message="something odd")]},
])
def test_any_node_complaint_rejected(kw):
    with pytest.raises(BadgeError):
        verifier(result(**kw)).verify("jose", "reader-01")


def test_T2_status_must_be_literally_true():
    with pytest.raises(BadgeError):
        verifier(result(status="true")).verify("jose", "reader-01")


def test_stolen_badge_subject_mismatch():
    with pytest.raises(BadgeError, match="subject mismatch"):
        verifier(result(subject="executor-01")).verify("jose", "rogue-99")


def test_mcp_badge_cannot_act_as_agent_and_vice_versa():
    mcp = result(types=("VerifiableCredential", MCP_SERVER_BADGE))
    with pytest.raises(BadgeError, match="expected AgentBadge"):
        verifier(mcp).verify("jose", "reader-01")
    with pytest.raises(BadgeError, match="expected MCPServerBadge"):
        verifier(result(), badge_type=MCP_SERVER_BADGE).verify("jose", "reader-01")


@pytest.mark.parametrize("exp,match", [
    ("2000-01-01T00:00:00Z", "expired"),
    ("not-a-date", "unreadable"),
    ("2999-01-01T00:00:00", "expired"),  # naive timestamp -> fail closed
])
def test_expiry_enforced_locally(exp, match):
    with pytest.raises(BadgeError, match=match):
        verifier(result(exp=exp)).verify("jose", "reader-01")


def test_unmapped_identity_gets_no_role():
    with pytest.raises(BadgeError, match="no role mapped"):
        verifier(result(subject="intern-07")).verify("jose", "intern-07")


@pytest.mark.parametrize("badge", [None, ""])
def test_no_badge(badge):
    with pytest.raises(BadgeError, match="no badge"):
        verifier(result()).verify(badge, "reader-01")


def test_node_unreachable_blocks_via_gate(policy, audit, read_session):
    def down(jose):
        raise ConnectionError("identity node unreachable")
    g = Gate(AgntcyBadgeVerifier(ROLES, node=down, published=lambda s: PUBLISHED_OK),
             policy, BaselineIntentChecker(), audit)
    d = g.authorize(ToolCall("reader-01", "jose", "show_acl", read_session,
                             {"device": "edge-fw-01"}))
    assert d.verdict is Verdict.BLOCK and d.checks[0].status is Status.ERROR


def test_gate_end_to_end_with_agntcy_verifier(policy, audit, read_session):
    g = Gate(verifier(result()), policy, BaselineIntentChecker(), audit)
    d = g.authorize(ToolCall("reader-01", "jose", "show_acl", read_session,
                             {"device": "edge-fw-01"}))
    assert d.verdict is Verdict.ALLOW and d.verified_role == "reader"


def test_T3_revoked_at_node_but_holder_presents_original_copy():
    # The gap proven live: node Verify says status=True for the pre-revocation copy,
    # but the node's published copy of the same VC id carries REVOCATION status.
    revoked = [jose_of({"id": "vc-1", "credentialStatus": [{"purpose": REVOKED}]})]
    with pytest.raises(BadgeError, match="revoked"):
        verifier(result(), published=revoked).verify("jose", "reader-01")


@pytest.mark.parametrize("published,match", [
    ([], "not published"),
    ([jose_of({"id": "vc-other"})], "not published"),
    (["not-a-jose"], "unreadable"),
    (["a.!!!.c"], "unreadable"),
])
def test_published_status_must_be_proven(published, match):
    with pytest.raises(BadgeError, match=match):
        verifier(result(), published=published).verify("jose", "reader-01")


def test_badge_without_vc_id_cannot_match_published_copy():
    with pytest.raises(BadgeError, match="not published"):
        verifier(result(vc_id=""), published=[jose_of({"id": ""})]).verify("jose", "reader-01")


def test_status_lookup_failure_blocks_via_gate(policy, audit, read_session):
    def down(subject):
        raise ConnectionError("identity node unreachable")
    g = Gate(verifier(result(), published=down), policy, BaselineIntentChecker(), audit)
    d = g.authorize(ToolCall("reader-01", "jose", "show_acl", read_session,
                             {"device": "edge-fw-01"}))
    assert d.verdict is Verdict.BLOCK and d.checks[0].status is Status.ERROR


def test_no_partial_node_wiring():
    with pytest.raises(ValueError, match="both"):
        AgntcyBadgeVerifier(ROLES, node=lambda jose: result())


def test_role_map_file_loads_and_rejects_wildcards(tmp_path):
    roles = load_role_map(ROOT / "policies" / "identities.yaml", "agents")
    assert roles["AGNTCY-13cbc3cf-89ae-43d6-b5b4-b0681092b8fb"] == "reader"
    bad = tmp_path / "ids.yaml"
    bad.write_text("agents:\n  '*': executor\n")
    with pytest.raises(ValueError, match="wildcard"):
        load_role_map(bad, "agents")
