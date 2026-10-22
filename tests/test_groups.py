"""Group admission (P3 PR5): policy loader + the admit() decision. Must never be loosened."""
import pytest

from agenttrustsec.authz.groups import ChannelPolicy, GroupPolicy, GroupPolicyError, admit
from agenttrustsec.identity.badge import BadgeError, VerifiedIdentity
from agenttrustsec.models import Status, TransportPeer, Verdict

from conftest import ROOT
from test_peer import MID, NAME, OTHER_KEY, THUMB, binding, peer, token

POLICY = ChannelPolicy("agenttrustsec/lab/reviewers", frozenset({"intake"}),
                       frozenset({"reviewer"}), 10.0)


class Verifier:
    def __init__(self, role="reviewer", fail=None):
        self.role, self.fail = role, fail

    def verify(self, badge, claimed):
        if self.fail:
            raise self.fail
        return VerifiedIdentity(MID, self.role, "vc-1", key_thumbprint=THUMB)


def run(verifier=None, p=None, *, as_moderator=False, expected=NAME):
    return admit(POLICY, as_moderator=as_moderator, verifier=verifier or Verifier(),
                 binding=binding, claimed_id=MID, badge="jose",
                 peer=peer() if p is None else p, expected_name=expected)


def test_genuine_reviewer_admitted():
    d, ident = run()
    assert d.verdict is Verdict.ALLOW and ident.role == "reviewer"
    assert [c.name for c in d.checks] == ["badge", "peer", "group"]
    assert d.call.tool == "group.join" and d.call.args == {"channel": POLICY.channel}


@pytest.mark.parametrize("kw,blocked_by,match", [
    ({"verifier": Verifier(fail=BadgeError("badge 'vc-1' revoked"))}, "badge", "revoked"),
    ({"verifier": Verifier(fail=RuntimeError("node down"))}, "badge", "RuntimeError"),
    # Q7: another trusted key answering under the invited name with a copied badge
    ({"p": peer(tok=token(signer=OTHER_KEY))}, "peer", "not signed by the badge's key"),
    ({"verifier": Verifier(role="executor")}, "group", "may not join"),
    ({"expected": "agenttrustsec/lab/someone-else"}, "group", "invited as"),
])
def test_admission_refusals(kw, blocked_by, match):
    d, ident = run(**kw)
    assert d.verdict is Verdict.BLOCK and ident is None
    assert d.blocked_by == blocked_by
    assert match in next(c.reason for c in d.checks if c.name == blocked_by)


def test_no_transport_identity_refused():
    d, _ = admit(POLICY, as_moderator=False, verifier=Verifier(), binding=binding,
                 claimed_id=MID, badge="jose", peer=None, expected_name=NAME)
    assert d.blocked_by == "peer"


def test_moderator_needs_moderator_role():
    assert run(Verifier(role="intake"), as_moderator=True, expected=None)[0].verdict is Verdict.ALLOW
    d, _ = run(Verifier(role="reviewer"), as_moderator=True, expected=None)
    assert d.blocked_by == "group" and "may not moderate" in d.checks[2].reason


def test_skips_after_failure():
    d, _ = run(Verifier(fail=BadgeError("nope")))
    assert [c.status for c in d.checks[1:]] == [Status.SKIPPED, Status.SKIPPED]


def test_audit_record_shape_has_peer_not_token():
    rec = run()[0].to_audit_record()
    assert rec["tool"] == "group.join" and rec["peer"] == {"source_name": NAME, "subject": NAME}
    assert "eyJ" not in str(rec)


# --- policy file -------------------------------------------------------------------------

def test_repo_policy_loads():
    ch = GroupPolicy.from_yaml(ROOT / "policies" / "groups.yaml").channel("agenttrustsec/lab/reviewers")
    assert ch.moderator_roles == {"intake"} and ch.member_roles == {"reviewer"}


def test_unknown_channel_denied():
    with pytest.raises(GroupPolicyError, match="not in the group policy"):
        GroupPolicy({}).channel("agenttrustsec/lab/anything")


@pytest.mark.parametrize("body,match", [
    ("channels:\n  c:\n    member_roles: ['*']\n", "wildcard"),
    ("channels:\n  any:\n    member_roles: [reviewer]\n", "wildcard"),
    ("channels:\n  c:\n    member_roles: [reviewer]\n    attest_timeout_s: 0\n", "attest_timeout_s"),
    ("channels: [c]\n", "mapping"),
])
def test_bad_policy_rejected(tmp_path, body, match):
    f = tmp_path / "groups.yaml"
    f.write_text(body)
    with pytest.raises(GroupPolicyError, match=match):
        GroupPolicy.from_yaml(f)


def test_empty_roles_admit_no_one():
    ch = ChannelPolicy("c", frozenset(), frozenset(), 10.0)
    d, _ = admit(ch, as_moderator=False, verifier=Verifier(), binding=binding, claimed_id=MID,
                 badge="jose", peer=TransportPeer(NAME, NAME, token()), expected_name=NAME)
    assert d.blocked_by == "group"
