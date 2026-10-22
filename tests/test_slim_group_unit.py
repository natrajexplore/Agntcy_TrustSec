"""AttestedGroup / GroupMember logic without a node (fake SLIM session)."""
import asyncio
import json
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("slim_bindings")

from agenttrustsec.authz.groups import ChannelPolicy, GroupPolicy  # noqa: E402
from agenttrustsec.identity.badge import VerifiedIdentity  # noqa: E402
from agenttrustsec.models import CheckResult, Status  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402
from agenttrustsec.transport.slim_group import (  # noqa: E402
    AttestedGroup, GroupMember, GroupNotReady, ModeratorRejected, _Member,
)

CH = "agenttrustsec/lab/reviewers"
MOD, R1, R2 = "agenttrustsec/lab/mod", "agenttrustsec/lab/r1", "agenttrustsec/lab/r2"


def msg(src, body, token="tok"):
    ctx = NS(source_name=src, metadata={slim.PEER_SUBJECT: src}, identity=token)
    return NS(context=ctx, payload=json.dumps(body).encode())


class FakeSession:
    def __init__(self, msgs=(), participants=(), list_error=None):
        self.msgs, self.participants, self.list_error = list(msgs), list(participants), list_error
        self.published, self.removed = [], []

    async def participants_list_async(self):
        if self.list_error:
            raise self.list_error
        return [NS(name=p) for p in self.participants]

    async def publish_async(self, data, pt, md):
        self.published.append(json.loads(data))

    async def remove_async(self, name):
        self.removed.append(str(name))
        return NS(wait_async=_noop)

    async def get_message_async(self, timeout):
        if self.msgs:
            return self.msgs.pop(0)
        await asyncio.sleep(timeout.total_seconds())
        raise TimeoutError

    def destination(self):
        return CH


async def _noop():
    return None


class Binding:
    def __init__(self, ok=True):
        self.ok = ok

    def check(self, peer, ident):
        return CheckResult("peer", Status.PASS if self.ok else Status.FAIL, "x")


def group(session, binding=None):
    g = AttestedGroup(NS(name=MOD, app=None, conn_id=0),
                      ChannelPolicy(CH, frozenset({"intake"}), frozenset({"reviewer"}), 1.0),
                      "mod-id", "badge", verifier=None, binding=binding or Binding(), audit=None)
    g.session = session
    g.admitted[R1] = _Member("r1-id", VerifiedIdentity("r1-id", "reviewer", "vc"), "tok")
    return g


def test_broadcast_refused_and_intruder_removed_when_live_group_differs():
    s = FakeSession(participants=[MOD, R1, R2])          # R2 never attested
    with pytest.raises(GroupNotReady, match="unattested"):
        asyncio.run(group(s).broadcast("secret"))
    assert s.published == [] and s.removed == [R2]


def test_broadcast_refused_when_membership_unreadable():
    s = FakeSession(list_error=RuntimeError("session dropped"))
    with pytest.raises(GroupNotReady, match="membership unknown"):
        asyncio.run(group(s).broadcast("secret"))
    assert s.published == []


def test_broadcast_sent_when_group_is_exactly_admitted():
    s = FakeSession(participants=[MOD, R1])
    asyncio.run(group(s).broadcast("secret"))
    assert s.published == [{"type": "broadcast", "data": "secret"}]


def test_receive_accepts_only_admitted_replies():
    s = FakeSession(msgs=[msg(R2, {"type": "reply", "data": "from outsider"}),
                          msg(R1, {"type": "attest", "data": "not a reply"}),
                          msg(R1, {"type": "reply", "data": "LGTM"})])
    assert asyncio.run(group(s).receive(2)) == ("r1-id", "LGTM")


def test_member_whose_token_no_longer_binds_is_dropped():
    s = FakeSession(msgs=[msg(R1, {"type": "reply", "data": "x"}, token="other-key")])
    g = group(s, Binding(ok=False))
    with pytest.raises(TimeoutError):
        asyncio.run(g.receive(0.5))
    assert R1 not in g.admitted and s.removed == [R1]


def test_member_refuses_group_whose_first_message_is_not_a_hello():
    s = FakeSession(msgs=[msg(MOD, {"type": "broadcast", "data": "early secret"})])
    left = []

    async def listen(timeout):
        return s

    async def delete(session):
        left.append(True)
        return NS(wait_async=_noop)
    app = NS(listen_for_session_async=listen, delete_session_async=delete)
    m = GroupMember(NS(app=app), GroupPolicy({CH: ChannelPolicy(CH, frozenset({"intake"}),
                    frozenset({"reviewer"}), 1.0)}), "r1-id", "badge", verifier=None,
                    binding=Binding())
    with pytest.raises(ModeratorRejected, match="not a moderator hello"):
        asyncio.run(m.join(1))
    assert left == [True]
