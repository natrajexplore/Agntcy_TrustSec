"""SLIM<->MCP bridge without a node: peer pinning and payload handling (fake session)."""
import asyncio
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("slim_bindings")

from agenttrustsec.transport import slim  # noqa: E402

PING = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'


def msg(sub, src=None, payload=PING):
    ctx = NS(source_name=src or sub, metadata={slim.PEER_SUBJECT: sub}, identity=f"tok-{sub}")
    return NS(context=ctx, payload=payload)


class FakeSession:
    def __init__(self, msgs):
        self.msgs = list(msgs)

    async def get_message_async(self, timeout):
        if self.msgs:
            return self.msgs.pop(0)
        await asyncio.sleep(3600)


def received(msgs):
    async def go():
        out = []
        async with slim._bridge(FakeSession(msgs), pin=slim._pinner()) as (read, _):
            for _ in msgs:
                out.append(await asyncio.wait_for(read.receive(), 2))
                if isinstance(out[-1], Exception):
                    break
        return out
    return asyncio.run(go())


def test_same_peer_messages_flow():
    out = received([msg("agenttrustsec/lab/a"), msg("agenttrustsec/lab/a")])
    assert [o.message.method for o in out] == ["ping", "ping"]


@pytest.mark.parametrize("second", [msg("agenttrustsec/lab/b"),
                                    msg("agenttrustsec/lab/a", src="agenttrustsec/lab/b")])
def test_identity_switch_mid_session_drops_session(second):
    out = received([msg("agenttrustsec/lab/a"), second])
    assert isinstance(out[1], slim.PeerChanged)


def test_non_jsonrpc_payload_surfaces_as_error_not_crash():
    out = received([msg("agenttrustsec/lab/a", payload=b"not json")])
    assert isinstance(out[0], ValueError)


def test_peer_of_reads_subject_from_metadata_only():
    p = slim.peer_of(msg("agenttrustsec/lab/a", src="agenttrustsec/lab/b").context)
    assert (p.subject, p.source_name, p.token) == ("agenttrustsec/lab/a", "agenttrustsec/lab/b",
                                                   "tok-agenttrustsec/lab/a")
