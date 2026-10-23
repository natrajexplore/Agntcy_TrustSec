"""Item C: the MCPServerBadge's signed tool inventory vs what the gateway serves.
Gateway refuses to start on drift; agents refuse results for tools / args the badge doesn't sign."""
import asyncio
import json
import secrets

import pytest

from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.identity.badge import BadgeError
from agenttrustsec.mcpgate import inventory, serve
from agenttrustsec.mcpgate.client import ServerAuthError, TrustedClient
from agenttrustsec.mcpgate.server import build_server
from agenttrustsec.models import Intent, Session
from agenttrustsec.tools import netops

from conftest import ROOT

STALE = json.loads((ROOT / "tests" / "fixtures" / "netops-mcp.badge-3abc3ccf.json").read_text(encoding="utf-8"))


@pytest.fixture
def broker():
    return TokenBroker(secrets.token_bytes(32))


def gateway_tools(gate, broker):
    return asyncio.run(inventory.served(build_server("netops-mcp", gate, broker, None, serve._registry(broker))))


def test_the_2026_10_20_badge_drifted_on_review_change_only(gate, broker):
    # the CLI's signing shape (inputSchema minus top-level title) matches for the 5 unchanged tools
    assert inventory.drift(inventory.from_badge(STALE), gateway_tools(gate, broker)) == [
        "review_change changed (description, parameters)"]


def test_no_drift_when_the_badge_signs_what_is_served(gate, broker):
    serving = gateway_tools(gate, broker)
    assert inventory.drift(inventory.from_badge({"tools": inventory.to_badge_tools(serving)}), serving) == []


def test_every_kind_of_drift_is_named():
    signed = {"a": {"description": "A", "parameters": {"properties": {"x": {}}}},
              "b": {"description": "B", "parameters": {}}, "c": {"description": "C", "parameters": {}}}
    serving = {"a": {"description": "A", "parameters": {"properties": {"x": {}, "y": {}}}},
               "b": {"description": "B2", "parameters": {}}, "d": {"description": "D", "parameters": {}}}
    assert inventory.drift(signed, serving) == [
        "d not in badge", "c signed but not served", "a changed (parameters)", "b changed (description)"]


@pytest.mark.parametrize("raw", [None, {}, {"tools": "x"}, {"tools": [{"name": 1}]},
                                 {"tools": [{"name": "a"}, {"name": "a"}]}, "not json"])
def test_unreadable_inventories_are_refused(raw):
    with pytest.raises(ValueError):
        inventory.from_badge(raw)


@pytest.mark.parametrize("tool,args,why", [
    ("show_acl", {"device": "d"}, None),
    ("push_config", {"device": "d"}, "not in the server's signed inventory"),
    ("show_acl", {"device": "d", "extra": 1}, "argument(s) ['extra']"),
])
def test_vouches_for(tool, args, why):
    signed = {"show_acl": {"description": "", "parameters": {"properties": {"device": {}}}}}
    got = inventory.vouches_for(signed, tool, args)
    assert got == why if why is None else why in got
    assert "no tool inventory" in inventory.vouches_for(None, tool, args)


# --- agent side ------------------------------------------------------------------------------

def call(server, verifier, broker, tool, args):
    session = broker.seal_session(Session("Audit the ACLs on edge-fw-01", Intent.READ))

    async def go():
        from mcp import Client
        async with Client(server) as c:
            tc = TrustedClient(c, agent_id="reader-01", badge=verifier.issue("reader-01", "reader"),
                               session_token=session, verifier=verifier, server_id="netops-mcp")
            try:
                return await tc.call(tool, args)
            except Exception as e:  # noqa: BLE001 - re-raise outside the task group
                err = e
        raise err
    return asyncio.run(go())


@pytest.mark.parametrize("tools,why", [
    (None, "no tool inventory"),
    ([{"name": "show_bgp_neighbors", "description": "", "parameters": {}}], "'show_acl' is not in"),
    ([{"name": "show_acl", "description": "", "parameters": {"properties": {}}}], "argument(s) ['device']"),
    ("garbage", "carries no tool list"),
])
def test_agent_refuses_results_the_server_badge_does_not_vouch_for(gate, verifier, broker, tools, why):
    server = build_server("netops-mcp", gate, broker, verifier.issue("netops-mcp", "mcp_server", tools=tools),
                          netops.REGISTRY)
    with pytest.raises(ServerAuthError, match="not trusted") as e:
        call(server, verifier, broker, "show_acl", {"device": "edge-fw-01"})
    assert why in str(e.value)


# --- gateway side: badge selection at startup ------------------------------------------------

class FakeVerifier:
    def __init__(self, idents):
        self.idents = idents

    def verify(self, badge, server_id):
        if isinstance(self.idents[badge], Exception):
            raise self.idents[badge]
        return self.idents[badge]


def fetch(monkeypatch, vcs, idents, serving):
    import io
    from agenttrustsec.identity.badge import VerifiedIdentity
    ids = {k: (v if isinstance(v, Exception) else VerifiedIdentity("gw", "mcp_server", k, tools=v))
           for k, v in idents.items()}
    monkeypatch.setattr(serve, "AgntcyBadgeVerifier", lambda *a, **k: FakeVerifier(ids))
    monkeypatch.setattr(serve.urllib.request, "urlopen",
                        lambda *a, **k: io.BytesIO(json.dumps({"vcs": [{"value": v} for v in vcs]}).encode()))
    return serve.fetch_server_badge("http://node", "gw", serving)


def test_gateway_refuses_to_start_with_a_drifted_badge(monkeypatch, gate, broker):
    with pytest.raises(inventory.InventoryDrift, match="review_change changed"):
        fetch(monkeypatch, ["old"], {"old": STALE["tools"]}, gateway_tools(gate, broker))


def test_gateway_picks_the_badge_that_matches_whatever_the_order(monkeypatch, gate, broker):
    serving = gateway_tools(gate, broker)
    assert fetch(monkeypatch, ["old", "new"], {"old": STALE["tools"], "new": inventory.to_badge_tools(serving)},
                 serving) == "new"


def test_gateway_without_any_valid_badge_still_refuses(monkeypatch, gate, broker):
    with pytest.raises(BadgeError, match="no valid MCP server badge"):
        fetch(monkeypatch, ["x"], {"x": BadgeError("revoked")}, gateway_tools(gate, broker))
