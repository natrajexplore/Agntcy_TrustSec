"""MCP threat-model tests (docs/ARCHITECTURE.md §4, T5 and T9–T11 over MCP).

Real `mcp` 2.x client <-> server, connected in-process. These must never be loosened.
"""
import asyncio
import json
import secrets

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError

from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.identity.badge import LocalDevVerifier
from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError, TrustedClient
from agenttrustsec.mcpgate.server import (
    META_AGENT, META_BADGE, META_DECISION, META_SESSION, build_server,
)
from agenttrustsec.models import Intent, Session
from agenttrustsec.tools import extdata, netops

SERVER_ID = "netops-mcp"
PUSH = {"device": "edge-fw-01", "lines": ["permit ip any any"]}


@pytest.fixture
def broker():
    return TokenBroker(secrets.token_bytes(32))


@pytest.fixture
def intel(broker):
    return extdata.ThreatIntelAPI(broker)


@pytest.fixture
def server(gate, broker, verifier, intel):
    badge = verifier.issue(SERVER_ID, "mcp_server")
    return build_server(SERVER_ID, gate, broker, badge,
                        {**netops.REGISTRY, **extdata.make_registry(intel)})


def run(coro):
    return asyncio.run(coro)


async def _call(server, verifier, broker, session, agent_id, role, tool, args,
                badge="valid", server_id=SERVER_ID):
    b = verifier.issue(agent_id, role) if badge == "valid" else badge
    token = session if isinstance(session, str) else broker.seal_session(session)
    async with Client(server) as c:
        tc = TrustedClient(c, agent_id=agent_id, badge=b, session_token=token,
                           verifier=verifier, server_id=server_id)
        try:
            return await tc.call(tool, args)
        except Exception as e:  # re-raise outside the client's task group
            err = e
    raise err


READ = Session("Audit the ACLs on edge-fw-01 and check the threat intel reputation of "
               "203.0.113.66", Intent.READ)


def test_happy_path_read_over_mcp(server, verifier, broker, audit):
    r = run(_call(server, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))
    assert not r.is_error
    assert [x["verdict"] for x in audit.read_all()] == ["ALLOW"]


def test_T5_executor_push_during_read_session_over_mcp(server, verifier, broker):
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, READ, "executor-01", "executor",
                  "push_config", PUSH))
    assert e.value.blocked_by == "intent"
    assert netops.PUSHED == []


@pytest.mark.parametrize("badge", [None, "forged"])
def test_T1_T2_bad_agent_badge_over_mcp(server, verifier, broker, badge):
    if badge == "forged":
        badge = LocalDevVerifier(secrets.token_bytes(32)).issue("executor-01", "executor")
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, READ, "executor-01", "executor",
                  "show_acl", {"device": "edge-fw-01"}, badge=badge))
    assert e.value.blocked_by == "badge"


def test_T11_self_upgraded_session_blocked(server, verifier, broker, audit):
    forged = TokenBroker(secrets.token_bytes(32)).seal_session(
        Session("Push permit any any to edge-fw-01", Intent.CHANGE))
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, forged, "executor-01", "executor",
                  "push_config", PUSH))
    assert e.value.blocked_by == "session"
    assert netops.PUSHED == []
    rec, = audit.read_all()
    assert rec["verdict"] == "BLOCK" and rec["blocked_by"] == "session"


def test_T11_missing_session_blocked(server, verifier, broker):
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, "", "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))
    assert e.value.blocked_by == "session"


def test_T6_external_lookup_of_unnamed_ip_blocked_by_scope(server, verifier, broker, intel):
    # P4b: the request never names this IP, so the agent may not look it up (T6)
    unnamed = Session("Audit the ACLs on edge-fw-01 and check threat intel reputation", Intent.READ)
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, unnamed, "reader-01", "reader",
                  "lookup_threat_intel", {"ip": "203.0.113.66"}))
    assert e.value.blocked_by == "intent" and "scope" in e.value.reason
    assert intel.served == []


def test_external_data_via_brokered_token(server, verifier, broker, intel):
    r = run(_call(server, verifier, broker, READ, "reader-01", "reader",
                  "lookup_threat_intel", {"ip": "203.0.113.66"}))
    assert json.loads(r.content[0].text)["verdict"] == "malicious"
    assert intel.served == [{"sub": "reader-01", "ip": "203.0.113.66"}]


def test_external_data_not_reached_when_blocked(server, verifier, broker, intel):
    # executor is not allowed lookup_threat_intel -> no token minted, API untouched
    with pytest.raises(McpBlocked) as e:
        run(_call(server, verifier, broker, READ, "executor-01", "executor",
                  "lookup_threat_intel", {"ip": "203.0.113.66"}))
    assert e.value.blocked_by == "tbac"
    assert intel.served == []


def test_T10_external_api_rejects_direct_call_without_token(intel):
    tool = extdata.make_registry(intel)["lookup_threat_intel"]
    with pytest.raises(Exception, match="no brokered token"):
        tool(ip="203.0.113.66")
    assert intel.served == []


def test_T9_fake_mcp_server_rejected(verifier, broker, gate):
    # Impostor runs the same tools but cannot present a badge from our issuer.
    rogue_badge = LocalDevVerifier(secrets.token_bytes(32)).issue(SERVER_ID, "mcp_server")
    fake = build_server(SERVER_ID, gate, broker, rogue_badge, netops.REGISTRY)
    with pytest.raises(ServerAuthError, match="not trusted"):
        run(_call(fake, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))


def test_T9_unstamped_server_rejected(verifier, broker):
    plain = MCPServer(SERVER_ID)          # no gate middleware at all
    plain.add_tool(netops.show_acl, name="show_acl")
    with pytest.raises(ServerAuthError):
        run(_call(plain, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))


def test_T9_server_badge_for_other_server_rejected(server, verifier, broker):
    with pytest.raises(ServerAuthError, match="subject mismatch"):
        run(_call(server, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}, server_id="cmdb-mcp"))


def test_T9_agent_badge_cannot_pose_as_server(gate, verifier, broker):
    # A valid badge, but for an agent role, not mcp_server.
    srv = build_server(SERVER_ID, gate, broker,
                       verifier.issue(SERVER_ID, "executor"), netops.REGISTRY)
    with pytest.raises(ServerAuthError, match="role"):
        run(_call(srv, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))


@pytest.mark.parametrize("probe", [lambda c: c.read_resource("file:///etc/passwd"),
                                   lambda c: c.list_prompts()])
def test_unlisted_methods_refused(server, probe):
    async def go():
        async with Client(server) as c:
            try:
                await probe(c)
            except MCPError as e:
                err = e
        raise err
    with pytest.raises(MCPError, match="deny by default"):
        run(go())


def test_resources_list_served_empty_for_badge_discovery(server):
    async def go():
        async with Client(server) as c:
            return await c.list_resources()
    assert run(go()).resources == []


def test_badgeless_server_refuses_tools_call(gate, verifier, broker, audit):
    # Badge-issuance mode: discoverable, but runs nothing and is audited.
    srv = build_server(SERVER_ID, gate, broker, None, netops.REGISTRY)

    async def go():
        async with Client(srv) as c:
            tools = await c.list_tools()
            meta = {META_AGENT: "executor-01", META_BADGE: verifier.issue("executor-01", "executor"),
                    META_SESSION: broker.seal_session(
                        Session("Remove the permit any any rule on edge-fw-01", Intent.CHANGE))}
            return tools, await c.call_tool("push_config", PUSH, meta=meta)
    tools, r = run(go())
    assert "push_config" in [t.name for t in tools.tools]
    assert r.is_error and r.meta[META_DECISION]["blocked_by"] == "server_badge"
    assert netops.PUSHED == []
    rec, = audit.read_all()
    assert rec["verdict"] == "BLOCK" and rec["blocked_by"] == "server_badge"


def test_badgeless_server_fails_client_server_auth(gate, verifier, broker):
    srv = build_server(SERVER_ID, gate, broker, None, netops.REGISTRY)
    with pytest.raises(ServerAuthError):
        run(_call(srv, verifier, broker, READ, "reader-01", "reader",
                  "show_acl", {"device": "edge-fw-01"}))


def test_one_audit_record_per_mcp_call(server, verifier, broker, audit):
    run(_call(server, verifier, broker, READ, "reader-01", "reader",
              "show_acl", {"device": "edge-fw-01"}))
    for tool, args in [("push_config", PUSH), ("show_bgp_neighbors", {"device": "r1"})]:
        with pytest.raises(McpBlocked):
            run(_call(server, verifier, broker, READ, "reader-01", "reader", tool, args))
    recs = audit.read_all()
    assert [r["verdict"] for r in recs] == ["ALLOW", "BLOCK", "BLOCK"]
    assert all("agenttrustsec" not in str(r.get("args")) for r in recs)
