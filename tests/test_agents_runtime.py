"""P5b agent runtime + reader without a lab: registry, allowed tools, refusal, badge fetch."""
import asyncio
import base64
import io
import json

import pytest

from agenttrustsec.agents import reader
from agenttrustsec.agents.runtime import load_agent, result_body
from agenttrustsec.identity.agntcy import fetch_current_badge, load_role_map
from agenttrustsec.identity.badge import BadgeError

from conftest import ROOT

IDS = ROOT / "policies" / "identities.yaml"


@pytest.mark.parametrize("name,role", [("intake-01", "intake"), ("reader-01", "reader"),
                                       ("reviewer-01", "reviewer"), ("executor-01", "executor")])
def test_registry_ids_match_the_authorization_map(name, role):
    cfg = load_agent(name)
    assert load_role_map(IDS, "agents")[cfg.metadata_id] == role
    assert load_role_map(IDS, "mcp_servers")[cfg.gateway_id] == "mcp_server"
    assert cfg.key_path.name == f"{name}.pem"


def test_unknown_agent_refused():
    with pytest.raises(KeyError):
        load_agent("rogue-99")


def test_reader_tools_come_from_tbac():
    assert reader.allowed_tools() == {"show_running_config", "show_acl", "show_bgp_neighbors",
                                      "lookup_threat_intel"}


def test_reader_refuses_non_read_job_before_any_gateway_contact():
    class NoGateway:
        def gateway(self, token):
            raise AssertionError("must not reach the gateway")
    for tool in ("push_config", "review_change", "made_up_tool"):
        with pytest.raises(reader.NotAReadTool):
            asyncio.run(reader.run_job(NoGateway(), "token", tool, {"device": "edge-fw-01"}))


def jose(status=None):
    body = {"id": "vc", **({"credentialStatus": [{"purpose": status}]} if status else {})}
    enc = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")
    return f"h.{enc}.s"


@pytest.mark.parametrize("published,expected", [
    ([jose("CREDENTIAL_STATUS_PURPOSE_REVOCATION"), jose()], 1),         # skips the revoked copy
    ([jose()], 0),
])
def test_current_badge_is_the_unrevoked_copy(monkeypatch, published, expected):
    payload = json.dumps({"vcs": [{"value": v} for v in published]}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: io.BytesIO(payload))
    assert fetch_current_badge("http://node", "AGNTCY-x") == published[expected]


def test_no_unrevoked_badge_refused(monkeypatch):
    payload = json.dumps({"vcs": [{"value": jose("CREDENTIAL_STATUS_PURPOSE_REVOCATION")}]}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: io.BytesIO(payload))
    with pytest.raises(BadgeError, match="no unrevoked"):
        fetch_current_badge("http://node", "AGNTCY-x")


def test_result_body_parses_json_or_keeps_text():
    from types import SimpleNamespace as NS
    assert result_body(NS(content=[NS(text='["a", "b"]')])) == ["a", "b"]
    assert result_body(NS(content=[NS(text="plain")])) == "plain"
