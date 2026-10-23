"""P5a: the gateway's review_change tool runs RuleGate's deterministic engine against the lab
device's rulebase — the device (not the caller) decides vendor and rulebase."""
import asyncio
import json
import secrets

import pytest
import yaml
from pydantic import ValidationError

from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.mcpgate.client import TrustedClient
from agenttrustsec.mcpgate.server import build_server
from agenttrustsec.models import Intent, Session
from agenttrustsec.review.engine import UnknownDevice
from agenttrustsec.tools import netops

from conftest import ROOT

CRS = ROOT / "tests" / "fixtures" / "rulegate" / "change_requests"


def change(name):
    cr = yaml.safe_load((CRS / name).read_text(encoding="utf-8"))
    cr.pop("target")                          # the device decides
    return cr


def test_clean_change_approved():
    r = netops.review_change("edge-fw-01", change("cr-1001-panos-web-to-db.yaml"))
    assert (r["device"], r["vendor"], r["decision"], r["check_ids"]) == ("edge-fw-01", "panos", "APPROVE", [])


def test_any_any_rejected_with_rulegate_checks():
    r = netops.review_change("edge-fw-01", change("cr-1003-panos-any-any.yaml"))
    assert r["decision"] == "REJECT"
    assert set(r["check_ids"]) == {"RG-001", "RG-002", "RG-005", "RG-006", "RG-015", "RG-016"}
    assert all({"id", "severity", "title"} <= set(f) for f in r["findings"])


def test_ftd_device_uses_the_fmc_rulebase():
    r = netops.review_change("edge-fw-02", change("cr-2003-ftd-pci-fastpath.yaml"))
    assert (r["vendor"], r["device_group"], r["decision"]) == ("ftd", "DC-Edge-ACP", "REJECT")


def test_caller_cannot_choose_the_rulebase():
    cr = change("cr-1001-panos-web-to-db.yaml")
    cr["target"] = {"vendor": "ftd", "device_group": "DC-Edge-ACP"}      # ignored
    r = netops.review_change("edge-fw-01", cr)
    assert (r["vendor"], r["device_group"]) == ("panos", "DC-Core")


@pytest.mark.parametrize("device,cr,exc", [
    ("core-rtr-01", {"x": 1}, UnknownDevice),                            # no rulebase in the lab
    ("edge-fw-01", None, ValueError),                                    # nothing to review
    ("edge-fw-01", {"change_id": "bad id; drop", "request": {}}, ValidationError),  # schema violation
])
def test_review_refuses_bad_input(device, cr, exc):
    with pytest.raises(exc):
        netops.review_change(device, cr)


def test_empty_request_defaults_to_any_and_is_rejected():
    # RuleGate treats unspecified fields as `any` — the most dangerous value — so an empty
    # request reviews as allow any/any: REJECT, score 100 (fail-safe, not a pass).
    r = netops.review_change("edge-fw-01", {"change_id": "CR-9", "request": {}})
    assert r["decision"] == "REJECT" and r["risk_score"] == 100
    assert {"RG-001", "RG-012"} <= set(r["check_ids"])


def test_reviewer_calls_review_change_through_the_gate(gate, verifier, audit):
    from mcp import Client

    broker = TokenBroker(secrets.token_bytes(32))
    server = build_server("netops-mcp", gate, broker, verifier.issue("netops-mcp", "mcp_server"),
                          netops.REGISTRY)
    session = broker.seal_session(Session(
        "Risk-review the proposed change CR-1003 on edge-fw-01", Intent.READ))

    async def go():
        async with Client(server) as c:
            tc = TrustedClient(c, agent_id="reviewer-01", badge=verifier.issue("reviewer-01", "reviewer"),
                               session_token=session, verifier=verifier, server_id="netops-mcp")
            return await tc.call("review_change", {"device": "edge-fw-01",
                                                   "change": change("cr-1003-panos-any-any.yaml")})
    result = asyncio.run(go())
    body = json.loads(result.content[0].text)
    assert body["decision"] == "REJECT" and body["change_id"] == "CR-1003"
    rec, = audit.read_all()
    assert rec["verdict"] == "ALLOW" and rec["tool"] == "review_change"
