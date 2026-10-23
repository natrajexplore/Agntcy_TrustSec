# Ported from RuleGate tests (crewai_fw_chg_reviewer @ 6ce533b): proves the vendored core is faithful.
import datetime as dt

import pytest
from review_helpers import make_cr

from agenttrustsec.review.analysis.risk_rules import CHECKS, RiskPolicy, decide, load_policy, scan
from agenttrustsec.review.analysis.shadow import RuleRef, ShadowReport, analyze
from agenttrustsec.review.models.findings import Decision, Evidence, Finding, Severity


@pytest.fixture
def policy():
    return load_policy()  # package data/risk_policy.yaml


def ids(cr, policy, rules=()):
    return scan(cr, analyze(cr, list(rules)), policy).check_ids


def test_catalog_is_complete():
    assert sorted(CHECKS) == [f"RG-{i:03d}" for i in range(1, 17)]


def test_clean_requests_have_no_findings(policy):
    assert ids(make_cr("panos"), policy) == set()
    assert ids(make_cr("ftd"), policy) == set()


# RG-001 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg001_any_any(vendor, policy):
    assert "RG-001" in ids(make_cr(vendor, source="any", destination="any"), policy)
    assert "RG-001" not in ids(make_cr(vendor, source="any"), policy)
    assert "RG-001" not in ids(make_cr(vendor, action="deny", source="any", destination="any"), policy)  # edge


# RG-002 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg002_service_any(vendor, policy):
    assert "RG-002" in ids(make_cr(vendor, service="any"), policy)
    assert "RG-002" not in ids(make_cr(vendor), policy)


def test_rg002_application_default_is_not_any(policy):
    assert "RG-002" not in ids(make_cr("panos", service="application-default"), policy)


# RG-003 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor,zone", [("panos", "untrust"), ("ftd", "outside")])
def test_rg003_untrust_to_internal(vendor, zone, policy):
    assert "RG-003" in ids(make_cr(vendor, source_zone=zone), policy)
    assert "RG-003" not in ids(make_cr(vendor), policy)
    assert "RG-003" not in ids(make_cr(vendor, source_zone=zone, destination_zone=zone), policy)  # edge: transit


# RG-004 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg004_broad_cidr(vendor, policy):
    assert "RG-004" in ids(make_cr(vendor, source=["10.0.0.0/8"]), policy)
    assert "RG-004" in ids(make_cr(vendor, source=["10.0.0.0/16"]), policy)          # edge: at threshold
    assert "RG-004" not in ids(make_cr(vendor, source=["10.0.0.0/17"]), policy)
    assert "RG-004" in ids(make_cr(vendor, destination="any"), policy)                # one side any
    assert "RG-004" in ids(make_cr(vendor, source=["2001:db8::/32"]), policy)          # IPv6


# RG-005 / RG-006 (PAN-OS only) -------------------------------------------------
def test_rg005_app_any(policy):
    assert "RG-005" in ids(make_cr("panos", application="any"), policy)
    assert "RG-005" not in ids(make_cr("panos"), policy)
    assert "RG-005" not in ids(make_cr("ftd", application="any"), policy)  # edge: vendor scope


def test_rg006_profiles(policy):
    assert "RG-006" in ids(make_cr("panos", security_profile_group=None), policy)
    assert "RG-006" not in ids(make_cr("panos"), policy)
    assert "RG-006" not in ids(make_cr("panos", action="deny", security_profile_group=None), policy)  # edge


# RG-007 / RG-008 (FTD only) ----------------------------------------------------
def test_rg007_intrusion_and_file_policy(policy):
    assert "RG-007" in ids(make_cr("ftd", intrusion_policy=None), policy)
    assert "RG-007" not in ids(make_cr("ftd"), policy)
    assert "RG-007" in ids(make_cr("ftd", service=["tcp/80"]), policy)                  # edge: file policy expected
    assert "RG-007" not in ids(make_cr("ftd", service=["tcp/80"], file_policy="Block-Malware"), policy)
    assert "RG-007" not in ids(make_cr("panos", intrusion_policy=None), policy)


def test_rg008_trust_and_fastpath(policy):
    trust = scan(c := make_cr("ftd", ftd_action="trust"), analyze(c, []), policy)
    f = next(f for f in trust.findings if f.check_id == "RG-008")
    assert f.severity == Severity.MEDIUM
    fp = scan(c := make_cr("ftd", prefilter_fastpath=True), analyze(c, []), policy)
    assert next(f for f in fp.findings if f.check_id == "RG-008").severity == Severity.HIGH
    assert "RG-008" not in ids(make_cr("ftd"), policy)
    assert "RG-007" not in trust.check_ids  # edge: intrusion policy applies to Allow only


# RG-009 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg009_logging(vendor, policy):
    assert "RG-009" in ids(make_cr(vendor, logging=False), policy)
    assert "RG-009" not in ids(make_cr(vendor), policy)


# RG-010 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg010_cleartext(vendor, policy):
    assert "RG-010" in ids(make_cr(vendor, service=["tcp/23"]), policy)
    assert "RG-010" not in ids(make_cr(vendor, service=["tcp/80"]), policy)                 # HTTP internal is ok
    untrust = "untrust" if vendor == "panos" else "outside"
    assert "RG-010" in ids(make_cr(vendor, source_zone=untrust, service=["tcp/80"]), policy)  # edge


def test_rg010_app_id_telnet(policy):
    assert "RG-010" in ids(make_cr("panos", application=["telnet"], service="application-default"), policy)


# RG-011 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg011_management_ports(vendor, policy):
    assert "RG-011" in ids(make_cr(vendor, service=["tcp/22"]), policy)
    assert "RG-011" not in ids(make_cr(vendor, source_zone="mgmt", service=["tcp/22"]), policy)
    assert "RG-011" not in ids(make_cr(vendor, service=["tcp/443"]), policy)
    assert "RG-011" in ids(make_cr(vendor, service=["tcp/443"], destination_zone="mgmt"), policy)  # edge


# RG-012 ------------------------------------------------------------------------
@pytest.mark.parametrize("vendor", ["panos", "ftd"])
def test_rg012_metadata(vendor, policy):
    assert "RG-012" in ids(make_cr(vendor, business_justification="need it"), policy)
    assert "RG-012" in ids(make_cr(vendor, temporary=True), policy)
    assert "RG-012" not in ids(make_cr(vendor, temporary=True, expiry=dt.date(2026, 11, 1)), policy)
    assert "RG-012" in ids(make_cr(vendor, ticket_ref=None), policy)


# RG-013 / RG-014 / RG-015 come from shadow analysis ----------------------------
def _ref(name, action):
    return RuleRef(rule_id=name, name=name, position=3, layer="pre", action=action)


def test_rule_based_checks_follow_shadow_report(policy):
    cr = make_cr("panos")
    base = dict(section="pre", placement_requested="bottom", insertion_position=4)
    r = scan(cr, ShadowReport(**base, duplicate_of=_ref("dup", "allow")), policy)
    assert r.check_ids == {"RG-013"} and r.decision == Decision.REJECT_DUPLICATE
    r = scan(cr, ShadowReport(**base, shadowed_by=_ref("deny", "deny")), policy)
    assert r.check_ids == {"RG-014"} and r.decision == Decision.APPROVE_WITH_CONDITIONS
    r = scan(cr, ShadowReport(**base, deny_overrides=[_ref("deny", "deny")]), policy)
    assert r.check_ids == {"RG-015"} and r.decision == Decision.REJECT
    assert any(e.kind == "rule" for e in r.findings[0].evidence)


# RG-016 ------------------------------------------------------------------------
def test_rg016_sensitive_zone(policy):
    r = scan(c := make_cr("panos", destination_zone="pci-cde"), analyze(c, []), policy)
    f = next(f for f in r.findings if f.check_id == "RG-016")
    assert any("PCI DSS" in ref for ref in f.compliance)
    assert "RG-016" not in ids(make_cr("panos"), policy)
    assert "RG-016" in ids(make_cr("ftd", destination_zone="any"), policy)  # edge: any includes sensitive zones


# Policy, decision and scoring ---------------------------------------------------
def test_severity_comes_from_policy():
    pol = RiskPolicy(check_severity={"RG-009": Severity.CRITICAL})
    r = scan(c := make_cr("panos", logging=False), analyze(c, []), pol)
    assert r.findings[0].severity == Severity.CRITICAL and r.decision == Decision.REJECT


def _finding(check_id, sev):
    return Finding(check_id=check_id, severity=sev, title="t", detail="d",
                   evidence=[Evidence(kind="check", ref=check_id)])


def test_decision_table():
    assert decide([]) == Decision.APPROVE
    assert decide([_finding("RG-009", Severity.MEDIUM)]) == Decision.APPROVE
    assert decide([_finding("RG-011", Severity.HIGH)]) == Decision.APPROVE_WITH_CONDITIONS
    assert decide([_finding("RG-013", Severity.INFO), _finding("RG-011", Severity.HIGH)]) == Decision.REJECT_DUPLICATE
    assert decide([_finding("RG-001", Severity.CRITICAL), _finding("RG-013", Severity.INFO)]) == Decision.REJECT


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        Finding(check_id="RG-001", severity=Severity.HIGH, title="t", detail="d", evidence=[])


def test_score_is_capped(policy):
    cr = make_cr("panos", source="any", destination="any", service="any", application="any",
                 security_profile_group=None, logging=False, destination_zone="any")
    assert scan(cr, analyze(cr, []), policy).risk_score == 100


@pytest.mark.parametrize("bad", ["../../etc", "CR/1", "CR\1", "..", ".hidden", "", "x" * 65])
def test_change_id_cannot_escape_report_dir(bad):
    """Regression: change_id becomes reports/<change_id>/, so path characters must be rejected."""
    with pytest.raises(ValueError):
        type(make_cr("panos")).model_validate({**make_cr("panos").model_dump(mode="json"), "change_id": bad})
