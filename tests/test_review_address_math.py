# Ported from RuleGate tests (crewai_fw_chg_reviewer @ 6ce533b): proves the vendored core is faithful.
import pytest

from agenttrustsec.review.analysis import address_math as am
from agenttrustsec.review.models.normalized_rule import NormalizedRule


def addrs(*tokens):
    return [e for t in tokens for e in am.parse_address_token(t)]


def svc(*tokens):
    return [p for t in tokens for p in am.parse_service_token(t)]


def test_cidr_containment():
    assert am.addrs_contain(addrs("10.1.0.0/16"), addrs("10.1.4.0/24")) is True
    assert am.addrs_contain(addrs("10.1.4.0/24"), addrs("10.1.0.0/16")) is False


def test_any_expands_to_v4_and_v6():
    assert am.addrs_contain(addrs("any"), addrs("2001:db8::/64", "192.0.2.1")) is True
    assert am.is_any_address(addrs("any"))


def test_mixed_ip_versions_do_not_raise():
    assert am.addrs_contain(addrs("10.0.0.0/8"), addrs("2001:db8::1")) is False
    assert am.addrs_overlap(addrs("10.0.0.0/8"), addrs("2001:db8::1")) is False


def test_range_is_summarized():
    entries = addrs("10.99.0.10-10.99.0.12")
    assert {e.value for e in entries} == {"10.99.0.10/31", "10.99.0.12/32"}
    assert am.addrs_contain(entries, addrs("10.99.0.11")) is True


def test_union_coverage_is_conservative():
    # 10.0.0.0/25 + 10.0.0.128/25 together cover the /24, but no single entry does
    assert am.addrs_contain(addrs("10.0.0.0/25", "10.0.0.128/25"), addrs("10.0.0.0/24")) is False


def test_unresolved_is_undecidable():
    r = am.ObjectResolver({"web": {"type": "fqdn", "value": "www.example.net"}})
    entries = r.resolve("web")
    assert entries[0].unresolved and entries[0].reason == "fqdn"
    assert am.addrs_contain(entries, addrs("10.0.0.1")) is None
    assert am.addrs_overlap(entries, addrs("10.0.0.1")) is None


def test_group_resolution_and_cycles():
    r = am.ObjectResolver({
        "a": {"type": "ip", "value": "10.0.0.1"},
        "g1": {"type": "group", "members": ["a", "g2"]},
        "g2": {"type": "group", "members": ["g1"]},
    })
    out = r.resolve("g1")
    assert out[0].value == "10.0.0.1/32" and out[0].source_object == "g1"
    assert any(e.unresolved and e.reason == "group-cycle" for e in out)


def test_port_ranges():
    assert am.services_contain(svc("tcp/1000-2000"), svc("tcp/1500")) is True
    assert am.services_contain(svc("tcp/1000-2000"), svc("udp/1500")) is False
    assert am.services_overlap(svc("tcp/1000-2000"), svc("tcp/1999-3000")) is True
    assert am.services_contain(svc("any"), svc("udp/53", "icmp")) is True
    assert am.services_contain(svc("tcp/443"), svc("any")) is False


def test_bad_service_rejected():
    with pytest.raises(ValueError):
        am.parse_service_token("https")


def test_application_default_expansion():
    rule = NormalizedRule(vendor="panos", rule_id="r", name="r", position=1, layer="pre", action="allow",
                          applications=["postgres"], app_default_service=True)
    assert [str(p) for p in am.effective_services(rule)] == ["tcp/5432"]
    rule.applications = ["custom-app"]
    assert am.effective_services(rule) is None
