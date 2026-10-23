# Ported from RuleGate tests (crewai_fw_chg_reviewer @ 6ce533b): proves the vendored core is faithful.
from pathlib import Path
import pytest

from agenttrustsec.review.parsers import ftd_fmc, panos

PAN = str(Path(__file__).resolve().parents[1] / "src" / "agenttrustsec" / "review" / "data" / "rulebases" / "panos_running.xml")
FMC = str(Path(__file__).resolve().parents[1] / "src" / "agenttrustsec" / "review" / "data" / "rulebases" / "fmc_accessrules.json")


def test_panos_order_and_count():
    rules = panos.load_offline(PAN, "DC-Core")
    assert len(rules) == 10
    assert [r.position for r in rules] == list(range(1, 11))
    assert rules[0].name == "Block-DMZ-to-Mgmt" and rules[0].layer == "pre"
    assert rules[-1].name == "Cleanup-Deny-All" and rules[-1].layer == "post"


def test_panos_object_and_group_resolution():
    rules = {r.name: r for r in panos.load_offline(PAN, "DC-Core")}
    db = rules["Allow-App-to-DB-Postgres"]
    assert {a.value for a in db.dst_addrs} == {"10.40.10.15/32", "10.40.10.16/32"}
    assert db.app_default_service and db.applications == ["postgres"]
    assert db.inspection.profile_group == "Strict-Inspection"
    assert [str(s) for s in rules["Allow-DMZ-to-App-8443"].services] == ["tcp/8443"]
    assert rules["Allow-DMZ-to-App-8443"].src_addrs[0].source_object == "internal-10"


def test_panos_unresolved_and_disabled():
    rules = {r.name: r for r in panos.load_offline(PAN, "DC-Core")}
    assert rules["Allow-DNS-Out"].dst_addrs[0].unresolved and rules["Allow-DNS-Out"].dst_addrs[0].reason == "fqdn"
    assert rules["Block-Quarantine"].src_addrs[0].reason == "dynamic"
    assert rules["Block-Quarantine"].action == "drop"
    assert rules["Old-Temp-Vendor-Access"].enabled is False


def test_panos_unknown_device_group():
    with pytest.raises(ValueError):
        panos.load_offline(PAN, "Nope")


def test_fmc_order_layers_and_default_action():
    rules = ftd_fmc.load_offline(FMC, "DC-Edge-ACP")
    assert [r.layer for r in rules] == ["prefilter", "mandatory", "mandatory", "mandatory", "default", "default-action"]
    assert rules[0].action == "fastpath"
    assert rules[-1].name == "DefaultAction" and rules[-1].action == "deny"


def test_fmc_resolution():
    rules = {r.name: r for r in ftd_fmc.load_offline(FMC)}
    web = rules["Allow-Users-to-DC-Web"]
    assert [a.value for a in web.src_addrs] == ["10.10.0.0/16"]
    assert sorted(str(s) for s in web.services) == ["tcp/443", "tcp/80"]
    assert web.inspection.intrusion_policy and web.inspection.file_policy == "Block-Malware"
    assert rules["Allow-Vendor-Portal"].dst_addrs[0].unresolved
    assert rules["Block-Any-to-PCI"].src_zones == ["any"]
