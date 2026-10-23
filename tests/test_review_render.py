"""Item A: change request -> config. The vendored renderer (review/render.py) must match RuleGate
byte for byte, and staged_lines() must turn it into exactly the lines push_config gets.

Golden fixtures in fixtures/rulegate/staged/ were rendered ONCE by RuleGate itself
(crewai_fw_chg_reviewer @ 6ce533b, its own venv, RULEGATE_MODE=offline) from the same sample CRs."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agenttrustsec.authz.broker import lines_digest
from agenttrustsec.review.engine import (NotRenderable, _fmc_line, build_context, read_request_file,
                                         review_for_device, staged_lines, summary)
from agenttrustsec.review.render import render

from review_helpers import make_cr

FIX = Path(__file__).resolve().parent / "fixtures" / "rulegate"
SAMPLES = sorted((FIX / "change_requests").glob("*.yaml"))


def test_every_sample_has_a_golden_rendering():
    assert len(SAMPLES) == 11 and {p.stem for p in SAMPLES} == {p.stem for p in (FIX / "staged").glob("*.json")}


@pytest.mark.parametrize("cr", SAMPLES, ids=[p.stem for p in SAMPLES])
def test_render_is_byte_identical_to_rulegate(cr):
    golden = json.loads((FIX / "staged" / f"{cr.stem}.json").read_text(encoding="utf-8"))
    assert render(build_context(read_request_file(cr))).model_dump() == golden


@pytest.mark.parametrize("cr", SAMPLES, ids=[p.stem for p in SAMPLES])
def test_staged_lines_are_the_config_without_comments(cr):
    ctx = build_context(read_request_file(cr))
    st, golden = staged_lines(ctx), json.loads((FIX / "staged" / f"{cr.stem}.json").read_text(encoding="utf-8"))
    assert st["lines_digest"] == lines_digest(st["lines"]) and st["rollback"] == golden["rollback"]
    assert st["rule_name"] == golden["rule_name"] and st == staged_lines(ctx)              # deterministic
    if st["vendor"] == "panos":
        assert st["lines"] == [ln for ln in golden["config"].splitlines() if ln and not ln.startswith("#")]
        assert st["lines"][-1].startswith("move ")
    else:
        (line,) = st["lines"]
        call = json.loads(line)
        assert set(call) == {"method", "endpoint", "query", "body"} and call["method"] == "POST"
        assert call["body"]["name"] == golden["rule_name"] and call["endpoint"] in golden["config"]
        assert call["query"] == "" or call["query"].startswith("?")


def test_summary_carries_the_staged_lines():
    s = summary(review_for_device("edge-fw-01", make_cr().model_dump(mode="json", exclude={"target"})))
    assert s["staged"]["vendor"] == "panos" and s["staged"]["rule_name"] == "CR-TEST-web-dmz-to-db-trust"


def test_the_same_request_on_another_device_renders_other_lines():
    # device decides vendor + rulebase: a PAN-OS rendering never passes for the FTD box
    ftd = make_cr("ftd").model_dump(mode="json", exclude={"target"})
    assert staged_lines(review_for_device("edge-fw-02", ftd))["vendor"] == "ftd"
    assert staged_lines(review_for_device("edge-fw-01", ftd))["vendor"] == "panos"


def test_fmc_payload_without_method_endpoint_or_query_is_refused():
    with pytest.raises(NotRenderable):
        _fmc_line('// Method:   POST\n{"name": "x"}')


# Every request field that reaches a pushed line, with a value that would smuggle a second command.
INJECT = "x\nset deviceconfig system ip-address 6.6.6.6"


@pytest.mark.parametrize("field,value", [
    ("source_zone", INJECT), ("destination_zone", "dmz ]; delete rulebase"),
    ("source", "10.0.0.0/8 ]"), ("destination", INJECT),
    ("application", 'ssl" ; commit'), ("service", "tcp/443 ]"), ("users", "corp\\a b"),
    ("security_profile_group", INJECT), ("placement", "before:Rule-1 ]"),
])
def test_command_injection_through_request_fields_is_refused(field, value):
    with pytest.raises(ValidationError):
        make_cr(**{field: value})


@pytest.mark.parametrize("field,value", [
    ("ticket_ref", "CHG1\nset x"), ("ticket_ref", 'CHG1" ; set x'), ("requester", "ops\nset x"),
    ("requester", 'ops" x'), ("expiry", "2026-10-11\nset x"),
])
def test_command_injection_through_description_and_comment_fields_is_refused(field, value):
    with pytest.raises(ValidationError):
        make_cr(**{field: value})


def test_free_text_never_reaches_a_pushed_line():
    # justification is flattened and appears in no PAN-OS line; requester only in a '#' comment
    cr = make_cr(business_justification="line1\nset deviceconfig x", requester="ops-team")
    st = staged_lines(build_context(cr))
    assert not any("deviceconfig" in ln or "ops-team" in ln for ln in st["lines"])
