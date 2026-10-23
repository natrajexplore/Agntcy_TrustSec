# Ported from RuleGate tests (crewai_fw_chg_reviewer @ 6ce533b): proves the vendored core is faithful.
"""RuleGate's labelled scenarios: exact decision, exact check IDs and human-review flag for every
sample change request. The deterministic suite only — the CrewAI/LLM suite is not ported."""
from pathlib import Path

import pytest

from agenttrustsec.review.engine import build_context, read_request_file

CR = str(Path(__file__).resolve().parent / "fixtures" / "rulegate" / "change_requests") + "/"

SCENARIOS = [
    # file, expected decision, expected check IDs (exact), needs human review
    ("cr-1001-panos-web-to-db.yaml", "APPROVE", set(), False),
    ("cr-1002-panos-duplicate.yaml", "REJECT_DUPLICATE", {"RG-005", "RG-013"}, False),
    ("cr-1003-panos-any-any.yaml", "REJECT", {"RG-001", "RG-002", "RG-005", "RG-006", "RG-015", "RG-016"}, False),
    ("cr-1004-panos-dmz-to-pci.yaml", "APPROVE_WITH_CONDITIONS", {"RG-014", "RG-016"}, False),
    ("cr-1005-panos-telnet-untrust.yaml", "APPROVE_WITH_CONDITIONS", {"RG-003", "RG-010", "RG-012"}, True),
    ("cr-1006-panos-ssh-no-justification.yaml", "APPROVE_WITH_CONDITIONS", {"RG-009", "RG-011", "RG-012"}, False),
    ("cr-2001-ftd-vendor-sftp.yaml", "APPROVE_WITH_CONDITIONS", {"RG-003", "RG-011"}, False),
    ("cr-2002-ftd-trust-bypass.yaml", "APPROVE", {"RG-008"}, False),
    ("cr-2003-ftd-pci-fastpath.yaml", "REJECT", {"RG-008", "RG-015", "RG-016"}, False),
    ("cr-2004-ftd-clean.yaml", "APPROVE", set(), False),
    ("cr-2005-ftd-duplicate.yaml", "REJECT_DUPLICATE", {"RG-013"}, False),
]


@pytest.mark.parametrize("file,decision,check_ids,review", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_deterministic_scenario(file, decision, check_ids, review):
    risk = build_context(read_request_file(CR + file)).risk
    assert risk.decision.value == decision
    assert risk.check_ids == check_ids
    assert risk.needs_human_review is review
