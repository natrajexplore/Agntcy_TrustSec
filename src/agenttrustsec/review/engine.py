"""Review engine: load a change request + the device's rulebase, run shadow analysis and the
RG-xxx risk checks. Adapted from RuleGate's `pipeline.py` (@ 6ce533b), offline mode only:
rulebases and the risk policy come from this package's `data/`, never from the cwd or env.

`review_for_device()` is what the gateway tool calls: the LAB DEVICE decides vendor, device
group and rulebase — the caller cannot point the review at a different rulebase.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agenttrustsec.review.analysis import shadow
from agenttrustsec.review.analysis.risk_rules import RiskPolicy, load_policy, scan
from agenttrustsec.review.models.change_request import NormalizedChangeRequest
from agenttrustsec.review.models.findings import RiskReport
from agenttrustsec.review.models.normalized_rule import NormalizedRule
from agenttrustsec.review.parsers import LOADERS

DATA = Path(__file__).resolve().parent / "data"
RULEBASES = {"panos": DATA / "rulebases" / "panos_running.xml",
             "ftd": DATA / "rulebases" / "fmc_accessrules.json"}

# Lab devices (tools/netops.py names) -> (vendor, device group). Unknown device -> no review.
LAB_DEVICES = {"edge-fw-01": ("panos", "DC-Core"), "edge-fw-02": ("ftd", "DC-Edge-ACP")}


class UnknownDevice(LookupError):
    pass


def read_request_file(path: str | Path) -> NormalizedChangeRequest:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
    return NormalizedChangeRequest.model_validate(data)


def load_rulebase(cr: NormalizedChangeRequest) -> list[NormalizedRule]:
    return LOADERS[cr.target.vendor](RULEBASES[cr.target.vendor], cr.target.device_group)


@dataclass
class ReviewContext:
    request: NormalizedChangeRequest
    rules: list[NormalizedRule]
    policy: RiskPolicy
    shadow: shadow.ShadowReport = field(init=False)
    risk: RiskReport = field(init=False)

    def __post_init__(self) -> None:
        self.shadow = shadow.analyze(self.request, self.rules)
        self.risk = scan(self.request, self.shadow, self.policy)


def build_context(cr: NormalizedChangeRequest, policy_path: str | Path | None = None) -> ReviewContext:
    return ReviewContext(request=cr, rules=load_rulebase(cr), policy=load_policy(policy_path))


def review_for_device(device: str, change: dict[str, Any]) -> ReviewContext:
    """Validate `change` (a RuleGate change request without `target`) and review it against
    the rulebase of lab `device`. Any `target` in `change` is replaced by the device's."""
    if device not in LAB_DEVICES:
        raise UnknownDevice(f"no rulebase for device {device!r}")
    vendor, group = LAB_DEVICES[device]
    cr = NormalizedChangeRequest.model_validate({**change, "target": {"vendor": vendor, "device_group": group}})
    return build_context(cr)


def summary(ctx: ReviewContext) -> dict[str, Any]:
    """Compact, JSON-safe result for agents and the audit trail."""
    r = ctx.risk
    return {
        "change_id": ctx.request.change_id,
        "vendor": r.vendor,
        "device_group": r.device_group,
        "decision": r.decision.value,
        "risk_score": r.risk_score,
        "check_ids": sorted(r.check_ids),
        "needs_human_review": r.needs_human_review,
        "findings": [{"id": f.check_id, "severity": f.severity.value, "title": f.title}
                     for f in r.findings],
    }
