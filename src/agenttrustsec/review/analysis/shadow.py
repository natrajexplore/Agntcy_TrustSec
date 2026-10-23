# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Duplicate / shadow / deny-override detection against an ordered, normalized rulebase.

Semantics (first match wins, rules sorted by global ``position``):

* RG-013 duplicate  - in the *current* rulebase, the first rule that fully covers the
  requested access already has the requested outcome (permit for allow, block for deny),
  and no earlier rule partially overlaps with the opposite outcome.
* RG-014 shadowed   - a rule above the requested placement fully covers the request with
  the opposite outcome, so the new rule would never match.
* RG-015 deny override - a new allow would sit above an explicit (non catch-all) block
  rule that it overlaps, i.e. it punches a hole in an intentional deny.

Partial overlaps are informational. Anything that depends on an UNRESOLVED entry, a
user-based rule, or an unknown application is reported as needing human review.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from agenttrustsec.review.analysis import address_math as am
from agenttrustsec.review.models.change_request import NormalizedChangeRequest
from agenttrustsec.review.models.normalized_rule import (
    ANY,
    BLOCK_ACTIONS,
    PERMIT_ACTIONS,
    AddressEntry,
    InspectionProfile,
    NormalizedRule,
)

LAYER_ORDER = {
    "panos": ["pre", "local", "post", "default"],
    "ftd": ["prefilter", "mandatory", "default", "default-action"],
}

DIMENSIONS = ("src_zones", "dst_zones", "src_addrs", "dst_addrs", "applications", "services")


class RuleRef(BaseModel):
    rule_id: str
    name: str
    position: int
    layer: str
    action: str

    @classmethod
    def of(cls, r: NormalizedRule) -> "RuleRef":
        return cls(rule_id=r.rule_id, name=r.name, position=r.position, layer=r.layer, action=r.action)

    def label(self) -> str:
        return f"#{self.position} {self.name} ({self.layer}, {self.action})"


class OverlapNote(BaseModel):
    rule: RuleRef
    partial_dimensions: list[str] = Field(description="Dimensions where the rule overlaps but does not fully cover the request")


class ReviewNote(BaseModel):
    rule: RuleRef
    reason: str


class ShadowReport(BaseModel):
    section: str
    placement_requested: str
    insertion_position: int = Field(description="Global position the new rule would take")
    placement_notes: list[str] = Field(default_factory=list)
    duplicate_of: RuleRef | None = None
    shadowed_by: RuleRef | None = None
    deny_overrides: list[RuleRef] = Field(default_factory=list)
    partial_overlaps: list[OverlapNote] = Field(default_factory=list)
    needs_review: list[ReviewNote] = Field(default_factory=list)
    disabled_cleanup_candidates: list[RuleRef] = Field(default_factory=list)
    recommended_placement: str = ""
    move_before: str | None = Field(None, description="Rule name the new rule should be moved before (None = bottom of section)")

    @property
    def needs_human_review(self) -> bool:
        return bool(self.needs_review)


# --------------------------------------------------------------------------- request -> rule

def _request_addresses(tokens: list[str], field: str) -> list[AddressEntry]:
    out: list[AddressEntry] = []
    for t in tokens:
        parsed = am.parse_address_token(t, source_object=f"request.{field}")
        out.extend(parsed or [AddressEntry(value=t, source_object=f"request.{field}", unresolved=True, reason="request-object")])
    return out


def request_to_rule(cr: NormalizedChangeRequest) -> NormalizedRule:
    """Build the candidate rule the change request describes (position assigned by caller)."""
    req = cr.request
    app_default = req.service == ["application-default"]
    services = [] if app_default else [p for s in req.service for p in am.parse_service_token(s, "request.service")]
    if req.action == "deny":
        action = "deny"
    elif cr.target.vendor == "ftd" and req.prefilter_fastpath:
        action = "fastpath"
    elif cr.target.vendor == "ftd" and req.ftd_action == "trust":
        action = "trust"
    else:
        action = "allow"
    return NormalizedRule(
        vendor=cr.target.vendor,
        rule_id=f"{cr.change_id}-candidate",
        name=f"{cr.change_id}-candidate",
        position=0,
        layer="candidate",
        action=action,
        src_zones=req.source_zone,
        dst_zones=req.destination_zone,
        src_addrs=_request_addresses(req.source, "source"),
        dst_addrs=_request_addresses(req.destination, "destination"),
        services=services,
        applications=req.application,
        app_default_service=app_default,
        users=req.users,
        inspection=InspectionProfile(
            profile_group=req.security_profile_group,
            intrusion_policy=req.intrusion_policy,
            file_policy=req.file_policy,
        ),
        log_at_end=req.logging,
        raw_ref=f"change_request:{cr.change_id}",
    )


# --------------------------------------------------------------------------- comparisons

def _dimension_results(rule: NormalizedRule, cand: NormalizedRule) -> dict[str, tuple[bool | None, bool | None]]:
    """Per dimension: (rule covers candidate, rule overlaps candidate)."""
    rs, cs = am.effective_services(rule), am.effective_services(cand)
    return {
        "src_zones": (am.zones_contain(rule.src_zones, cand.src_zones), am.zones_overlap(rule.src_zones, cand.src_zones)),
        "dst_zones": (am.zones_contain(rule.dst_zones, cand.dst_zones), am.zones_overlap(rule.dst_zones, cand.dst_zones)),
        "src_addrs": (am.addrs_contain(rule.src_addrs, cand.src_addrs), am.addrs_overlap(rule.src_addrs, cand.src_addrs)),
        "dst_addrs": (am.addrs_contain(rule.dst_addrs, cand.dst_addrs), am.addrs_overlap(rule.dst_addrs, cand.dst_addrs)),
        "applications": (am.apps_contain(rule.applications, cand.applications), am.apps_overlap(rule.applications, cand.applications)),
        "services": (am.services_contain(rs, cs), am.services_overlap(rs, cs)),
    }


def _combine(values: list[bool | None]) -> bool | None:
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def compare(rule: NormalizedRule, cand: NormalizedRule) -> tuple[bool | None, bool | None, list[str]]:
    """Return (covers, overlaps, partial_dimensions). None means undecidable."""
    dims = _dimension_results(rule, cand)
    overlaps = _combine([o for _, o in dims.values()])
    covers = _combine([c for c, _ in dims.values()])
    if rule.users and ANY not in rule.users and covers is not False:
        covers = None  # a user-scoped rule never fully covers a request we cannot attribute to users
    partial = [d for d, (c, o) in dims.items() if c is False and o is not False]
    return covers, overlaps, partial


def is_catch_all(rule: NormalizedRule) -> bool:
    svc = am.effective_services(rule)
    return (
        ANY in rule.src_zones and ANY in rule.dst_zones
        and not am.has_unresolved(rule.src_addrs + rule.dst_addrs)
        and am.is_any_address(rule.src_addrs) and am.is_any_address(rule.dst_addrs)
        and ANY in rule.applications and svc is not None and am.is_any_service(svc)
    )


def _undecidable_reason(rule: NormalizedRule) -> str:
    reasons = []
    if rule.unresolved_entries:
        reasons.append("UNRESOLVED objects: " + ", ".join(f"{e.value} ({e.reason})" for e in rule.unresolved_entries))
    if rule.users and ANY not in rule.users:
        reasons.append("user-based match: " + ", ".join(rule.users))
    if rule.unresolved_services:
        reasons.append("UNRESOLVED service objects: " + ", ".join(rule.unresolved_services))
    elif am.effective_services(rule) is None:
        reasons.append("application-default with unmapped App-ID: " + ", ".join(rule.applications))
    return "; ".join(reasons) or "undecidable comparison"


# --------------------------------------------------------------------------- placement

def _section_for(cr: NormalizedChangeRequest, rules: list[NormalizedRule]) -> str:
    if cr.target.vendor == "ftd":
        return "prefilter" if cr.request.prefilter_fastpath else "mandatory"
    return "pre" if any(r.layer == "pre" for r in rules) or not rules else "local"


def _insertion_index(cr: NormalizedChangeRequest, rules: list[NormalizedRule], section: str, notes: list[str]) -> int:
    order = LAYER_ORDER[cr.target.vendor]
    sec_rank = order.index(section)
    in_section = [i for i, r in enumerate(rules) if r.layer == section]
    before_section = [i for i, r in enumerate(rules) if order.index(r.layer) < sec_rank]
    top = in_section[0] if in_section else (before_section[-1] + 1 if before_section else 0)
    bottom = in_section[-1] + 1 if in_section else top

    placement = cr.request.placement
    if placement == "top":
        return top
    if placement == "bottom":
        return bottom
    where, _, ref = placement.partition(":")
    for i, r in enumerate(rules):
        if ref in (r.name, r.rule_id):
            if r.layer != section:
                notes.append(f"Placement reference '{ref}' is in layer '{r.layer}', not '{section}'; used bottom of section.")
                return bottom
            return i if where == "before" else i + 1
    notes.append(f"Placement reference '{ref}' not found; used bottom of section '{section}'.")
    return bottom


# --------------------------------------------------------------------------- analysis

def analyze(cr: NormalizedChangeRequest, rules: list[NormalizedRule]) -> ShadowReport:
    rules = sorted(rules, key=lambda r: r.position)
    cand = request_to_rule(cr)
    section = _section_for(cr, rules)
    notes: list[str] = []
    idx = _insertion_index(cr, rules, section, notes)
    insertion_position = rules[idx].position if idx < len(rules) else (rules[-1].position + 1 if rules else 1)

    wanted = PERMIT_ACTIONS if cand.action in PERMIT_ACTIONS else BLOCK_ACTIONS
    opposite = BLOCK_ACTIONS if wanted is PERMIT_ACTIONS else PERMIT_ACTIONS

    report = ShadowReport(section=section, placement_requested=cr.request.placement,
                          insertion_position=insertion_position, placement_notes=notes)

    duplicate_decided = False
    opposite_partial_seen = False
    shadow_decided = False

    for i, rule in enumerate(rules):
        if rule.action == "monitor":
            continue  # FTD Monitor / Prefilter Analyze rules do not terminate evaluation
        covers, overlaps, partial = compare(rule, cand)
        if overlaps is False:
            continue
        ref = RuleRef.of(rule)
        if not rule.enabled:
            report.disabled_cleanup_candidates.append(ref)
            continue
        above = i < idx
        catch_all = is_catch_all(rule)

        if covers is None:
            report.needs_review.append(ReviewNote(rule=ref, reason=_undecidable_reason(rule)))
            # an undecidable rule in front of the decisive rule blocks a definitive duplicate
            if not duplicate_decided:
                opposite_partial_seen = True
            continue

        # --- RG-013: current behaviour for the requested traffic
        if not duplicate_decided:
            if covers:
                duplicate_decided = True
                if rule.action in wanted and not opposite_partial_seen:
                    report.duplicate_of = ref
            elif rule.action in opposite:
                opposite_partial_seen = True

        # --- RG-014: first covering rule above the placement with the opposite outcome
        if above and covers and not shadow_decided:
            shadow_decided = True
            if rule.action in opposite:
                report.shadowed_by = ref

        # --- RG-015: new permit placed above an explicit block it overlaps
        if (not above and cand.action in PERMIT_ACTIONS and rule.action in BLOCK_ACTIONS and not catch_all):
            report.deny_overrides.append(ref)
        elif not covers and not catch_all:
            report.partial_overlaps.append(OverlapNote(rule=ref, partial_dimensions=partial))

    report.move_before = rules[idx].name if idx < len(rules) and rules[idx].layer == section else None
    report.recommended_placement = _recommend(report, section)
    return report


def _recommend(r: ShadowReport, section: str) -> str:
    if r.duplicate_of:
        return f"No change needed: requested access already matches {r.duplicate_of.label()}."
    if r.shadowed_by:
        return (f"Rule as placed is unreachable: {r.shadowed_by.label()} matches first. "
                f"Moving it above that rule would override an intentional {r.shadowed_by.action}; requires a policy exception.")
    if r.deny_overrides:
        names = ", ".join(d.label() for d in r.deny_overrides)
        return (f"Do not place above explicit block rule(s) {names}. Narrow the request so it no longer overlaps, "
                f"or place it below them and obtain a documented exception.")
    target = f"before rule '{r.move_before}'" if r.move_before else f"at the bottom of the {section} section"
    return f"Place {target} (global position {r.insertion_position}); no covering or conflicting rules above."
