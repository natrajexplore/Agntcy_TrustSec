# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""RG-xxx risk check catalog. Pure functions; thresholds come from data/risk_policy.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel, Field

from agenttrustsec.review.analysis import address_math as am
from agenttrustsec.review.analysis.shadow import ShadowReport, request_to_rule
from agenttrustsec.review.models.change_request import NormalizedChangeRequest
from agenttrustsec.review.models.findings import Decision, Evidence, Finding, RiskReport, Severity
from agenttrustsec.review.models.normalized_rule import ANY, PERMIT_ACTIONS, NormalizedRule, PortRange

# --------------------------------------------------------------------------- policy


class RiskPolicy(BaseModel):
    severity_weights: dict[Severity, int] = Field(default_factory=lambda: {
        Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 5, Severity.INFO: 0})
    check_severity: dict[str, Severity] = Field(default_factory=dict)
    broad_prefix: dict[str, int] = Field(default_factory=lambda: {"ipv4": 16, "ipv6": 48})
    untrust_zones: list[str] = Field(default_factory=lambda: ["untrust", "outside", "internet"])
    management_zones: list[str] = Field(default_factory=lambda: ["mgmt", "management", "oob-mgmt"])
    sensitive_zones: dict[str, list[str]] = Field(default_factory=dict)
    management_ports: list[str] = Field(default_factory=lambda: ["tcp/22", "tcp/3389", "udp/161", "udp/162"])
    management_https_ports: list[str] = Field(default_factory=lambda: ["tcp/443"])
    cleartext_ports_always: list[str] = Field(default_factory=lambda: ["tcp/23", "tcp/21"])
    cleartext_ports_from_untrust: list[str] = Field(default_factory=lambda: ["tcp/80", "tcp/445", "tcp/139"])
    cleartext_apps_always: list[str] = Field(default_factory=lambda: ["telnet", "ftp"])
    cleartext_apps_from_untrust: list[str] = Field(default_factory=lambda: ["web-browsing", "ms-ds-smb"])
    file_policy_ports: list[str] = Field(default_factory=lambda: ["tcp/80", "tcp/21", "tcp/445", "tcp/25"])
    trust_action_severity: Severity = Severity.MEDIUM
    min_justification_length: int = 15


def load_policy(path: str | Path | None = None) -> RiskPolicy:
    """Load risk policy YAML; built-in defaults apply for anything not set."""
    p = Path(path) if path else Path(__file__).resolve().parents[1] / "data" / "risk_policy.yaml"
    if not p.exists():
        return RiskPolicy()
    return RiskPolicy.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")) or {})


def _ports(specs: list[str]) -> list[PortRange]:
    return [r for s in specs for r in am.parse_service_token(s)]


# --------------------------------------------------------------------------- registry


@dataclass
class CheckContext:
    policy: RiskPolicy
    shadow: ShadowReport
    candidate: NormalizedRule

    def severity_for(self, check_id: str) -> Severity:
        return self.policy.check_severity.get(check_id, CHECKS[check_id].default_severity)


@dataclass
class RegisteredCheck:
    check_id: str
    default_severity: Severity
    vendors: set[str]
    func: Callable[[NormalizedChangeRequest, CheckContext], list[Finding]]


CHECKS: dict[str, RegisteredCheck] = {}


def register_check(check_id: str, default_severity: Severity, vendors: set[str] | None = None):
    def deco(func):
        if check_id in CHECKS:
            raise ValueError(f"duplicate check id {check_id}")
        CHECKS[check_id] = RegisteredCheck(check_id, default_severity, vendors or {"panos", "ftd"}, func)
        return func
    return deco


def _is_permit(ctx: CheckContext) -> bool:
    return ctx.candidate.action in PERMIT_ACTIONS


def _f(ctx: CheckContext, check_id: str, title: str, detail: str, evidence: list[Evidence],
       remediation: str | None = None, severity: Severity | None = None, compliance: list[str] | None = None) -> Finding:
    return Finding(check_id=check_id, severity=severity or ctx.severity_for(check_id), title=title, detail=detail,
                   evidence=evidence, remediation=remediation, compliance=compliance or [])


def _req(field: str, detail: str | None = None) -> Evidence:
    return Evidence(kind="request_field", ref=field, detail=detail)


def _rule(ref, detail: str | None = None) -> Evidence:
    return Evidence(kind="rule", ref=f"#{ref.position} {ref.name} [{ref.rule_id}]", detail=detail)


def _resolved(entries):
    return [e for e in entries if not e.unresolved]


def _zone_hit(zones: list[str], targets: list[str]) -> list[str]:
    if ANY in zones:
        return [ANY]
    return [z for z in zones if z.lower() in {t.lower() for t in targets}]


# --------------------------------------------------------------------------- checks


@register_check("RG-001", Severity.CRITICAL)
def check_any_any(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Source any and destination any on a permit rule exposes everything to everything."""
    c = ctx.candidate
    if _is_permit(ctx) and am.is_any_address(_resolved(c.src_addrs)) and am.is_any_address(_resolved(c.dst_addrs)):
        return [_f(ctx, "RG-001", "Source any to destination any on allow",
                   "The rule permits every source to reach every destination in the selected zones.",
                   [_req("request.source", "any"), _req("request.destination", "any")],
                   "Restrict source and destination to the specific hosts or subnets named in the justification.")]
    return []


@register_check("RG-002", Severity.HIGH)
def check_service_any(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Service any on a permit rule opens every port and protocol."""
    c = ctx.candidate
    if _is_permit(ctx) and not c.app_default_service and am.is_any_service(c.services):
        return [_f(ctx, "RG-002", "Service / port any on allow",
                   "All ports and protocols are permitted between the requested endpoints.",
                   [_req("request.service", "any")],
                   "List the exact protocol/port pairs the application needs (or application-default with an App-ID on PAN-OS).")]
    return []


@register_check("RG-003", Severity.HIGH)
def check_untrust_to_internal(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Inbound access from an untrusted zone into internal zones."""
    c, p = ctx.candidate, ctx.policy
    src_hit = _zone_hit(c.src_zones, p.untrust_zones)
    internal_dst = [z for z in c.dst_zones if z == ANY or z.lower() not in {u.lower() for u in p.untrust_zones}]
    if _is_permit(ctx) and src_hit and internal_dst:
        return [_f(ctx, "RG-003", "Untrusted source to internal destination",
                   f"Traffic from {', '.join(c.src_zones)} is permitted into {', '.join(internal_dst)}.",
                   [_req("request.source_zone", ", ".join(c.src_zones)), _req("request.destination_zone", ", ".join(internal_dst))],
                   "Terminate external access in a DMZ, restrict the source to known partner addresses, and apply full inspection.")]
    return []


@register_check("RG-004", Severity.MEDIUM)
def check_broad_cidr(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Overly broad source or destination prefixes (one side any counts as broad)."""
    c, p = ctx.candidate, ctx.policy
    if not _is_permit(ctx):
        return []
    src_any, dst_any = am.is_any_address(_resolved(c.src_addrs)), am.is_any_address(_resolved(c.dst_addrs))
    findings_ev: list[Evidence] = []
    for field, entries, is_any in (("request.source", c.src_addrs, src_any), ("request.destination", c.dst_addrs, dst_any)):
        if is_any and not (src_any and dst_any):
            findings_ev.append(_req(field, "any"))
            continue
        if is_any:
            continue
        for e in _resolved(entries):
            n = e.network()
            limit = p.broad_prefix["ipv4" if n.version == 4 else "ipv6"]
            if n.prefixlen <= limit:
                findings_ev.append(_req(field, f"{n} (/{n.prefixlen} is at or broader than /{limit})"))
    if findings_ev:
        return [_f(ctx, "RG-004", "Overly broad address scope",
                   "One or more address entries cover far more hosts than a typical application flow needs.",
                   findings_ev, "Narrow to the specific hosts or the smallest subnet that contains them.")]
    return []


@register_check("RG-005", Severity.MEDIUM, vendors={"panos"})
def check_app_any(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """PAN-OS rule without an App-ID is port-based and weaker than App-ID enforcement."""
    if _is_permit(ctx) and ANY in ctx.candidate.applications:
        return [_f(ctx, "RG-005", "Application any (port-based rule)",
                   "Without an App-ID the firewall allows any application on the permitted ports.",
                   [_req("request.application", "any")],
                   "Specify the App-ID(s) and use service application-default where possible.")]
    return []


@register_check("RG-006", Severity.HIGH, vendors={"panos"})
def check_panos_profiles(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """PAN-OS allow without a Security Profile Group skips threat inspection."""
    if ctx.candidate.action == "allow" and not ctx.candidate.inspection.has_panos_inspection():
        return [_f(ctx, "RG-006", "No Security Profile Group",
                   "Allowed traffic would not be inspected by AV, anti-spyware, vulnerability, URL or WildFire profiles.",
                   [_req("request.security_profile_group", "not set")],
                   "Attach the standard Security Profile Group (e.g. Strict-Inspection).")]
    return []


@register_check("RG-007", Severity.HIGH, vendors={"ftd"})
def check_ftd_intrusion(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """FTD Allow rule without an Intrusion Policy (and File Policy for file-capable protocols)."""
    c = ctx.candidate
    if c.action != "allow":
        return []
    ev: list[Evidence] = []
    if not c.inspection.intrusion_policy:
        ev.append(_req("request.intrusion_policy", "not set"))
    file_capable = am.services_overlap(c.services, _ports(ctx.policy.file_policy_ports))
    if file_capable and not c.inspection.file_policy:
        ev.append(_req("request.file_policy", "not set on a file-capable protocol"))
    if ev:
        return [_f(ctx, "RG-007", "Allow rule without intrusion / file inspection",
                   "Snort intrusion inspection (and file/malware inspection where relevant) would not apply to this traffic.",
                   ev, "Attach the standard Intrusion Policy, and a File Policy for HTTP/FTP/SMB/SMTP flows.")]
    return []


@register_check("RG-008", Severity.HIGH, vendors={"ftd"})
def check_ftd_bypass(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """FTD Trust (no deep inspection) or Prefilter Fastpath (bypasses the ACP entirely)."""
    a = ctx.candidate.action
    if a == "fastpath":
        return [_f(ctx, "RG-008", "Prefilter Fastpath bypasses inspection",
                   "Fastpathed traffic skips the Access Control Policy, Snort, and all security intelligence.",
                   [_req("request.prefilter_fastpath", "true")],
                   "Use an ACP Allow rule with intrusion inspection; reserve Fastpath for documented high-throughput trusted flows.")]
    if a == "trust":
        return [_f(ctx, "RG-008", "Trust action skips deep inspection",
                   "Trusted traffic is not inspected by intrusion or file policies.",
                   [_req("request.ftd_action", "trust")],
                   "Use Allow with an Intrusion Policy unless a documented performance exception exists.",
                   severity=ctx.policy.trust_action_severity)]
    return []


@register_check("RG-009", Severity.MEDIUM)
def check_logging(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Logging disabled (PAN log-end / FTD end-of-connection logging)."""
    if not ctx.candidate.log_at_end:
        return [_f(ctx, "RG-009", "Logging disabled",
                   "Sessions matching this rule would leave no end-of-session log for investigation or audit.",
                   [_req("request.logging", "false")], "Enable log-at-session-end and forward logs to the SIEM.")]
    return []


@register_check("RG-010", Severity.HIGH)
def check_cleartext(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Cleartext or legacy protocols (telnet, FTP always; HTTP, SMB from untrust)."""
    c, p = ctx.candidate, ctx.policy
    if not _is_permit(ctx) or am.is_any_service(c.services):
        return []  # service any is RG-002
    from_untrust = bool(_zone_hit(c.src_zones, p.untrust_zones))
    ports = p.cleartext_ports_always + (p.cleartext_ports_from_untrust if from_untrust else [])
    apps = p.cleartext_apps_always + (p.cleartext_apps_from_untrust if from_untrust else [])
    svc = am.effective_services(c) or []
    ev = [_req("request.service", s) for s in ports if am.services_overlap(svc, _ports([s]))]
    ev += [_req("request.application", a) for a in c.applications if a in apps]
    if ev:
        return [_f(ctx, "RG-010", "Cleartext or legacy protocol",
                   "Credentials and data on these protocols travel unencrypted.",
                   ev, "Use the encrypted equivalent (SSH/SFTP/HTTPS/SMB3 over VPN).")]
    return []


@register_check("RG-011", Severity.HIGH)
def check_mgmt_ports(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Management ports reachable from non-management source zones."""
    c, p = ctx.candidate, ctx.policy
    if not _is_permit(ctx) or am.is_any_service(c.services):
        return []
    mgmt_src = {z.lower() for z in p.management_zones}
    if c.src_zones != [ANY] and all(z.lower() in mgmt_src for z in c.src_zones):
        return []
    svc = am.effective_services(c) or []
    ports = list(p.management_ports)
    if _zone_hit(c.dst_zones, p.management_zones):
        ports += p.management_https_ports
    ev = [_req("request.service", s) for s in ports if am.services_overlap(svc, _ports([s]))]
    if ev:
        ev.insert(0, _req("request.source_zone", ", ".join(c.src_zones)))
        return [_f(ctx, "RG-011", "Management port from non-management zone",
                   "Administrative protocols should only be reachable from management/jump-host zones.",
                   ev, "Source the access from the management zone or a PAM jump host.")]
    return []


@register_check("RG-012", Severity.LOW)
def check_hygiene(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Missing business justification, ticket reference, or expiry on a temporary request."""
    ev: list[Evidence] = []
    if len((req.business_justification or "").strip()) < ctx.policy.min_justification_length:
        ev.append(_req("business_justification", "missing or too short"))
    if not req.ticket_ref:
        ev.append(_req("ticket_ref", "missing"))
    if req.temporary and not req.expiry:
        ev.append(_req("expiry", "temporary request without expiry"))
    if ev:
        return [_f(ctx, "RG-012", "Missing change metadata",
                   "The request lacks information the CAB needs to approve and later recertify the rule.",
                   ev, "Provide a business justification, ticket reference, and an expiry date for temporary access.")]
    return []


@register_check("RG-013", Severity.INFO)
def check_duplicate(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Requested access is already permitted (or denied) by an existing rule."""
    d = ctx.shadow.duplicate_of
    if d:
        return [_f(ctx, "RG-013", "Access already exists",
                   f"The requested traffic already matches {d.label()} first in the current rulebase.",
                   [_rule(d, "first full match")], "Close the request as duplicate; no change is required.")]
    return []


@register_check("RG-014", Severity.HIGH)
def check_shadowed(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """New rule would be shadowed by a broader rule above its placement."""
    s = ctx.shadow.shadowed_by
    if s:
        return [_f(ctx, "RG-014", "New rule would be shadowed",
                   f"{s.label()} sits above the requested placement and fully covers the request, so the new rule never matches.",
                   [_rule(s, "covers request above placement")], ctx.shadow.recommended_placement)]
    return []


@register_check("RG-015", Severity.CRITICAL)
def check_deny_override(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """New permit would sit above an explicit deny that it overlaps."""
    denies = ctx.shadow.deny_overrides
    if denies:
        return [_f(ctx, "RG-015", "Would override an existing deny",
                   "The new rule would permit traffic that an explicit block rule below it is meant to stop: "
                   + ", ".join(d.label() for d in denies) + ".",
                   [_rule(d, "explicit block overlapped") for d in denies], ctx.shadow.recommended_placement)]
    return []


@register_check("RG-016", Severity.HIGH)
def check_sensitive_zone(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """Request crosses into or out of a sensitive zone (PCI / CDE / OT / management)."""
    c, p = ctx.candidate, ctx.policy
    if not _is_permit(ctx) or not p.sensitive_zones:
        return []
    sensitive = {z.lower(): refs for z, refs in p.sensitive_zones.items()}
    ev: list[Evidence] = []
    refs: list[str] = []
    for field, zones in (("request.source_zone", c.src_zones), ("request.destination_zone", c.dst_zones)):
        for z in zones:
            if z == ANY:
                ev.append(_req(field, "any (includes sensitive zones: " + ", ".join(p.sensitive_zones) + ")"))
                refs += [r for rs in sensitive.values() for r in rs]
            elif z.lower() in sensitive:
                ev.append(_req(field, z))
                refs += sensitive[z.lower()]
    if ev:
        return [_f(ctx, "RG-016", "Crosses a sensitive zone",
                   "Access into or out of a regulated / high-value zone needs compliance review and strict scoping.",
                   ev, "Limit to named hosts and ports, enable full inspection and logging, and attach compliance sign-off.",
                   compliance=sorted(set(refs)))]
    return []


# --------------------------------------------------------------------------- scanner


def decide(findings: list[Finding]) -> Decision:
    ids = {f.check_id for f in findings}
    sev = {f.severity for f in findings}
    if Severity.CRITICAL in sev:
        return Decision.REJECT
    if "RG-013" in ids:
        return Decision.REJECT_DUPLICATE
    if Severity.HIGH in sev:
        return Decision.APPROVE_WITH_CONDITIONS
    return Decision.APPROVE


def scan(cr: NormalizedChangeRequest, shadow: ShadowReport, policy: RiskPolicy) -> RiskReport:
    """Run every applicable RG check and produce the scored, decided risk report."""
    ctx = CheckContext(policy=policy, shadow=shadow, candidate=request_to_rule(cr))
    findings: list[Finding] = []
    for check in sorted(CHECKS.values(), key=lambda c: c.check_id):
        if cr.target.vendor in check.vendors:
            findings.extend(check.func(cr, ctx))

    notes: list[str] = []
    for n in shadow.needs_review:
        notes.append(f"{n.rule.label()}: {n.reason} — duplicate/shadow/conflict results for this rule are not definitive.")
    unresolved_req = [e.value for e in ctx.candidate.src_addrs + ctx.candidate.dst_addrs if e.unresolved]
    if unresolved_req:
        notes.append("Request contains non-literal addresses that could not be resolved: " + ", ".join(unresolved_req))
    if req_users := cr.request.users:
        notes.append("Request is user-based (" + ", ".join(req_users) + "); user/group membership is not evaluated offline.")
    notes += shadow.placement_notes

    weights = policy.severity_weights
    score = min(100, sum(weights.get(f.severity, 0) for f in findings))
    max_sev = max((f.severity for f in findings), key=lambda s: s.rank, default=None)
    return RiskReport(
        change_id=cr.change_id,
        vendor=cr.target.vendor,
        device_group=cr.target.device_group,
        findings=findings,
        risk_score=score,
        decision=decide(findings),
        max_severity=max_sev,
        needs_human_review=bool(shadow.needs_review or unresolved_req or cr.request.users),
        review_notes=notes,
    )
