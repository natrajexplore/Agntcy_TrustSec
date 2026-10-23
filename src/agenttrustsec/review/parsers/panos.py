# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""PAN-OS / Panorama running-config XML -> NormalizedRule (offline, read-only).

Evaluation order: Panorama pre-rulebase, then local (vsys) rules, then post-rulebase.
Security rules match on pre-NAT IP / post-NAT zone; the export already reflects that.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from agenttrustsec.review.analysis.address_math import ObjectResolver, parse_service_token
from agenttrustsec.review.models.normalized_rule import ANY, InspectionProfile, NormalizedRule, PortRange, any_services

# Predefined PAN-OS service objects
PREDEFINED_SERVICES = {
    "service-http": ["tcp/80", "tcp/8080"],
    "service-https": ["tcp/443"],
}

_ACTIONS = {"allow": "allow", "deny": "deny", "drop": "drop",
            "reset-client": "reset", "reset-server": "reset", "reset-both": "reset"}


def _members(node: ET.Element | None, tag: str) -> list[str]:
    if node is None:
        return []
    el = node.find(tag)
    return [m.text.strip() for m in el.findall("member") if m.text] if el is not None else []


def _collect_address_objects(scopes: list[ET.Element]) -> dict[str, dict]:
    """Later scopes override earlier ones (shared first, then device-group / vsys)."""
    objs: dict[str, dict] = {}
    for scope in scopes:
        for e in scope.findall("./address/entry"):
            name = e.get("name")
            if (v := e.findtext("ip-netmask")) or (v := e.findtext("ip-range")):
                objs[name] = {"type": "ip", "value": v.strip()}
            elif e.find("fqdn") is not None:
                objs[name] = {"type": "fqdn", "value": e.findtext("fqdn", "").strip()}
            else:
                objs[name] = {"type": "unsupported"}
        for g in scope.findall("./address-group/entry"):
            name = g.get("name")
            if g.find("static") is not None:
                objs[name] = {"type": "group", "members": _members(g, "static")}
            else:
                objs[name] = {"type": "dynamic"}
        for edl in scope.findall("./external-list/entry"):
            objs[edl.get("name")] = {"type": "edl"}
    return objs


def _collect_service_objects(scopes: list[ET.Element]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    services: dict[str, list[str]] = dict(PREDEFINED_SERVICES)
    groups: dict[str, list[str]] = {}
    for scope in scopes:
        for e in scope.findall("./service/entry"):
            for proto in ("tcp", "udp", "sctp"):
                port = e.findtext(f"protocol/{proto}/port")
                if port:
                    services[e.get("name")] = [f"{proto}/{port.strip()}"]
        for g in scope.findall("./service-group/entry"):
            groups[g.get("name")] = _members(g, "members")
    return services, groups


def _resolve_services(names: list[str], services: dict, groups: dict, seen: tuple = ()) -> tuple[list[PortRange], list[str]]:
    """Return (resolved port ranges, unresolved service names)."""
    out: list[PortRange] = []
    unresolved: list[str] = []
    for n in names:
        if n == ANY:
            out.extend(any_services())
        elif n in services:
            for spec in services[n]:
                out.extend(parse_service_token(spec, source_object=n))
        elif n in groups and n not in seen:
            sub, unres = _resolve_services(groups[n], services, groups, seen + (n,))
            out.extend(sub)
            unresolved.extend(unres)
        else:
            unresolved.append(n)
    return out, unresolved


def _rule_from_entry(e: ET.Element, *, position: int, layer: str, resolver: ObjectResolver,
                     services: dict, groups: dict, scope_ref: str) -> NormalizedRule:
    name = e.get("name")
    svc_names = _members(e, "service") or [ANY]
    app_default = svc_names == ["application-default"]
    svc, unresolved_svc = ([], []) if app_default else _resolve_services(svc_names, services, groups)
    users = [u for u in _members(e, "source-user") if u != ANY]
    profile = e.find("profile-setting")
    return NormalizedRule(
        vendor="panos",
        rule_id=e.get("uuid") or name,
        name=name,
        position=position,
        layer=layer,
        action=_ACTIONS.get((e.findtext("action") or "allow").strip(), "deny"),
        enabled=(e.findtext("disabled") or "no").strip() != "yes",
        src_zones=_members(e, "from") or [ANY],
        dst_zones=_members(e, "to") or [ANY],
        src_addrs=resolver.resolve_all(_members(e, "source") or [ANY]),
        dst_addrs=resolver.resolve_all(_members(e, "destination") or [ANY]),
        services=svc,
        unresolved_services=unresolved_svc,
        applications=_members(e, "application") or [ANY],
        app_default_service=app_default,
        users=users,
        inspection=InspectionProfile(
            profile_group=next(iter(_members(profile, "group")), None) if profile is not None else None,
            profiles=[m.text for m in profile.findall("profiles/*/member") if m.text] if profile is not None else [],
        ),
        log_at_end=(e.findtext("log-end") or "yes").strip() == "yes",
        raw_ref=f"{scope_ref}/{layer}/{name}",
    )


def load_offline(path: str | Path, device_group: str | None = None) -> list[NormalizedRule]:
    """Parse a Panorama or firewall running-config XML export.

    With Panorama exports, ``device_group`` selects the device group (first one if omitted).
    """
    root = ET.parse(path).getroot()
    shared = root.find("./shared")
    base_scopes = [shared] if shared is not None else []

    dg = None
    dgs = root.findall("./devices/entry/device-group/entry")
    if dgs:
        dg = next((d for d in dgs if d.get("name") == device_group), None) if device_group else dgs[0]
        if dg is None:
            raise ValueError(f"Device group {device_group!r} not found in {path}")

    layers: list[tuple[str, list[ET.Element], str, list[ET.Element]]] = []
    if dg is not None:
        scopes = base_scopes + [dg]
        ref = f"device-group:{dg.get('name')}"
        layers.append(("pre", dg.findall("./pre-rulebase/security/rules/entry"), ref, scopes))
        layers.append(("post", dg.findall("./post-rulebase/security/rules/entry"), ref, scopes))
    else:
        for vsys in root.findall("./devices/entry/vsys/entry"):
            scopes = base_scopes + [vsys]
            layers.append(("local", vsys.findall("./rulebase/security/rules/entry"), f"vsys:{vsys.get('name')}", scopes))

    rules: list[NormalizedRule] = []
    for layer, entries, ref, scopes in sorted(layers, key=lambda l: ["pre", "local", "post"].index(l[0])):
        resolver = ObjectResolver(_collect_address_objects(scopes))
        services, groups = _collect_service_objects(scopes)
        for e in entries:
            rules.append(_rule_from_entry(e, position=len(rules) + 1, layer=layer, resolver=resolver,
                                          services=services, groups=groups, scope_ref=ref))
    return rules
