# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Cisco FMC access-policy export (JSON, expanded=true) -> NormalizedRule (offline, read-only).

Evaluation order: Prefilter policy, then ACP mandatory section, then default section,
then the policy default action. FTD access rules match on real (untranslated) IPs.

Expected export shape (a sanitized merge of FMC REST GET responses)::

    {
      "accessPolicy": {"name": ..., "id": ..., "defaultAction": "BLOCK", "defaultLogEnd": true},
      "objects": {"networks": {name: {"type": "Host|Network|Range|FQDN", "value": ...}},
                  "networkGroups": {name: [member, ...]},
                  "dynamicObjects": [name, ...],
                  "ports": {name: [{"protocol": "6", "port": "443"}]},
                  "portGroups": {name: [member, ...]}},
      "prefilterRules": [...],          # GET .../prefilterpolicies/{id}/prefilterrules?expanded=true
      "items": [...]                    # GET .../accesspolicies/{id}/accessrules?expanded=true
    }
"""

from __future__ import annotations

import json
from pathlib import Path

from agenttrustsec.review.analysis.address_math import PROTOCOL_NUMBERS, ObjectResolver, parse_service_token
from agenttrustsec.review.models.normalized_rule import ANY, InspectionProfile, NormalizedRule, PortRange, any_addresses, any_services

_ACP_ACTIONS = {"ALLOW": "allow", "TRUST": "trust", "BLOCK": "deny", "BLOCK_RESET": "reset",
                "BLOCK_INTERACTIVE": "deny", "BLOCK_RESET_INTERACTIVE": "reset", "MONITOR": "monitor"}
_PREFILTER_ACTIONS = {"FASTPATH": "fastpath", "BLOCK": "deny", "ANALYZE": "monitor"}


def _build_resolver(objects: dict) -> ObjectResolver:
    table: dict[str, dict] = {}
    for name, obj in objects.get("networks", {}).items():
        kind = obj.get("type", "Network")
        table[name] = {"type": "fqdn", "value": obj.get("value", "")} if kind == "FQDN" else {"type": "ip", "value": obj["value"]}
    for name, members in objects.get("networkGroups", {}).items():
        table[name] = {"type": "group", "members": members}
    for name in objects.get("dynamicObjects", []):
        table[name] = {"type": "dynamic"}
    return ObjectResolver(table)


def _names(block: dict | None, key: str = "objects") -> list[str]:
    return [o["name"] for o in (block or {}).get(key, []) if o.get("name")]


def _addresses(block: dict | None, resolver: ObjectResolver):
    if not block:
        return any_addresses()
    out = []
    for o in block.get("objects", []):
        unresolvable = {"FQDN": "fqdn", "DynamicObject": "dynamic"}.get(o.get("type", ""))
        if unresolvable and o["name"] not in resolver.objects:
            resolver.objects[o["name"]] = {"type": unresolvable}
        if "value" in o and o.get("type") in ("Host", "Network", "Range"):
            out.extend(resolver.resolve(o["value"]))
        else:
            out.extend(resolver.resolve(o["name"]))
    for lit in block.get("literals", []):
        out.extend(resolver.resolve(lit["value"]))
    return out or any_addresses()


def _port_spec(p: dict) -> str:
    proto = PROTOCOL_NUMBERS.get(str(p.get("protocol", "")), str(p.get("protocol", "")).lower())
    if proto == "icmp":
        return "icmp"
    return f"{proto}/{p['port']}" if p.get("port") else f"{proto}/0-65535"


def _ports(block: dict | None, objects: dict) -> tuple[list[PortRange], list[str]]:
    if not block:
        return any_services(), []
    port_objs, port_groups = objects.get("ports", {}), objects.get("portGroups", {})
    out: list[PortRange] = []
    unresolved: list[str] = []

    def expand(name: str, seen: tuple = ()):
        if name in port_objs:
            for p in port_objs[name]:
                out.extend(parse_service_token(_port_spec(p), source_object=name))
        elif name in port_groups and name not in seen:
            for m in port_groups[name]:
                expand(m, seen + (name,))
        else:
            unresolved.append(name)

    for o in block.get("objects", []):
        if "protocol" in o:
            out.extend(parse_service_token(_port_spec(o), source_object=o.get("name")))
        else:
            expand(o["name"])
    for lit in block.get("literals", []):
        out.extend(parse_service_token(_port_spec(lit), source_object="literal"))
    if not out and not unresolved:
        out = any_services()
    return out, unresolved


def _rule(r: dict, *, position: int, layer: str, action: str, resolver: ObjectResolver, objects: dict,
          policy_name: str) -> NormalizedRule:
    zone_src = r.get("sourceZones") or r.get("sourceInterfaces")
    zone_dst = r.get("destinationZones") or r.get("destinationInterfaces")
    services, unresolved_svc = _ports(r.get("destinationPorts"), objects)
    apps = _names(r.get("applications"), "applications") or [ANY]
    return NormalizedRule(
        vendor="ftd",
        rule_id=r.get("id") or r["name"],
        name=r["name"],
        position=position,
        layer=layer,
        action=action,
        enabled=r.get("enabled", True),
        src_zones=_names(zone_src) or [ANY],
        dst_zones=_names(zone_dst) or [ANY],
        src_addrs=_addresses(r.get("sourceNetworks"), resolver),
        dst_addrs=_addresses(r.get("destinationNetworks"), resolver),
        services=services,
        unresolved_services=unresolved_svc,
        applications=apps,
        users=_names(r.get("users")),
        inspection=InspectionProfile(
            intrusion_policy=(r.get("ipsPolicy") or {}).get("name"),
            file_policy=(r.get("filePolicy") or {}).get("name"),
        ),
        log_at_end=bool(r.get("logEnd", False)),
        raw_ref=f"{policy_name}/{layer}/{r.get('id') or r['name']}",
    )


def load_offline(path: str | Path, device_group: str | None = None) -> list[NormalizedRule]:
    """Parse an FMC export. ``device_group`` (access policy name) is checked when given."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    policy = data.get("accessPolicy", {})
    policy_name = policy.get("name", "access-policy")
    if device_group and policy.get("name") and device_group != policy["name"]:
        raise ValueError(f"Access policy {device_group!r} not found in {path} (found {policy_name!r})")
    objects = data.get("objects", {})
    resolver = _build_resolver(objects)

    rules: list[NormalizedRule] = []
    for r in data.get("prefilterRules", []):
        rules.append(_rule(r, position=len(rules) + 1, layer="prefilter",
                           action=_PREFILTER_ACTIONS.get(r.get("action", "ANALYZE"), "monitor"),
                           resolver=resolver, objects=objects, policy_name=policy_name))

    items = data.get("items", [])
    items = sorted(items, key=lambda r: (r.get("metadata", {}).get("section", "Mandatory").lower() != "mandatory",
                                         r.get("metadata", {}).get("ruleIndex", 0)))
    for r in items:
        layer = r.get("metadata", {}).get("section", "Mandatory").lower()
        rules.append(_rule(r, position=len(rules) + 1, layer=layer,
                           action=_ACP_ACTIONS.get(r.get("action", "BLOCK"), "deny"),
                           resolver=resolver, objects=objects, policy_name=policy_name))

    default = policy.get("defaultAction", "BLOCK").upper()
    rules.append(NormalizedRule(
        vendor="ftd", rule_id=f"{policy_name}:default-action", name="DefaultAction", position=len(rules) + 1,
        layer="default-action", action="deny" if "BLOCK" in default else "allow",
        src_addrs=any_addresses(), dst_addrs=any_addresses(), services=any_services(),
        log_at_end=bool(policy.get("defaultLogEnd", False)), raw_ref=f"{policy_name}/defaultAction"))
    return rules
