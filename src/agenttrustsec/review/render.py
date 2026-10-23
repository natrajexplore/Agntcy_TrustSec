# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Staged configuration, test plan and rollback rendering (text only, never sent to a device)."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel

from agenttrustsec.review.analysis.shadow import request_to_rule
from agenttrustsec.review.engine import ReviewContext

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES), undefined=StrictUndefined,
                   trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
_env.filters["json"] = lambda v: json.dumps(v, indent=2)  # keeps field order and <placeholders> readable

_PROTO_NUM = {"tcp": "6", "udp": "17", "sctp": "132", "icmp": "1"}


class StagedConfig(BaseModel):
    vendor: str
    filename: str
    rule_name: str
    config: str
    test_plan: list[str]
    rollback: list[str]


def _rule_name(change_id: str, req) -> str:
    base = f"{change_id}-{req.source_zone[0]}-to-{req.destination_zone[0]}"
    return re.sub(r"[^A-Za-z0-9_.-]", "-", base)[:63]


def _first_host(values: list[str], default: str) -> str:
    for v in values:
        try:
            net = ipaddress.ip_network(v, strict=False)
            return str(net.network_address if net.prefixlen == net.max_prefixlen else next(net.hosts(), net.network_address))
        except ValueError:
            continue
    return default


def _test_flows(ctx: ReviewContext) -> list[dict]:
    cand = request_to_rule(ctx.request)
    req = ctx.request.request
    src = _first_host(req.source, "<source-ip>")
    dst = _first_host(req.destination, "<destination-ip>")
    flows = []
    for s in cand.services or []:
        if s.protocol in ("tcp", "udp"):
            flows.append({"proto": s.protocol, "proto_num": _PROTO_NUM[s.protocol], "port": s.start, "src": src, "dst": dst})
    if not flows:
        flows.append({"proto": "tcp", "proto_num": "6", "port": "<port>", "src": src, "dst": dst})
    return flows


def render_panos(ctx: ReviewContext) -> StagedConfig:
    cr, req = ctx.request, ctx.request.request
    name = _rule_name(cr.change_id, req)
    services, service_objects = [], []
    for s in req.service:
        if s in ("any", "application-default"):
            services.append(s)
            continue
        proto, _, ports = s.partition("/")
        obj = f"{proto}-{ports.replace(',', '_')}"
        service_objects.append({"name": obj, "proto": proto, "ports": ports})
        services.append(obj)
    scope = f"device-group {cr.target.device_group} pre-rulebase" if cr.target.device_group else "rulebase"
    obj_scope = f"device-group {cr.target.device_group} " if cr.target.device_group else ""
    config = _env.get_template("panos_set.j2").render(
        cr=cr, req=req, name=name, scope=scope, obj_scope=obj_scope, services=services,
        service_objects=service_objects, shadow=ctx.shadow)
    flows = _test_flows(ctx)
    tests = [f"test security-policy-match from {req.source_zone[0]} to {req.destination_zone[0]} source {f['src']} "
             f"destination {f['dst']} protocol {f['proto_num']} destination-port {f['port']}"
             + (f" application {req.application[0]}" if req.application != ['any'] else "") for f in flows]
    return StagedConfig(
        vendor="panos", filename="staged_config.set", rule_name=name, config=config,
        test_plan=[f"PRE-CHANGE (expect current behaviour, see shadow analysis): {t}" for t in tests]
                  + [f"POST-CHANGE (expect match on rule {name}): {t}" for t in tests]
                  + ["POST-CHANGE: confirm traffic log entries for the rule (log-end) and zero threat-log drops for legitimate flows."],
        rollback=[f"delete {scope} security rules {name}"]
                 + [f"delete {obj_scope}service {o['name']}  # only if not referenced elsewhere" for o in service_objects]
                 + ["commit; push to device group (Panorama) through the normal change process"],
    )


def render_ftd(ctx: ReviewContext) -> StagedConfig:
    cr, req = ctx.request, ctx.request.request
    name = _rule_name(cr.change_id, req)
    cand = request_to_rule(cr)
    is_fastpath = cand.action == "fastpath"

    def net_literals(values: list[str]) -> list[dict]:
        out = []
        for v in values:
            if v == "any":
                return []
            net = ipaddress.ip_network(v, strict=False)
            out.append({"type": "Host" if net.prefixlen == net.max_prefixlen else "Network",
                        "value": str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)})
        return out

    port_literals = [] if any(s.protocol == "any" for s in cand.services) else [
        {"type": "PortLiteral", "protocol": _PROTO_NUM[s.protocol],
         **({"port": str(s.start) if s.start == s.end else f"{s.start}-{s.end}"} if s.protocol != "icmp" else {})}
        for s in cand.services]
    payload = {
        "name": name,
        "type": "PrefilterRule" if is_fastpath else "AccessRule",
        "action": {"allow": "ALLOW", "trust": "TRUST", "fastpath": "FASTPATH", "deny": "BLOCK"}[cand.action],
        "enabled": True,
        ("sourceInterfaces" if is_fastpath else "sourceZones"): {"objects": [
            {"name": z, "type": "SecurityZone", "id": f"<UUID of zone {z}>"} for z in req.source_zone if z != "any"]},
        ("destinationInterfaces" if is_fastpath else "destinationZones"): {"objects": [
            {"name": z, "type": "SecurityZone", "id": f"<UUID of zone {z}>"} for z in req.destination_zone if z != "any"]},
        "sourceNetworks": {"literals": net_literals(req.source)},
        "destinationNetworks": {"literals": net_literals(req.destination)},
        "destinationPorts": {"literals": port_literals},
        "logBegin": False,
        "logEnd": req.logging,
        "sendEventsToFMC": req.logging,
    }
    if cand.action == "allow" and req.intrusion_policy:
        payload["ipsPolicy"] = {"name": req.intrusion_policy, "type": "IntrusionPolicy", "id": "<UUID of intrusion policy>"}
    if cand.action == "allow" and req.file_policy:
        payload["filePolicy"] = {"name": req.file_policy, "type": "FilePolicy", "id": "<UUID of file policy>"}
    endpoint = ("/api/fmc_config/v1/domain/{domainUUID}/policy/prefilterpolicies/{prefilterPolicyUUID}/prefilterrules"
                if is_fastpath else
                "/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{accessPolicyUUID}/accessrules")
    config = _env.get_template("fmc_accessrule.json.j2").render(
        cr=cr, payload=payload, endpoint=endpoint, shadow=ctx.shadow,
        section=ctx.shadow.section)
    flows = _test_flows(ctx)
    tests = [f"packet-tracer input <ingress-interface-for-{req.source_zone[0]}> {f['proto']} {f['src']} 54321 {f['dst']} {f['port']} detail"
             for f in flows]
    return StagedConfig(
        vendor="ftd", filename="staged_config.fmc.json", rule_name=name, config=config,
        test_plan=[f"PRE-CHANGE (FTD CLI, read-only diagnostic): {t}" for t in tests]
                  + [f"POST-CHANGE (expect match on rule {name}): {t}" for t in tests]
                  + ["POST-CHANGE: verify Connection Events in FMC show the new rule with end-of-connection logging."],
        rollback=[f"DELETE {endpoint}/<UUID of rule {name}> (via FMC UI or API, by an engineer with change approval)",
                  "Deploy the policy to the affected FTD devices from FMC",
                  "Re-run the packet-tracer test and confirm the previous behaviour is restored"],
    )


def render(ctx: ReviewContext) -> StagedConfig:
    return render_panos(ctx) if ctx.request.target.vendor == "panos" else render_ftd(ctx)
