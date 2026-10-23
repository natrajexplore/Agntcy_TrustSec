# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Deterministic address, service, zone and application math.

Containment is evaluated entry by entry: an inner network is covered when it is a
subnet of a single outer network of the same IP version. Coverage that only exists
across the union of several outer networks is not detected (conservative: it can
miss a duplicate, it never invents one).

Functions that may hit unresolved entries return ``None`` meaning "cannot decide".
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from agenttrustsec.review.models.normalized_rule import ANY, AddressEntry, NormalizedRule, PortRange, any_addresses, any_services

# PAN-OS App-ID standard ports used to expand "application-default".
# Unknown applications make the effective service set undecidable (None).
APP_DEFAULT_PORTS: dict[str, list[str]] = {
    "ssl": ["tcp/443"],
    "web-browsing": ["tcp/80"],
    "ssh": ["tcp/22"],
    "telnet": ["tcp/23"],
    "ftp": ["tcp/21"],
    "ms-rdp": ["tcp/3389"],
    "postgres": ["tcp/5432"],
    "mysql": ["tcp/3306"],
    "mssql-db": ["tcp/1433"],
    "oracle": ["tcp/1521"],
    "dns": ["udp/53", "tcp/53"],
    "ntp": ["udp/123"],
    "snmp": ["udp/161"],
    "ldap": ["tcp/389"],
    "smtp": ["tcp/25"],
    "ms-ds-smb": ["tcp/445"],
    "rsync": ["tcp/873"],
}

PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp", "132": "sctp", "1": "icmp"}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


# --------------------------------------------------------------------------- parsing

def parse_address_token(token: str, source_object: str | None = None) -> list[AddressEntry]:
    """Parse 'any', an IP, a CIDR, or an 'a-b' range into AddressEntry objects.

    Returns an empty list when the token is not a literal (it is then an object name).
    """
    token = token.strip()
    if token.lower() == ANY:
        return any_addresses()
    try:
        net = ipaddress.ip_network(token, strict=False)
        return [AddressEntry(value=str(net), source_object=source_object)]
    except ValueError:
        pass
    if "-" in token:
        lo, _, hi = token.partition("-")
        try:
            first, last = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
            return [AddressEntry(value=str(n), source_object=source_object or token)
                    for n in ipaddress.summarize_address_range(first, last)]
        except (ValueError, TypeError):
            pass
    return []


def parse_service_token(token: str, source_object: str | None = None) -> list[PortRange]:
    """Parse 'any', 'icmp', 'tcp/443', 'udp/1000-2000', 'tcp/80,8080' into PortRange objects."""
    token = token.strip().lower()
    if token == ANY:
        return any_services()
    if token == "icmp":
        return [PortRange(protocol="icmp", source_object=source_object)]
    proto, sep, ports = token.partition("/")
    if not sep or proto not in ("tcp", "udp", "sctp"):
        raise ValueError(f"Unsupported service {token!r}; use tcp/<port>, udp/<port>, icmp or any")
    return [_port_range(proto, p, source_object) for p in ports.split(",") if p.strip()]


def _port_range(proto: str, spec: str, source_object: str | None) -> PortRange:
    spec = spec.strip()
    if spec in ("", ANY):
        return PortRange(protocol=proto, start=0, end=65535, source_object=source_object)
    lo, _, hi = spec.partition("-")
    start, end = int(lo), int(hi or lo)
    if start > end:
        raise ValueError(f"Invalid port range {spec!r}")
    return PortRange(protocol=proto, start=start, end=end, source_object=source_object)


class ObjectResolver:
    """Recursive, cycle-safe resolver for vendor address objects and groups.

    ``objects`` maps name -> {"type": "ip"|"fqdn"|"dynamic"|"edl"|"group", "value": str, "members": [...]}.
    """

    def __init__(self, objects: dict[str, dict]):
        self.objects = objects

    def resolve(self, token: str) -> list[AddressEntry]:
        return self._resolve(token, stack=())

    def resolve_all(self, tokens: Iterable[str]) -> list[AddressEntry]:
        out: list[AddressEntry] = []
        for t in tokens:
            out.extend(self.resolve(t))
        return out

    def _resolve(self, token: str, stack: tuple[str, ...]) -> list[AddressEntry]:
        literal = parse_address_token(token, source_object=stack[0] if stack else None)
        if literal:
            return literal
        if token in stack:
            return [AddressEntry(value=token, unresolved=True, reason="group-cycle")]
        obj = self.objects.get(token)
        if obj is None:
            return [AddressEntry(value=token, unresolved=True, reason="unknown-object")]
        kind = obj.get("type")
        origin = stack[0] if stack else token
        if kind == "ip":
            entries = parse_address_token(obj["value"], source_object=origin)
            return entries or [AddressEntry(value=token, unresolved=True, reason="unparseable-object")]
        if kind == "group":
            out: list[AddressEntry] = []
            for m in obj.get("members", []):
                out.extend(self._resolve(m, stack + (token,)))
            return out
        # fqdn / dynamic address group / EDL: never guessed offline
        return [AddressEntry(value=token, source_object=origin, unresolved=True, reason=kind or "unknown")]


# --------------------------------------------------------------------------- addresses

def has_unresolved(entries: Iterable[AddressEntry]) -> bool:
    return any(e.unresolved for e in entries)


def is_any_address(entries: list[AddressEntry]) -> bool:
    nets = {str(e.network()) for e in entries if not e.unresolved}
    return "0.0.0.0/0" in nets or "::/0" in nets


def _same_version(a: Network, b: Network) -> bool:
    return a.version == b.version


def addrs_contain(outer: list[AddressEntry], inner: list[AddressEntry]) -> bool | None:
    if has_unresolved(outer) or has_unresolved(inner):
        return None
    outer_nets = [e.network() for e in outer]
    for e in inner:
        n = e.network()
        if not any(_same_version(n, o) and n.subnet_of(o) for o in outer_nets):
            return False
    return True


def addrs_overlap(a: list[AddressEntry], b: list[AddressEntry]) -> bool | None:
    resolved_a = [e.network() for e in a if not e.unresolved]
    resolved_b = [e.network() for e in b if not e.unresolved]
    if any(_same_version(x, y) and x.overlaps(y) for x in resolved_a for y in resolved_b):
        return True
    if has_unresolved(a) or has_unresolved(b):
        return None
    return False


def broadest_prefix(entries: list[AddressEntry], version: int) -> int | None:
    lens = [e.network().prefixlen for e in entries if not e.unresolved and e.network().version == version]
    return min(lens) if lens else None


# --------------------------------------------------------------------------- services

def is_any_service(services: list[PortRange]) -> bool:
    return any(s.protocol == ANY for s in services)


def _range_contains(o: PortRange, i: PortRange) -> bool:
    if o.protocol == ANY:
        return True
    if i.protocol == ANY or o.protocol != i.protocol:
        return False
    if o.protocol == "icmp":
        return True
    return o.start <= i.start and i.end <= o.end


def _range_overlaps(a: PortRange, b: PortRange) -> bool:
    if ANY in (a.protocol, b.protocol):
        return True
    if a.protocol != b.protocol:
        return False
    if a.protocol == "icmp":
        return True
    return a.start <= b.end and b.start <= a.end


def services_contain(outer: list[PortRange] | None, inner: list[PortRange] | None) -> bool | None:
    if outer is None or inner is None:
        return None
    return all(any(_range_contains(o, i) for o in outer) for i in inner)


def services_overlap(a: list[PortRange] | None, b: list[PortRange] | None) -> bool | None:
    if a is None or b is None:
        return None
    return any(_range_overlaps(x, y) for x in a for y in b)


def effective_services(rule: NormalizedRule) -> list[PortRange] | None:
    """Expand PAN 'application-default' to concrete ports. None means undecidable."""
    if rule.unresolved_services:
        return None
    if not rule.app_default_service:
        return rule.services
    if ANY in rule.applications:
        return any_services()
    out: list[PortRange] = []
    for app in rule.applications:
        ports = APP_DEFAULT_PORTS.get(app)
        if ports is None:
            return None
        for p in ports:
            out.extend(parse_service_token(p, source_object=f"{app}:application-default"))
    return out


# --------------------------------------------------------------------------- zones / apps

def _set_contains(outer: list[str], inner: list[str]) -> bool:
    return ANY in outer or (ANY not in inner and set(inner) <= set(outer))


def _set_overlaps(a: list[str], b: list[str]) -> bool:
    return ANY in a or ANY in b or bool(set(a) & set(b))


zones_contain = _set_contains
zones_overlap = _set_overlaps
apps_contain = _set_contains
apps_overlap = _set_overlaps
