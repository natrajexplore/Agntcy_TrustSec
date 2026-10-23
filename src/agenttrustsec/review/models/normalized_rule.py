# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Vendor-neutral rule model. Every parser produces this shape; analysis only consumes it."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field

Vendor = Literal["panos", "ftd"]
Action = Literal["allow", "deny", "drop", "reset", "trust", "fastpath", "monitor"]

PERMIT_ACTIONS = {"allow", "trust", "fastpath"}
BLOCK_ACTIONS = {"deny", "drop", "reset"}

ANY = "any"
ANY_NETWORKS = ("0.0.0.0/0", "::/0")


class AddressEntry(BaseModel):
    """A resolved network, or an entry that cannot be resolved offline (FQDN, DAG, EDL)."""

    value: str                      # CIDR for resolved entries, original token otherwise
    source_object: str | None = None  # object/group name it came from (evidence)
    unresolved: bool = False
    reason: str | None = None       # e.g. "fqdn", "dynamic-address-group", "edl", "unknown-object"

    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        if self.unresolved:
            raise ValueError(f"Address entry {self.value!r} is unresolved")
        return ipaddress.ip_network(self.value, strict=False)


class PortRange(BaseModel):
    """Protocol plus inclusive port range. protocol 'any' matches every protocol and port."""

    protocol: Literal["tcp", "udp", "sctp", "icmp", "any"]
    start: int = Field(0, ge=0, le=65535)
    end: int = Field(65535, ge=0, le=65535)
    source_object: str | None = None

    def __str__(self) -> str:
        if self.protocol == ANY:
            return ANY
        if self.protocol == "icmp":
            return "icmp"
        return f"{self.protocol}/{self.start}" if self.start == self.end else f"{self.protocol}/{self.start}-{self.end}"


class InspectionProfile(BaseModel):
    profile_group: str | None = None      # PAN Security Profile Group
    profiles: list[str] = Field(default_factory=list)  # PAN individual profiles
    intrusion_policy: str | None = None   # FTD
    file_policy: str | None = None        # FTD

    def has_panos_inspection(self) -> bool:
        return bool(self.profile_group or self.profiles)


class NormalizedRule(BaseModel):
    vendor: Vendor
    rule_id: str                    # PAN rule name / FMC rule UUID
    name: str
    position: int                   # global evaluation order, 1-based
    layer: str                      # pre|local|post (PAN), prefilter|mandatory|default (FTD)
    action: Action
    enabled: bool = True
    src_zones: list[str] = Field(default_factory=lambda: [ANY])
    dst_zones: list[str] = Field(default_factory=lambda: [ANY])
    src_addrs: list[AddressEntry] = Field(default_factory=list)
    dst_addrs: list[AddressEntry] = Field(default_factory=list)
    services: list[PortRange] = Field(default_factory=list)
    unresolved_services: list[str] = Field(default_factory=list)  # unknown service objects -> undecidable
    applications: list[str] = Field(default_factory=lambda: [ANY])
    app_default_service: bool = False
    users: list[str] = Field(default_factory=list)
    inspection: InspectionProfile = Field(default_factory=InspectionProfile)
    log_at_end: bool = False
    raw_ref: str = ""

    @property
    def unresolved_entries(self) -> list[AddressEntry]:
        return [a for a in self.src_addrs + self.dst_addrs if a.unresolved]

    def summary(self) -> dict:
        """Compact, JSON-friendly view for tool output and evidence."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "position": self.position,
            "layer": self.layer,
            "action": self.action,
            "enabled": self.enabled,
            "src_zones": self.src_zones,
            "dst_zones": self.dst_zones,
            "src_addrs": [a.value if not a.unresolved else f"UNRESOLVED:{a.value}" for a in self.src_addrs],
            "dst_addrs": [a.value if not a.unresolved else f"UNRESOLVED:{a.value}" for a in self.dst_addrs],
            "services": ["application-default"] if self.app_default_service else [str(s) for s in self.services],
            "unresolved_services": self.unresolved_services,
            "applications": self.applications,
            "users": self.users,
            "log_at_end": self.log_at_end,
            "inspection": self.inspection.model_dump(exclude_defaults=True),
        }


def any_addresses() -> list[AddressEntry]:
    return [AddressEntry(value=n, source_object=ANY) for n in ANY_NETWORKS]


def any_services() -> list[PortRange]:
    return [PortRange(protocol=ANY, source_object=ANY)]
