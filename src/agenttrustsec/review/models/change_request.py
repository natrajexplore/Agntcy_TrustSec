# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Vendor-neutral change request model.

Every value here can end up in staged configuration (PAN-OS ``set`` commands, FMC JSON) that a
human later applies, and in the Markdown CAB report. Fields are therefore restricted to strict
character sets: no whitespace, quotes, brackets, semicolons or control characters in anything that
is rendered into a command, so a crafted request cannot smuggle extra commands into staged config.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agenttrustsec.review.models.normalized_rule import Vendor

# Object / zone / application / device-group names rendered into CLI commands.
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# FTD policy names (rendered only into JSON values, so spaces and parentheses are safe).
POLICY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}$")
# User / group identities, e.g. corp\jdoe or jdoe@corp.example.
USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,127}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return list(v)


def _check_names(values: list[str], pattern: re.Pattern, what: str) -> list[str]:
    for i, v in enumerate(values, 1):
        if v != "any" and not pattern.match(v):
            raise ValueError(f"invalid {what} (entry {i}): use letters, digits, '.', '_' or '-' (max 63 characters)")
    return values


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos must fail loudly, not be ignored

    vendor: Vendor
    device_group: str | None = Field(None, description="Panorama device group (PAN) or access policy name (FTD)")

    @field_validator("device_group")
    @classmethod
    def _check_group(cls, v: str | None) -> str | None:
        if v is not None and not (NAME.match(v) or POLICY_NAME.match(v)):
            raise ValueError("device_group must use letters, digits, spaces, '.', '_', '-' or parentheses")
        return v


class RequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos must fail loudly, not be ignored

    action: Literal["allow", "deny"] = "allow"
    source_zone: list[str] = Field(default_factory=lambda: ["any"], max_length=16)
    source: list[str] = Field(default_factory=lambda: ["any"], max_length=64)
    destination_zone: list[str] = Field(default_factory=lambda: ["any"], max_length=16)
    destination: list[str] = Field(default_factory=lambda: ["any"], max_length=64)
    application: list[str] = Field(default_factory=lambda: ["any"], max_length=32)
    service: list[str] = Field(default_factory=lambda: ["any"], max_length=64,
                               description="e.g. tcp/443, udp/53, tcp/1000-2000, icmp, any, application-default")
    users: list[str] = Field(default_factory=list, max_length=32)
    logging: bool = True
    # PAN-OS inspection
    security_profile_group: str | None = None
    # FTD inspection / action
    intrusion_policy: str | None = None
    file_policy: str | None = None
    ftd_action: Literal["allow", "trust"] = "allow"
    prefilter_fastpath: bool = False
    # Where the requester wants the rule: top | bottom | before:<rule> | after:<rule>
    placement: str = "bottom"

    @field_validator("source_zone", "source", "destination_zone", "destination", "application", "service", "users", mode="before")
    @classmethod
    def _listify(cls, v):
        values = [str(x).strip() for x in _as_list(v) if str(x).strip()]
        return values

    @field_validator("source_zone", "source", "destination_zone", "destination", "application", "service", mode="after")
    @classmethod
    def _default_any(cls, v):
        return v or ["any"]

    @field_validator("source_zone", "destination_zone")
    @classmethod
    def _check_zones(cls, v: list[str]) -> list[str]:
        return _check_names(v, NAME, "zone")

    @field_validator("application")
    @classmethod
    def _check_apps(cls, v: list[str]) -> list[str]:
        return _check_names(v, NAME, "application")

    @field_validator("source", "destination")
    @classmethod
    def _check_addresses(cls, v: list[str]) -> list[str]:
        from agenttrustsec.review.analysis.address_math import parse_address_token  # lazy: avoids an import cycle

        for i, a in enumerate(v, 1):
            if not parse_address_token(a) and not NAME.match(a):
                raise ValueError(f"invalid address (entry {i}): use an IP, CIDR, range (a-b), 'any' or an object name")
        return v

    @field_validator("service")
    @classmethod
    def _check_services(cls, v: list[str]) -> list[str]:
        if "application-default" in v:
            if v != ["application-default"]:
                raise ValueError("application-default cannot be combined with other services")
            return v
        from agenttrustsec.review.analysis.address_math import parse_service_token  # lazy: avoids an import cycle

        for i, s in enumerate(v, 1):
            try:
                parse_service_token(s)
            except ValueError:
                raise ValueError(f"invalid service (entry {i}): use tcp/<port>, udp/<a>-<b>, icmp, any "
                                 "or application-default") from None
        return v

    @field_validator("users")
    @classmethod
    def _check_users(cls, v: list[str]) -> list[str]:
        return _check_names(v, USER, "user")

    @field_validator("security_profile_group")
    @classmethod
    def _check_profile(cls, v: str | None) -> str | None:
        if v is not None and not NAME.match(v):
            raise ValueError("security_profile_group must use letters, digits, '.', '_' or '-'")
        return v

    @field_validator("intrusion_policy", "file_policy")
    @classmethod
    def _check_policy(cls, v: str | None) -> str | None:
        if v is not None and not POLICY_NAME.match(v):
            raise ValueError("policy names may use letters, digits, spaces, '.', '_', '-' or parentheses")
        return v

    @field_validator("placement")
    @classmethod
    def _check_placement(cls, v: str) -> str:
        v = (v or "bottom").strip()
        if v in ("top", "bottom"):
            return v
        where, sep, ref = v.partition(":")
        if sep and where in ("before", "after") and NAME.match(ref):
            return v
        raise ValueError("placement must be top, bottom, before:<rule> or after:<rule> (rule name without spaces)")


class NormalizedChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos must fail loudly, not be ignored

    # Used as a report directory name: restrict to a safe charset (no path separators or "..").
    change_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    ticket_ref: str | None = Field(None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    requester: str | None = Field(None, max_length=120)
    business_justification: str | None = Field(None, max_length=2000)
    target: Target
    request: RequestSpec
    temporary: bool = False
    expiry: dt.date | None = None
    assumptions: list[str] = Field(default_factory=list, max_length=20,
                                   description="Fields the intake had to assume (free-text requests)")

    @field_validator("requester")
    @classmethod
    def _check_requester(cls, v: str | None) -> str | None:
        if v is not None and (CONTROL.search(v) or any(c in v for c in '"|`')):
            raise ValueError("requester must be a single line without quotes, pipes or backticks")
        return v

    @field_validator("business_justification")
    @classmethod
    def _flatten_justification(cls, v: str | None) -> str | None:
        # Free prose is allowed, but kept on one line so it cannot restructure the report.
        return " ".join(CONTROL.sub(" ", v).split()).replace("|", "/") if v is not None else None

    @field_validator("assumptions")
    @classmethod
    def _flatten_assumptions(cls, v: list[str]) -> list[str]:
        return [" ".join(CONTROL.sub(" ", a).split())[:300] for a in v]

    def missing_fields(self) -> list[str]:
        missing = []
        if not self.ticket_ref:
            missing.append("ticket_ref")
        if not self.requester:
            missing.append("requester")
        if not (self.business_justification or "").strip():
            missing.append("business_justification")
        if self.temporary and not self.expiry:
            missing.append("expiry")
        if self.request.service == ["any"]:
            missing.append("request.service (exact ports)")
        if not self.target.device_group:
            missing.append("target.device_group")
        return missing
