# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Findings, risk report, and decision models."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Decision(str, Enum):
    APPROVE = "APPROVE"
    APPROVE_WITH_CONDITIONS = "APPROVE_WITH_CONDITIONS"
    REJECT = "REJECT"
    REJECT_DUPLICATE = "REJECT_DUPLICATE"


class Evidence(BaseModel):
    kind: Literal["request_field", "rule", "object", "check"]
    ref: str
    detail: str | None = None

    def __str__(self) -> str:
        return f"{self.kind}:{self.ref}" + (f" ({self.detail})" if self.detail else "")


class Finding(BaseModel):
    check_id: str = Field(pattern=r"^RG-\d{3}$")
    severity: Severity
    title: str
    detail: str
    evidence: list[Evidence]
    remediation: str | None = None
    compliance: list[str] = Field(default_factory=list)
    needs_human_review: bool = False

    @field_validator("evidence")
    @classmethod
    def _evidence_required(cls, v: list[Evidence]) -> list[Evidence]:
        if not v:
            raise ValueError("every finding needs at least one piece of evidence")
        return v


class RiskReport(BaseModel):
    change_id: str
    vendor: str
    device_group: str | None
    findings: list[Finding]
    risk_score: int = Field(ge=0, le=100)
    decision: Decision
    max_severity: Severity | None
    needs_human_review: bool = False
    review_notes: list[str] = Field(default_factory=list)

    @property
    def check_ids(self) -> set[str]:
        return {f.check_id for f in self.findings}
