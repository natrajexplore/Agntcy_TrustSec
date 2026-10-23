"""Core data model for AgentTrustSec.

TrustSec analogy: a ToolCall is a flow hitting an enforcement point; a Decision is
the permit/deny plus the reasons you'd see in ISE Live Logs.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Intent(str, Enum):
    READ = "read"
    CHANGE = "change"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"      # check could not run -> treated as FAIL (deny by default)
    SKIPPED = "SKIPPED"  # not evaluated because an earlier check failed


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Session:
    """A user request. Intent is bound once, at intake, like posture at auth time."""
    user_prompt: str
    intent: Intent
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass(frozen=True)
class TransportPeer:
    """Who the transport says is on the other end (P3: SLIM). Not yet a trust decision —
    the gate's `peer` check binds it to the verified badge's key."""
    source_name: str   # routing name the peer sent from
    subject: str       # `sub` of the peer's identity token
    token: str         # the peer's signed identity token (never audited)


@dataclass(frozen=True)
class ToolCall:
    agent_id: str          # who the caller CLAIMS to be
    badge: str | None      # credential presented (None = no credential)
    tool: str
    session: Session
    args: dict[str, Any] = field(default_factory=dict)
    peer: TransportPeer | None = None   # set by the SLIM transport; None in-process
    approval: str | None = None         # P5d: reviewer-approval token (never audited)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    reason: str

    @property
    def passed(self) -> bool:
        return self.status is Status.PASS


@dataclass(frozen=True)
class Decision:
    call: ToolCall
    checks: tuple[CheckResult, ...]
    verdict: Verdict
    verified_role: str | None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def blocked_by(self) -> str | None:
        for c in self.checks:
            if c.status in (Status.FAIL, Status.ERROR):
                return c.name
        return None

    def to_audit_record(self) -> dict[str, Any]:
        """Flat record for the audit log. Never includes the raw badge."""
        return {
            "timestamp": self.timestamp,
            "session_id": self.call.session.session_id,
            "intent": self.call.session.intent.value,
            "user_prompt": self.call.session.user_prompt,
            "agent_id": self.call.agent_id,
            "badge_presented": self.call.badge is not None,
            "approval_presented": self.call.approval is not None,
            "peer": ({"source_name": self.call.peer.source_name,
                      "subject": self.call.peer.subject} if self.call.peer else None),
            "verified_role": self.verified_role,
            "tool": self.call.tool,
            "args": self.call.args,
            "checks": [
                {**asdict(c), "status": c.status.value} for c in self.checks
            ],
            "verdict": self.verdict.value,
            "blocked_by": self.blocked_by,
        }
