"""Intent-scoped authorization — the CASA idea.

TrustSec analogy: posture/context. The same identity may be allowed a tool in general,
but not for *this* request.

BaselineIntentChecker (P0) is deliberately simple and conservative:
  1. Hard rule: change tools require session intent == CHANGE.
  2. Relevance: the user prompt must share at least one keyword with the tool's
     policy keywords. No overlap -> FAIL.
P4 replaces step 2 with embeddings and/or an LLM verifier, evaluated on ASTRA first.
"""
from __future__ import annotations

import re
from typing import Protocol

from agenttrustsec.authz.tbac import ToolSpec
from agenttrustsec.models import CheckResult, Intent, Session, Status

_CHANGE_VERBS = {
    "push", "apply", "change", "modify", "deploy", "add", "remove", "delete",
    "configure", "update", "commit", "rollback", "shut", "enable", "disable",
}


def classify_intent(prompt: str) -> Intent:
    """Intake-agent helper. Conservative: anything not clearly a change is READ."""
    words = set(re.findall(r"[a-z]+", prompt.lower()))
    return Intent.CHANGE if words & _CHANGE_VERBS else Intent.READ


class IntentChecker(Protocol):
    def check(self, session: Session, spec: ToolSpec) -> CheckResult: ...


class BaselineIntentChecker:
    def check(self, session: Session, spec: ToolSpec) -> CheckResult:
        if spec.change and session.intent is not Intent.CHANGE:
            return CheckResult(
                "intent", Status.FAIL,
                f"{spec.name!r} is a change tool but session intent is "
                f"{session.intent.value!r}",
            )
        words = set(re.findall(r"[a-z0-9_]+", session.user_prompt.lower()))
        overlap = words & spec.keywords
        if not overlap:
            return CheckResult(
                "intent", Status.FAIL,
                f"{spec.name!r} not relevant to request (no keyword overlap)",
            )
        return CheckResult(
            "intent", Status.PASS,
            f"matches request on {sorted(overlap)}",
        )
