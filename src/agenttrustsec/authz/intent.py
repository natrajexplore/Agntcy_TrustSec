"""Intent-scoped authorization — the CASA idea.

TrustSec analogy: posture/context. The same identity may be allowed a tool in general,
but not for *this* request.

BaselineIntentChecker is deliberately simple and conservative. Ordered sub-checks, the
first failure decides (every one is named in the audit reason):
  1. change gate: change tools require session intent == CHANGE (rule 4).
  2. scope (P4b, T6): every value of the tool's `scoped_args` (device, IP, ...) must be
     named in the sealed user request; a tool with no `scoped_args` declaration is
     BLOCKED (deny by default, D5).
  3. relevance:
     - change tools, when a semantic matcher is configured (P4e, D4 = change tools only):
       the local LLM verifier must allow the tool for this request (rule 4's semantic
       check). A matcher error propagates -> the gate records ERROR -> BLOCK.
     - read tools (and the keyword-only dev/test mode): the user prompt must share at least
       one keyword with the tool's policy keywords. No overlap -> FAIL.
The gateway (mcpgate/serve.py, SLIM) always runs with the semantic matcher; keyword-only
mode exists for unit tests and the offline demo. Evaluation: docs/P4-design.md.
"""
from __future__ import annotations

import re
from typing import Any, Protocol

from agenttrustsec.authz.semantic import SemanticMatcher, ToolRef
from agenttrustsec.authz.tbac import ToolSpec
from agenttrustsec.models import CheckResult, Intent, Session, Status

_CHANGE_VERBS = {
    "push", "apply", "change", "modify", "deploy", "add", "remove", "delete",
    "configure", "update", "commit", "rollback", "shut", "enable", "disable",
}
# A target counts as "named" only as a whole token: `10.0.0.1` != `10.0.0.10`,
# `edge-fw-01` != `edge-fw-010` (these characters continue a name).
_NAME_CHARS = r"A-Za-z0-9._\-"


def classify_intent(prompt: str) -> Intent:
    """Intake-agent helper. Conservative: anything not clearly a change is READ."""
    words = set(re.findall(r"[a-z]+", prompt.lower()))
    return Intent.CHANGE if words & _CHANGE_VERBS else Intent.READ


def named_in(value: str, prompt: str) -> bool:
    pattern = rf"(?<![{_NAME_CHARS}]){re.escape(value)}(?![{_NAME_CHARS}])"
    return re.search(pattern, prompt, flags=re.IGNORECASE) is not None


def check_scope(prompt: str, spec: ToolSpec, args: dict[str, Any] | None) -> str | None:
    """None if every scoped target is named in the request; otherwise the failure reason."""
    if spec.scoped_args is None:
        return f"{spec.name!r} declares no scoped_args (deny by default)"
    if not spec.scoped_args:
        return None
    if args is None:
        return "call arguments not available to the scope check"
    for name in spec.scoped_args:
        if name not in args:
            return f"scoped argument {name!r} missing from the call"
        values = args[name] if isinstance(args[name], list) else [args[name]]
        for v in values:
            if not isinstance(v, str) or not v.strip():
                return f"scoped argument {name!r} must be a non-empty string"
            if not named_in(v.strip(), prompt):
                return f"{name}={v!r} is not named in the request"
    return None


class IntentChecker(Protocol):
    def check(self, session: Session, spec: ToolSpec,
              args: dict[str, Any] | None = None) -> CheckResult: ...


class BaselineIntentChecker:
    def __init__(self, semantic: SemanticMatcher | None = None):
        self.semantic = semantic          # P4e: judges change tools when set

    def check(self, session: Session, spec: ToolSpec,
              args: dict[str, Any] | None = None) -> CheckResult:
        if spec.change and session.intent is not Intent.CHANGE:
            return CheckResult(
                "intent", Status.FAIL,
                f"{spec.name!r} is a change tool but session intent is "
                f"{session.intent.value!r}",
            )
        scope_problem = check_scope(session.user_prompt, spec, args)
        if scope_problem:
            return CheckResult("intent", Status.FAIL, f"scope: {scope_problem}")
        scoped = ", ".join(f"{a}={args[a]!r}" for a in spec.scoped_args) if spec.scoped_args else "none"
        if spec.change and self.semantic is not None:
            verdict = self.semantic.match(session.user_prompt, ToolRef(spec.name, spec.description))
            return CheckResult("intent", Status.PASS if verdict.allow else Status.FAIL,
                               f"scope ok ({scoped}); semantic: {verdict.reason}")
        words = set(re.findall(r"[a-z0-9_]+", session.user_prompt.lower()))
        overlap = words & spec.keywords
        if not overlap:
            return CheckResult(
                "intent", Status.FAIL,
                f"{spec.name!r} not relevant to request (no keyword overlap)",
            )
        return CheckResult(
            "intent", Status.PASS,
            f"scope ok ({scoped}); matches request on {sorted(overlap)}",
        )
