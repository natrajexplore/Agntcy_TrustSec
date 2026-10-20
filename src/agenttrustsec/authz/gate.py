"""The enforcement point. Badge -> [Peer] -> TBAC -> Intent. ALLOW only if all PASS.

Rules enforced here (see CLAUDE.md):
  * Deny by default; any exception in a check becomes ERROR -> BLOCK.
  * Role comes only from the verified badge.
  * Exactly one audit record per call, including blocked calls.
  * A tool function is never invoked unless the verdict is ALLOW.
  * With a PeerBinding (P3, SLIM deployments) the `peer` check is mandatory: a call
    without a transport identity bound to the badge's key is BLOCKED.
"""
from __future__ import annotations

from typing import Any, Callable

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.intent import IntentChecker
from agenttrustsec.authz.peer import PeerBinding
from agenttrustsec.authz.tbac import TbacPolicy
from agenttrustsec.identity.badge import BadgeError, BadgeVerifier
from agenttrustsec.models import CheckResult, Decision, Status, ToolCall, Verdict


class BlockedError(PermissionError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"BLOCKED by {decision.blocked_by}: {decision.call.tool}")


class Gate:
    def __init__(self, verifier: BadgeVerifier, policy: TbacPolicy,
                 intent: IntentChecker, audit: AuditLog, peer: PeerBinding | None = None):
        self.verifier = verifier
        self.peer = peer
        self.policy = policy
        self.intent = intent
        self.audit = audit

    def authorize(self, call: ToolCall) -> Decision:
        checks: list[CheckResult] = []
        role: str | None = None
        ident = None

        # [1] Identity
        try:
            ident = self.verifier.verify(call.badge, call.agent_id)
            role = ident.role
            checks.append(CheckResult("badge", Status.PASS,
                                      f"verified {ident.agent_id} as role {role!r}"))
        except BadgeError as e:
            checks.append(CheckResult("badge", Status.FAIL, str(e)))
        except Exception as e:  # noqa: BLE001 - deny on any unexpected error
            checks.append(CheckResult("badge", Status.ERROR, f"{type(e).__name__}: {e}"))

        # [1b] Peer: the transport identity must hold the key the badge binds
        if self.peer is not None:
            if ident is None:
                checks.append(CheckResult("peer", Status.SKIPPED, "no verified badge"))
            else:
                try:
                    checks.append(self.peer.check(call.peer, ident))
                except Exception as e:  # noqa: BLE001
                    checks.append(CheckResult("peer", Status.ERROR, f"{type(e).__name__}: {e}"))
                if not checks[-1].passed:
                    role = None     # a badge not bound to this peer verifies no one

        # [2] TBAC
        if role is None:
            checks.append(CheckResult("tbac", Status.SKIPPED, "no verified role"))
        else:
            try:
                checks.append(self.policy.check(role, call.tool))
            except Exception as e:  # noqa: BLE001
                checks.append(CheckResult("tbac", Status.ERROR, f"{type(e).__name__}: {e}"))

        # [3] Intent
        spec = self.policy.spec(call.tool)
        if not all(c.passed for c in checks) or spec is None:
            checks.append(CheckResult("intent", Status.SKIPPED, "earlier check failed"))
        else:
            try:
                checks.append(self.intent.check(call.session, spec))
            except Exception as e:  # noqa: BLE001
                checks.append(CheckResult("intent", Status.ERROR, f"{type(e).__name__}: {e}"))

        evaluated = [c for c in checks if c.status is not Status.SKIPPED]
        required = 4 if self.peer is not None else 3
        allow = len(evaluated) == required and all(c.passed for c in evaluated)
        decision = Decision(
            call=call,
            checks=tuple(checks),
            verdict=Verdict.ALLOW if allow else Verdict.BLOCK,
            verified_role=role,
        )
        self.audit.write(decision)
        return decision

    def execute(self, call: ToolCall,
                registry: dict[str, Callable[..., Any]]) -> Any:
        """Authorize, then run the tool only on ALLOW."""
        decision = self.authorize(call)
        if decision.verdict is not Verdict.ALLOW:
            raise BlockedError(decision)
        fn = registry.get(call.tool)
        if fn is None:
            raise LookupError(f"no implementation for {call.tool!r}")
        return fn(**call.args)
