"""Group admission — the gate for SLIM group membership (P3 PR5, docs/P3-design.md §8).

TrustSec analogy: ISE deciding who joins a MACsec-protected VLAN. In SLIM a moderator
invites by NAME and any trusted key can answer for a name (lab/slim/group_probe.py Q7),
so admission re-runs the same checks as the tool gate before a member sees anything:

  badge  AGNTCY badge verifies (node signature, published + not revoked, subject)
  peer   the member's SLIM token is signed by the key that badge binds (authz/peer.py)
  group  the verified role is allowed in this channel (policies/groups.yaml) and the
         member answered under the name it was invited as

Every admission is one audit record, same shape as a tool decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from agenttrustsec.authz.peer import PeerBinding
from agenttrustsec.identity.badge import BadgeError, BadgeVerifier, VerifiedIdentity
from agenttrustsec.models import (
    CheckResult, Decision, Intent, Session, Status, ToolCall, TransportPeer, Verdict,
)

_WILDCARDS = {"*", "any", "all"}


class GroupPolicyError(Exception):
    """Unknown channel or malformed policy -> no admission (deny by default)."""


@dataclass(frozen=True)
class ChannelPolicy:
    channel: str
    moderator_roles: frozenset[str]
    member_roles: frozenset[str]
    attest_timeout_s: float


class GroupPolicy:
    def __init__(self, channels: dict[str, ChannelPolicy]):
        self._channels = dict(channels)

    @classmethod
    def from_yaml(cls, path: str | Path) -> GroupPolicy:
        raw = yaml.safe_load(Path(path).read_text()) or {}
        channels = raw.get("channels") or {}
        if not isinstance(channels, dict):
            raise GroupPolicyError("channels: must be a mapping")
        out = {}
        for name, spec in channels.items():
            if not isinstance(spec, dict):
                raise GroupPolicyError(f"{name}: must be a mapping")
            mods = frozenset(map(str, spec.get("moderator_roles") or []))
            members = frozenset(map(str, spec.get("member_roles") or []))
            if _WILDCARDS & ({str(name)} | mods | members):
                raise GroupPolicyError(f"{name}: wildcards are forbidden (deny by default)")
            timeout = float(spec.get("attest_timeout_s", 10))
            if not 0 < timeout <= 120:
                raise GroupPolicyError(f"{name}: attest_timeout_s must be in (0, 120]")
            out[str(name)] = ChannelPolicy(str(name), mods, members, timeout)
        return cls(out)

    def channel(self, name: str) -> ChannelPolicy:
        try:
            return self._channels[name]
        except KeyError:
            raise GroupPolicyError(f"channel {name!r} is not in the group policy") from None


def admit(policy: ChannelPolicy, *, as_moderator: bool, verifier: BadgeVerifier,
          binding: PeerBinding, claimed_id: str, badge: str | None,
          peer: TransportPeer | None, expected_name: str | None = None
          ) -> tuple[Decision, VerifiedIdentity | None]:
    """Decide one admission. Returns the (unaudited) Decision and, on ALLOW, the identity."""
    checks: list[CheckResult] = []
    ident: VerifiedIdentity | None = None
    try:
        ident = verifier.verify(badge, claimed_id)
        checks.append(CheckResult("badge", Status.PASS, f"verified {ident.agent_id} as {ident.role!r}"))
    except BadgeError as e:
        checks.append(CheckResult("badge", Status.FAIL, str(e)))
    except Exception as e:  # noqa: BLE001 - deny on any unexpected error
        checks.append(CheckResult("badge", Status.ERROR, f"{type(e).__name__}: {e}"))

    if ident is None:
        checks.append(CheckResult("peer", Status.SKIPPED, "no verified badge"))
    else:
        try:
            checks.append(binding.check(peer, ident))
        except Exception as e:  # noqa: BLE001
            checks.append(CheckResult("peer", Status.ERROR, f"{type(e).__name__}: {e}"))

    if not all(c.passed for c in checks):
        checks.append(CheckResult("group", Status.SKIPPED, "earlier check failed"))
    else:
        allowed = policy.moderator_roles if as_moderator else policy.member_roles
        what = "moderate" if as_moderator else "join"
        if ident.role not in allowed:
            checks.append(CheckResult("group", Status.FAIL,
                                      f"role {ident.role!r} may not {what} {policy.channel}"))
        elif expected_name is not None and peer.subject != expected_name:
            checks.append(CheckResult("group", Status.FAIL,
                                      f"answered as {peer.subject!r}, invited as {expected_name!r}"))
        else:
            checks.append(CheckResult("group", Status.PASS, f"{ident.role!r} may {what} {policy.channel}"))

    ok = len(checks) == 3 and all(c.passed for c in checks)
    action = "moderate" if as_moderator else "join"
    decision = Decision(
        call=ToolCall(claimed_id, badge, f"group.{action}", Session(f"admission to {policy.channel}",
                      Intent.READ, session_id=policy.channel[-12:]),
                      {"channel": policy.channel}, peer=peer),
        checks=tuple(checks), verdict=Verdict.ALLOW if ok else Verdict.BLOCK,
        verified_role=ident.role if ok else None)
    return decision, (ident if ok else None)
