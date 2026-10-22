"""Attested SLIM group sessions — the reviewer pool (P3 PR5, docs/P3-design.md §8).

TrustSec analogy: a MACsec VLAN whose membership ISE decides per port. SLIM invites by
NAME and admits any trusted key answering for it (lab/slim/group_probe.py Q7: an impostor
read the next broadcast). So:

  Moderator (AttestedGroup)
    * creates the MLS GROUP session, invites members, then sends its own badge (hello)
    * ADMISSION GATE: nothing is broadcast while any member is unattested; each member must
      `attest` with its badge; authz.groups.admit() runs badge -> peer -> group policy
    * fail / silence past the channel timeout -> remove (MLS epoch moves on) + audit
    * before every broadcast the live participant list must equal moderator + admitted
    * replies are accepted only from admitted members whose identity still binds

  Member (GroupMember)
    * verifies the moderator's hello (badge, key binding, moderator role for the channel)
      BEFORE attesting or reading anything — an impostor moderator gets nothing
    * attests to the moderator only (directed), reads moderator broadcasts only, replies
      directed to the moderator (reviews stay independent)

Wire messages are JSON: {"type": "moderator_hello"|"attest"|"broadcast"|"reply", ...}.
Verified against slim-bindings 3.3.6 (core 3.4.5).
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.groups import ChannelPolicy, GroupPolicy, GroupPolicyError, admit
from agenttrustsec.authz.peer import PeerBinding, slim_name
from agenttrustsec.identity.badge import BadgeVerifier, VerifiedIdentity
from agenttrustsec.models import CheckResult, Decision, Intent, Session, Status, ToolCall, Verdict
from agenttrustsec.transport import slim

log = logging.getLogger(__name__)
sb = slim.sb


class GroupNotReady(Exception):
    """Broadcast refused: a member is not (or no longer) attested."""


class ModeratorRejected(Exception):
    """The group's moderator failed verification; the member left without attesting."""


def _encode(kind: str, **fields: Any) -> bytes:
    return json.dumps({"type": kind, **fields}).encode()


def _decode(payload: bytes) -> dict:
    try:
        msg = json.loads(payload)
    except ValueError:
        return {}
    return msg if isinstance(msg, dict) else {}


def _group_config(mls: bool) -> Any:
    return sb.SessionConfig(
        session_type=sb.SessionType.GROUP, max_retries=3,
        interval=datetime.timedelta(seconds=2), metadata={},
        mls_settings=sb.MlsSettings(header_integrity_validation_percent=100,
                                    max_seen_control_message_ids_size=None) if mls else None)


@dataclass
class _Member:
    agent_id: str
    ident: VerifiedIdentity
    token: str


@dataclass
class AttestedGroup:
    endpoint: slim.SlimEndpoint
    policy: ChannelPolicy
    agent_id: str               # moderator's badge subject
    badge: str                  # moderator's badge (sent in the hello)
    verifier: BadgeVerifier
    binding: PeerBinding
    audit: AuditLog
    mls: bool = True
    session: Any = None
    admitted: dict[str, _Member] = field(default_factory=dict)   # SLIM name -> member
    results: dict[str, str] = field(default_factory=dict)        # agent id -> outcome

    async def open(self) -> None:
        ctx = await self.endpoint.app.create_session_async(
            _group_config(self.mls), sb.Name.from_string(self.policy.channel))
        await ctx.completion.wait_async()
        self.session = ctx.session

    async def admit_members(self, member_ids: list[str]) -> dict[str, str]:
        """Invite and attest; returns agent id -> 'admitted' or the refusal reason."""
        pending: dict[str, str] = {}
        for mid in member_ids:
            name = slim_name(mid)
            try:
                await self.endpoint.app.set_route_async(sb.Name.from_string(name), self.endpoint.conn_id)
                handle = await self.session.invite_async(sb.Name.from_string(name))
                await handle.wait_async()
                pending[name] = mid
            except Exception as e:  # noqa: BLE001 - not joined (e.g. key outside trust)
                self._refuse(mid, f"invite failed: {str(e)[:120]}")
        if not pending:
            return self.results
        await self.session.publish_async(
            _encode("moderator_hello", agent_id=self.agent_id, badge=self.badge), None, None)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.policy.attest_timeout_s
        while pending and (left := deadline - loop.time()) > 0:
            try:
                msg = await self.session.get_message_async(timeout=datetime.timedelta(seconds=left))
            except Exception:  # noqa: BLE001 - timeout: whoever is left failed to attest
                break
            peer = slim.peer_of(msg.context)
            body = _decode(msg.payload)
            if body.get("type") != "attest" or peer.source_name not in pending:
                continue                           # nothing else counts before admission
            name = peer.source_name
            decision, ident = admit(self.policy, as_moderator=False, verifier=self.verifier,
                                    binding=self.binding, claimed_id=str(body.get("agent_id", "")),
                                    badge=body.get("badge"), peer=peer, expected_name=name)
            self.audit.write(decision)
            mid = pending.pop(name)
            if ident is not None:
                self.admitted[name] = _Member(ident.agent_id, ident, peer.token)
                self.results[mid] = "admitted"
            else:
                await self._remove(name)
                self.results[mid] = f"refused by {decision.blocked_by}"
        for name, mid in pending.items():
            await self._remove(name)
            self._refuse(mid, f"no attestation within {self.policy.attest_timeout_s:g}s")
        return self.results

    async def broadcast(self, data: str) -> None:
        """Send to every admitted member — only if the live group is exactly moderator + admitted."""
        try:
            live = {str(p.name) for p in await self.session.participants_list_async()}
        except Exception as e:  # noqa: BLE001 - can't see who's in the group -> don't send
            raise GroupNotReady(f"group membership unknown ({str(e)[:80]}); not sent") from None
        own = str(self.endpoint.name)
        unknown = {n for n in live if n not in self.admitted and n != own}
        if unknown:
            for name in unknown:
                await self._remove(name)
            raise GroupNotReady(f"unattested participant(s) {sorted(unknown)} removed; not sent")
        await self.session.publish_async(_encode("broadcast", data=data), None, None)

    async def receive(self, timeout: float) -> tuple[str, str]:
        """Next reply from an admitted member whose identity still binds: (agent id, data)."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while (left := deadline - loop.time()) > 0:
            msg = await self.session.get_message_async(timeout=datetime.timedelta(seconds=left))
            peer = slim.peer_of(msg.context)
            member = self.admitted.get(peer.source_name)
            body = _decode(msg.payload)
            if member is None or body.get("type") != "reply":
                continue
            if peer.token != member.token:         # token refreshed or swapped: re-bind
                check = self.binding.check(peer, member.ident)
                if not check.passed:
                    self.admitted.pop(peer.source_name)
                    await self._remove(peer.source_name)
                    log.error("member %s dropped: %s", member.agent_id, check.reason)
                    continue
                member.token = peer.token
            return member.agent_id, str(body.get("data", ""))
        raise TimeoutError("no verified reply")

    async def close(self) -> None:
        if self.session is not None:
            try:
                handle = await self.endpoint.app.delete_session_async(self.session)
                await handle.wait_async()
            except Exception as e:  # noqa: BLE001 - best-effort teardown
                log.debug("group close: %s", e)

    async def _remove(self, name: str) -> None:
        try:
            handle = await self.session.remove_async(sb.Name.from_string(name))
            await handle.wait_async()
        except Exception as e:  # noqa: BLE001 - already gone is fine; broadcast re-checks
            log.warning("remove %s: %s", name, e)

    def _refuse(self, mid: str, reason: str) -> None:
        self.results[mid] = reason
        self.audit.write(Decision(
            call=ToolCall(mid, None, "group.join", Session(f"admission to {self.policy.channel}",
                          Intent.READ, session_id=self.policy.channel[-12:]),
                          {"channel": self.policy.channel}),
            checks=(CheckResult("badge", Status.SKIPPED, "no attestation"),
                    CheckResult("peer", Status.SKIPPED, "no attestation"),
                    CheckResult("group", Status.FAIL, reason)),
            verdict=Verdict.BLOCK, verified_role=None))


@dataclass
class GroupMember:
    endpoint: slim.SlimEndpoint
    policy: GroupPolicy
    agent_id: str
    badge: str
    verifier: BadgeVerifier          # must verify the MODERATOR's badge (intake role mapped)
    binding: PeerBinding
    audit: AuditLog | None = None
    session: Any = None
    moderator: str | None = None     # verified moderator agent id
    _mod_name: str = ""
    _mod_token: str = ""
    _mod_ident: VerifiedIdentity | None = None
    _mod_ctx: Any = None

    async def join(self, timeout: float = 60) -> str:
        """Wait for an invite, verify the moderator, then attest. Returns the moderator id."""
        self.session = await self.endpoint.app.listen_for_session_async(
            datetime.timedelta(seconds=timeout))
        try:
            channel = self.policy.channel(str(self.session.destination()))
            msg = await self.session.get_message_async(timeout=datetime.timedelta(seconds=timeout))
            body, peer = _decode(msg.payload), slim.peer_of(msg.context)
            if body.get("type") != "moderator_hello":
                raise ModeratorRejected(f"first message was {body.get('type')!r}, not a moderator hello")
            decision, ident = admit(channel, as_moderator=True, verifier=self.verifier,
                                    binding=self.binding, claimed_id=str(body.get("agent_id", "")),
                                    badge=body.get("badge"), peer=peer)
            if self.audit is not None:
                self.audit.write(decision)
            if ident is None:
                bad = next(c for c in decision.checks if c.name == decision.blocked_by)
                raise ModeratorRejected(f"moderator refused by {decision.blocked_by}: {bad.reason}")
        except (ModeratorRejected, GroupPolicyError):
            await self.leave()
            raise
        self.moderator, self._mod_ident = ident.agent_id, ident
        self._mod_name, self._mod_token, self._mod_ctx = peer.source_name, peer.token, msg.context
        await self.session.publish_to_async(
            msg.context, _encode("attest", agent_id=self.agent_id, badge=self.badge), None, None)
        return self.moderator

    async def receive(self, timeout: float) -> str:
        """Next broadcast from the verified moderator."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while (left := deadline - loop.time()) > 0:
            msg = await self.session.get_message_async(timeout=datetime.timedelta(seconds=left))
            peer, body = slim.peer_of(msg.context), _decode(msg.payload)
            if peer.source_name != self._mod_name or body.get("type") != "broadcast":
                continue
            if peer.token != self._mod_token:
                if not self.binding.check(peer, self._mod_ident).passed:
                    await self.leave()
                    raise ModeratorRejected("moderator identity changed mid-session")
                self._mod_token = peer.token
            self._mod_ctx = msg.context
            return str(body.get("data", ""))
        raise TimeoutError("no broadcast from the moderator")

    async def reply(self, data: str) -> None:
        await self.session.publish_to_async(self._mod_ctx, _encode("reply", data=data), None, None)

    async def leave(self) -> None:
        if self.session is not None:
            try:
                handle = await self.endpoint.app.delete_session_async(self.session)
                await handle.wait_async()
            except Exception as e:  # noqa: BLE001
                log.debug("leave: %s", e)
