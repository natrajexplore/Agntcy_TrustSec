"""P2: verify AGNTCY Agent / MCP Server Badges via an Identity Node.

TrustSec analogy: 802.1X against ISE. The badge (JOSE-enveloped Verifiable Credential)
proves WHO the agent is; the role (SGT) comes from our own authorization map
(`policies/identities.yaml`), never from the badge — AGNTCY badges carry no role, and
an agent must not be able to assert its own privilege.

Verified against agntcy-identity-sdk 0.0.26 + agntcy/identity node source:
  * `IdentitySdk().verify_badge(EnvelopedCredential) -> VerificationResult`
    {status, document: VerifiableCredential, errors, warnings}
  * A REVOKED badge comes back with status=False but `document` still populated and
    the reason in `warnings` -> we require status is True and no errors/warnings.
  * The node path checks signature (issuer JWKS) + revocation, but no expiry check was
    found -> we enforce `expiration_date` here.
  * VC `type` contains "AgentBadge" or "MCPServerBadge"; subject is content["id"].
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from agenttrustsec.identity.badge import BadgeError, VerifiedIdentity

AGENT_BADGE = "AgentBadge"
MCP_SERVER_BADGE = "MCPServerBadge"

# Takes the JOSE compact string the caller presented; returns a VerificationResult.
NodeVerify = Callable[[str], Any]


def sdk_node() -> NodeVerify:
    """Real Identity Node via the SDK. Env: IDENTITY_NODE_GRPC_SERVER_URL,
    IDENTITY_NODE_USE_SSL (see SDK README)."""
    from agntcy.identity.core.v1alpha1 import vc_pb2
    from agntcyidentity.sdk import IdentitySdk

    sdk = IdentitySdk()

    def verify(jose: str) -> Any:
        return sdk.verify_badge(vc_pb2.EnvelopedCredential(
            envelope_type=vc_pb2.CREDENTIAL_ENVELOPE_TYPE_JOSE, value=jose))

    return verify


def load_role_map(path: str | Path, section: str) -> dict[str, str]:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    entries = raw.get(section) or {}
    if not isinstance(entries, dict):
        raise ValueError(f"{section}: must be a mapping of badge id -> role")
    for ident, role in entries.items():
        if any(w in (str(ident), str(role)) for w in ("*", "any", "all")):
            raise ValueError(f"{section}: wildcards are forbidden (deny by default)")
    return {str(k): str(v) for k, v in entries.items()}


class AgntcyBadgeVerifier:
    def __init__(self, role_map: dict[str, str], *, badge_type: str = AGENT_BADGE,
                 node: NodeVerify | None = None):
        self.role_map = dict(role_map)
        self.badge_type = badge_type
        self._node = node

    def verify(self, badge: str | None, claimed_agent_id: str) -> VerifiedIdentity:
        if not badge or not isinstance(badge, str):
            raise BadgeError("no badge presented")
        if self._node is None:
            self._node = sdk_node()
        result = self._node(badge)  # transport errors propagate -> Gate ERROR -> BLOCK

        if result.status is not True:
            raise BadgeError(f"identity node rejected badge: {_reasons(result)}")
        if list(result.errors) or list(result.warnings):
            raise BadgeError(f"badge has errors/warnings: {_reasons(result)}")

        doc = result.document
        if self.badge_type not in list(doc.type):
            raise BadgeError(f"expected {self.badge_type}, got types {list(doc.type)}")

        subject = doc.content["id"] if "id" in doc.content else None
        if subject != claimed_agent_id:
            raise BadgeError(f"subject mismatch: badge is for {subject!r}, "
                             f"caller claims {claimed_agent_id!r}")

        if doc.expiration_date:
            try:
                exp = datetime.fromisoformat(doc.expiration_date.replace("Z", "+00:00"))
            except ValueError:
                raise BadgeError("badge expiration date unreadable") from None
            if exp.tzinfo is None or exp <= datetime.now(timezone.utc):
                raise BadgeError("badge expired")

        role = self.role_map.get(subject)
        if not role:
            raise BadgeError(f"no role mapped for verified id {subject!r}")
        return VerifiedIdentity(agent_id=subject, role=role, badge_id=doc.id or subject)


def _reasons(result: Any) -> str:
    items = list(result.errors) + list(result.warnings)
    return "; ".join(getattr(i, "message", "") or str(getattr(i, "reason", i))
                     for i in items) or "no reason given"
