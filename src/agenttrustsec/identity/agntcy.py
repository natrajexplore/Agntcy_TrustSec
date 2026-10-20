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
  * BUT Verify only checks the status INSIDE the presented badge. Revocation re-signs
    the same VC id with a REVOCATION credentialStatus and the node stores THAT copy;
    the holder's original copy still verifies status=True (proven on a live node,
    docs/notes-p1.md step 8). So we also fetch the node's published copies for the
    subject (GetWellKnown) and require the presented VC id to be published and not
    revoked — the OCSP/CRL check a switch does on top of signature validation.
  * The node path checks signature (issuer JWKS) + revocation, but no expiry check was
    found -> we enforce `expiration_date` here.
  * VC `type` contains "AgentBadge" or "MCPServerBadge"; subject is content["id"].
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from agenttrustsec.identity.badge import BadgeError, VerifiedIdentity
from agenttrustsec.identity.keys import THUMBPRINT_ANNOTATION

AGENT_BADGE = "AgentBadge"
MCP_SERVER_BADGE = "MCPServerBadge"

REVOKED = "CREDENTIAL_STATUS_PURPOSE_REVOCATION"

# Takes the JOSE compact string the caller presented; returns a VerificationResult.
NodeVerify = Callable[[str], Any]
# Takes a badge subject (metadata id); returns the JOSE strings the node publishes for it.
NodePublished = Callable[[str], list[str]]


def sdk_node() -> tuple[NodeVerify, NodePublished]:
    """Real Identity Node via the SDK. Env: IDENTITY_NODE_GRPC_SERVER_URL,
    IDENTITY_NODE_USE_SSL (see SDK README). `_get_vc_service` is SDK-internal (0.0.26);
    the public `get_badge` returns only the first VC, not all of them."""
    from agntcy.identity.core.v1alpha1 import vc_pb2
    from agntcy.identity.node.v1alpha1 import vc_service_pb2
    from agntcyidentity.sdk import IdentitySdk

    sdk = IdentitySdk()

    def verify(jose: str) -> Any:
        return sdk.verify_badge(vc_pb2.EnvelopedCredential(
            envelope_type=vc_pb2.CREDENTIAL_ENVELOPE_TYPE_JOSE, value=jose))

    def published(subject: str) -> list[str]:
        resp = sdk._get_vc_service().GetWellKnown(
            vc_service_pb2.GetVcWellKnownRequest(id=subject))
        return [vc.value for vc in resp.vcs]

    return verify, published


def _payload(jose: str) -> dict:
    part = jose.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


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
                 node: NodeVerify | None = None, published: NodePublished | None = None,
                 key_thumbprints: dict[str, str] | None = None):
        if (node is None) != (published is None):
            raise ValueError("pass both node and published, or neither (no partial checks)")
        self.role_map = dict(role_map)
        # D2: keys bound outside the badge (an MCPServerBadge can't carry one)
        self.key_thumbprints = dict(key_thumbprints or {})
        self.badge_type = badge_type
        self._node = node
        self._published = published

    def verify(self, badge: str | None, claimed_agent_id: str) -> VerifiedIdentity:
        if not badge or not isinstance(badge, str):
            raise BadgeError("no badge presented")
        if self._node is None:
            self._node, self._published = sdk_node()
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

        self._check_published_status(subject, doc.id)

        role = self.role_map.get(subject)
        if not role:
            raise BadgeError(f"no role mapped for verified id {subject!r}")
        return VerifiedIdentity(agent_id=subject, role=role, badge_id=doc.id or subject,
                                key_thumbprint=self._bound_key(subject, doc.content))

    def _bound_key(self, subject: str, content: Any) -> str | None:
        signed = _badge_thumbprint(content)
        mapped = self.key_thumbprints.get(subject)
        if signed and mapped and signed != mapped:
            raise BadgeError(f"key conflict for {subject!r}: badge binds {signed}, "
                             f"identities.yaml binds {mapped}")
        return signed or mapped


    def _check_published_status(self, subject: str, vc_id: str) -> None:
        # Lookup errors propagate -> Gate ERROR -> BLOCK. Unreadable copies -> BLOCK.
        current = []
        for jose in self._published(subject):
            try:
                vc = _payload(jose)
            except (ValueError, IndexError):
                raise BadgeError("identity node published an unreadable badge") from None
            if vc_id and vc.get("id") == vc_id:
                current.append(vc)
        if not current:
            raise BadgeError(f"badge {vc_id!r} is not published by the identity node")
        if any(s.get("purpose") == REVOKED
               for vc in current for s in (vc.get("credentialStatus") or [])):
            raise BadgeError(f"badge {vc_id!r} revoked (node's published copy)")


def _badge_thumbprint(content: Any) -> str | None:
    """The key thumbprint the issuer signed into an OASF AgentBadge, if any."""
    try:
        record = json.loads(content["badge"]) if "badge" in content else None
    except (TypeError, ValueError):
        return None
    annotations = record.get("annotations") if isinstance(record, dict) else None
    value = annotations.get(THUMBPRINT_ANNOTATION) if isinstance(annotations, dict) else None
    return value if isinstance(value, str) and value else None


def load_key_thumbprints(path: str | Path) -> dict[str, str]:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    entries = raw.get("key_thumbprints") or {}
    if not isinstance(entries, dict):
        raise ValueError("key_thumbprints: must be a mapping of badge id -> thumbprint")
    for ident, thumb in entries.items():
        if any(w in (str(ident), str(thumb)) for w in ("*", "any", "all")):
            raise ValueError("key_thumbprints: wildcards are forbidden (deny by default)")
    return {str(k): str(v) for k, v in entries.items()}


def _reasons(result: Any) -> str:
    items = list(result.errors) + list(result.warnings)
    return "; ".join(getattr(i, "message", "") or str(getattr(i, "reason", i))
                     for i in items) or "no reason given"
