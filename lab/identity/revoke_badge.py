"""Revoke a published AGNTCY badge on the lab Identity Node. LAB ONLY. IRREVERSIBLE.

    python lab/identity/revoke_badge.py <metadata-id>             # dry run: shows the target
    python lab/identity/revoke_badge.py <metadata-id> --yes       # actually revoke

The v0.0.26 CLI has no revoke command; this mirrors the node's `VcService/Revoke`
contract (internal/node/vc_service.go @ 8f7c1b5):
  * vc    = the SAME VC (same id), re-signed by the issuer key, with a credentialStatus
            entry of purpose CREDENTIAL_STATUS_PURPOSE_REVOCATION added
  * proof = self-issued JWT signed by the issuer key (pkg/oidc/self_issue.go):
            iss "agntcy:<issuer common name>", sub = aud = metadata id minus "AGNTCY-"
The node then overwrites its stored copy; .well-known serves the revoked version.

TrustSec analogy: the CA revoking a cert and publishing it to the CRL. Note the node's
Verify only checks the status INSIDE the presented badge — see AgntcyBadgeVerifier's
status check for why consumers must also consult the node's published copy.

The issuer private key is read from the CLI file vault (~/.identity/vault.json), kept
in memory only, and never printed. Env: IDENTITY_NODE_GRPC_SERVER_URL, IDENTITY_NODE_USE_SSL.
"""
from __future__ import annotations

import argparse
import base64
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jwt
from jwt.algorithms import RSAAlgorithm

REVOKED = "CREDENTIAL_STATUS_PURPOSE_REVOCATION"
_PRIVATE = {"d", "p", "q", "dp", "dq", "qi"}


def _b64json(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def decode(jose: str) -> tuple[dict, dict]:
    head, payload, _ = jose.split(".")
    return _b64json(head), _b64json(payload)


def is_revoked(vc: dict) -> bool:
    return any(s.get("purpose") == REVOKED for s in vc.get("credentialStatus") or [])


def load_issuer_key(vault: Path, kid: str):
    for k in json.loads(vault.read_text()):
        if k.get("kid") == kid:
            public = {f: v for f, v in k.items() if f not in _PRIVATE}
            return RSAAlgorithm.from_jwk(json.dumps(k)), public
    raise SystemExit(f"key {kid} not found in {vault}")


def build_revocation(jose: str, metadata_id: str, vault: Path) -> tuple[str, str]:
    header, vc = decode(jose)
    key, public_jwk = load_issuer_key(vault, header["kid"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vc["credentialStatus"] = [*(vc.get("credentialStatus") or []), {
        "id": f"{vc['id']}#revocation", "type": "RevocationEntry",
        "createdAt": now, "purpose": REVOKED}]
    revoked = jwt.api_jws.encode(json.dumps(vc).encode(), key, algorithm=header["alg"],
                                 headers={"kid": header["kid"]})
    sub = metadata_id.removeprefix("AGNTCY-")
    t = int(time.time())
    proof = jwt.encode({"iss": f"agntcy:{vc['issuer']}", "sub": sub, "aud": [sub],
                        "iat": t, "exp": t + 3600, "jti": str(uuid.uuid4()),
                        "sub_jwk": public_jwk},
                       key, algorithm=header["alg"], headers={"kid": header["kid"]})
    return revoked, proof


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("metadata_id")
    ap.add_argument("--vc-id", help="required if the metadata id has several badges")
    ap.add_argument("--vault", type=Path, default=Path.home() / ".identity" / "vault.json")
    ap.add_argument("--yes", action="store_true", help="really revoke (irreversible)")
    args = ap.parse_args(argv)

    from agntcy.identity.core.v1alpha1 import vc_pb2
    from agntcy.identity.node.v1alpha1 import vc_service_pb2
    from agntcyidentity.sdk import IdentitySdk

    stub = IdentitySdk()._get_vc_service()
    vcs = stub.GetWellKnown(vc_service_pb2.GetVcWellKnownRequest(id=args.metadata_id)).vcs
    matches = [v.value for v in vcs if args.vc_id in (None, decode(v.value)[1]["id"])]
    if len(matches) != 1:
        ids = [decode(v.value)[1]["id"] for v in vcs]
        raise SystemExit(f"need exactly one target badge, found {ids}; use --vc-id")
    jose = matches[0]
    _, vc = decode(jose)
    print(f"target: VC {vc['id']}  types {vc['type']}  subject {vc['credentialSubject']['id']}")
    if is_revoked(vc):
        raise SystemExit("already revoked")
    if not args.yes:
        print("dry run — re-run with --yes to revoke (IRREVERSIBLE)")
        return 0

    revoked, proof = build_revocation(jose, args.metadata_id, args.vault)
    stub.Revoke(vc_service_pb2.RevokeRequest(
        vc=vc_pb2.EnvelopedCredential(envelope_type=vc_pb2.CREDENTIAL_ENVELOPE_TYPE_JOSE,
                                      value=revoked),
        proof=vc_pb2.Proof(type="JWT", proof_value=proof)))
    print(f"revoked VC {vc['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
