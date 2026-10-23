"""Run the gated netops MCP server (lab). Tool calls are served ONLY over SLIM (D4).

    python -m agenttrustsec.mcpgate.serve --port 9090                     # HTTP: badge issuance
    python -m agenttrustsec.mcpgate.serve --transport slim --server-id AGNTCY-...

HTTP (127.0.0.1) only exists for `identity badge issue mcp` discovery: the server holds no
badge there, so every tools/call is BLOCKED (and audited).

SLIM: the gateway dials OUT to the SLIM node (no inbound port) and refuses to start unless
  * its published MCPServerBadge verifies (signature, published + not revoked, type,
    subject, role mcp_server) — a switch that won't join the fabric without a valid cert
  * its private key is the one bound to that badge (D2 `key_thumbprints`) and is in the
    trust JWKS — so agents' mutual-auth check can succeed
Every tools/call then passes the mandatory `peer` check (authz/peer.py) before TBAC/intent;
change tools are also judged by the local LLM verifier (P4e, D4) — no Ollama / changed
model = refuse to start.

Agents are verified as AGNTCY badges against `policies/identities.yaml`. Sessions are
sealed by the broker; AGENTTRUSTSEC_BROKER_KEY (hex, >= 32 bytes) shares its key with the
lab intake stand-in, otherwise it is per-process (intake wiring is P5).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.peer import PeerBinding, slim_name
from agenttrustsec.authz.tbac import TbacPolicy
from agenttrustsec.identity.agntcy import (
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_key_thumbprints, load_role_map,
)
from agenttrustsec.identity.badge import BadgeError
from agenttrustsec.identity.keys import jwk_thumbprint, public_jwk
from agenttrustsec.mcpgate.client import SERVER_ROLE
from agenttrustsec.mcpgate.server import build_server
from agenttrustsec.tools import extdata, netops

ROOT = Path(__file__).resolve().parents[3]
IDENTITIES = ROOT / "policies" / "identities.yaml"
TRUST_JWKS = ROOT / "policies" / "trust-jwks.json"
KEY_DIR = Path.home() / ".agenttrustsec" / "keys"


def fetch_server_badge(node_http: str, server_id: str) -> str:
    """Return the first published badge for server_id that verifies as our MCP server."""
    url = f"{node_http}/v1alpha1/vc/{server_id}/.well-known/vcs.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        vcs = json.load(r).get("vcs") or []
    verifier = AgntcyBadgeVerifier(load_role_map(IDENTITIES, "mcp_servers"),
                                   badge_type=MCP_SERVER_BADGE)
    errors = []
    for vc in vcs:                                # node order isn't guaranteed
        try:
            ident = verifier.verify(vc.get("value"), server_id)
        except BadgeError as e:
            errors.append(str(e))
            continue
        if ident.role == SERVER_ROLE:
            return vc["value"]
        errors.append(f"role {ident.role!r} is not {SERVER_ROLE!r}")
    raise BadgeError(f"no valid MCP server badge for {server_id!r}: {errors or 'none published'}")


def load_trust_jwks(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text())["keys"]


def check_own_key(pem: str, server_id: str, trust: list[dict[str, str]]) -> str:
    """The gateway's key must be the one its badge binds (D2) and be trusted by SLIM."""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    thumb = jwk_thumbprint(public_jwk(key.public_key()))
    bound = load_key_thumbprints(IDENTITIES).get(server_id)
    if thumb != bound:
        raise BadgeError(f"gateway key {thumb} is not the key bound to {server_id} ({bound})")
    if thumb not in {jwk_thumbprint(k) for k in trust}:
        raise BadgeError(f"gateway key {thumb} is not in the trust JWKS")
    return thumb


def broker_from_env() -> TokenBroker:
    hexkey = os.environ.get("AGENTTRUSTSEC_BROKER_KEY")
    if not hexkey:
        return TokenBroker(secrets.token_bytes(32))
    key = bytes.fromhex(hexkey)
    if len(key) < 32:
        raise ValueError("AGENTTRUSTSEC_BROKER_KEY must be >= 32 bytes (64 hex chars)")
    return TokenBroker(key)


def make_gate(audit_path: Path, peer: PeerBinding | None, semantic=None,
              approvals: TokenBroker | None = None) -> Gate:
    verifier = AgntcyBadgeVerifier(load_role_map(IDENTITIES, "agents"),
                                   key_thumbprints=load_key_thumbprints(IDENTITIES))
    return Gate(verifier, TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml"),
                BaselineIntentChecker(semantic), AuditLog(audit_path), peer=peer,
                approvals=approvals)


class LlmUnavailable(Exception):
    """The local LLM verifier can't be set up -> the gateway refuses to start (D3)."""


def local_llm_matcher():
    """P4e (D4): change tools are judged by the local Ollama verifier. Ollama down or the
    pinned model changed -> refuse to start; never fall back to the keyword check."""
    from agenttrustsec.authz.semantic import OLLAMA_MODEL, LlmMatcher, ollama_judge
    try:
        return LlmMatcher(ollama_judge()), OLLAMA_MODEL
    except (OSError, RuntimeError) as e:          # URLError is an OSError
        raise LlmUnavailable(f"local LLM verifier unavailable: {e}") from None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--transport", choices=["http", "slim"], default="http")
    ap.add_argument("--port", type=int, default=9090, help="HTTP issuance mode only")
    ap.add_argument("--server-id", help="this server's AGNTCY metadata id (badge subject)")
    ap.add_argument("--node", default="http://localhost:4000", help="Identity Node HTTP")
    ap.add_argument("--slim", default="http://127.0.0.1:46357", help="SLIM node endpoint")
    ap.add_argument("--name", default="netops-mcp")
    ap.add_argument("--key", type=Path, help="private key PEM (default ~/.agenttrustsec/keys/<name>.pem)")
    ap.add_argument("--trust-jwks", type=Path, default=TRUST_JWKS)
    ap.add_argument("--audit", type=Path, default=ROOT / "audit" / "decisions.jsonl")
    args = ap.parse_args(argv)

    if args.transport == "http":
        if args.server_id:
            ap.error("HTTP serves badge issuance only; tool calls go over SLIM (D4): use --transport slim")
        return _serve_http(args)
    if not args.server_id:
        ap.error("--transport slim requires --server-id")
    try:
        return asyncio.run(_serve_slim(args))
    except (BadgeError, LlmUnavailable) as e:
        print(f"{args.name}: REFUSING TO START: {e}", file=sys.stderr, flush=True)
        return 2


def _registry(broker: TokenBroker) -> dict:
    return {**netops.REGISTRY, **extdata.make_registry(extdata.ThreatIntelAPI(broker))}


def _serve_http(args: argparse.Namespace) -> int:
    broker = broker_from_env()
    server = build_server(args.name, make_gate(args.audit, None), broker, None, _registry(broker))
    print(f"{args.name}: http://127.0.0.1:{args.port}/mcp  badge=NONE "
          f"(issuance mode, tools/call BLOCKED)", flush=True)
    server.run(transport="streamable-http", host="127.0.0.1", port=args.port,
               streamable_http_path="/mcp")
    return 0


async def _serve_slim(args: argparse.Namespace) -> int:
    from agenttrustsec.transport import slim        # needs the [slim] extra

    trust = load_trust_jwks(args.trust_jwks)
    pem = (args.key or KEY_DIR / f"{args.name}.pem").read_text()
    thumb = check_own_key(pem, args.server_id, trust)
    badge = fetch_server_badge(args.node, args.server_id)
    broker = broker_from_env()
    llm, llm_model = local_llm_matcher()
    gate = make_gate(args.audit, PeerBinding(trust), semantic=llm, approvals=broker)
    server = build_server(args.name, gate, broker, badge, _registry(broker))
    name = slim_name(args.server_id)
    endpoint = await slim.connect(name, slim.jwt_identity(pem, name, trust), args.slim)
    print(f"{args.name}: slim {name} via {args.slim}  badge=verified {args.server_id}  "
          f"key={thumb}  peer-check=ON  change-tools-llm={llm_model}", flush=True)
    await slim.serve_slim(server, endpoint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
