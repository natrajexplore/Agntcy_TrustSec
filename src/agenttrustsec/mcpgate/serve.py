"""Run the gated netops MCP server over streamable HTTP (lab). LAB ONLY: 127.0.0.1.

    python -m agenttrustsec.mcpgate.serve --port 9090                 # badge issuance mode
    python -m agenttrustsec.mcpgate.serve --port 9090 --server-id AGNTCY-...

Without --server-id the server holds no badge: `identity badge issue mcp` can discover
it (initialize, tools/list, resources/list), but every tools/call is BLOCKED.
With --server-id it fetches its published MCPServerBadge from the Identity Node and
verifies it (signature, revocation, type, subject, role mcp_server) before serving —
like a switch that won't come up on the fabric without a valid cert.

Agents are verified as AGNTCY badges against `policies/identities.yaml`. The broker key
is per-process, so sessions must be sealed by this process (intake wiring is P5).
"""
from __future__ import annotations

import argparse
import json
import secrets
import urllib.request
from pathlib import Path

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.tbac import TbacPolicy
from agenttrustsec.identity.agntcy import (
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, load_role_map,
)
from agenttrustsec.identity.badge import BadgeError
from agenttrustsec.mcpgate.client import SERVER_ROLE
from agenttrustsec.mcpgate.server import build_server
from agenttrustsec.tools import extdata, netops

ROOT = Path(__file__).resolve().parents[3]
IDENTITIES = ROOT / "policies" / "identities.yaml"


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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--server-id", help="this server's AGNTCY metadata id (badge subject)")
    ap.add_argument("--node", default="http://localhost:4000", help="Identity Node HTTP")
    ap.add_argument("--name", default="netops-mcp")
    args = ap.parse_args(argv)

    badge = fetch_server_badge(args.node, args.server_id) if args.server_id else None
    broker = TokenBroker(secrets.token_bytes(32))
    gate = Gate(AgntcyBadgeVerifier(load_role_map(IDENTITIES, "agents")),
                TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml"),
                BaselineIntentChecker(), AuditLog(ROOT / "audit" / "decisions.jsonl"))
    server = build_server(args.name, gate, broker, badge,
                          {**netops.REGISTRY, **extdata.make_registry(extdata.ThreatIntelAPI(broker))})
    print(f"{args.name}: http://127.0.0.1:{args.port}/mcp  badge="
          f"{'verified ' + args.server_id if badge else 'NONE (issuance mode, tools/call BLOCKED)'}",
          flush=True)
    server.run(transport="streamable-http", host="127.0.0.1", port=args.port,
               streamable_http_path="/mcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
