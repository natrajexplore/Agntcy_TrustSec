"""Agent runtime (P5b): what every AgentTrustSec agent process needs to work on the fabric.

TrustSec analogy: the endpoint's supplicant. It holds the agent's identity (its private key and
its issuer-signed badge), joins the fabric by dialing OUT to the SLIM node under its own name
(no inbound port), and only trusts the gateway after mutual authentication — the gateway's
badge must verify AND the gateway must prove it holds the key that badge binds (P3 peer check).

Registry: lab/agents.yaml (public ids). Keys: ~/.agenttrustsec/keys/<name>.pem.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agenttrustsec.authz.peer import PeerBinding, slim_name
from agenttrustsec.identity.agntcy import (
    MCP_SERVER_BADGE, AgntcyBadgeVerifier, fetch_current_badge, load_key_thumbprints, load_role_map,
)

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "lab" / "agents.yaml"
IDENTITIES = ROOT / "policies" / "identities.yaml"
TRUST_JWKS = ROOT / "policies" / "trust-jwks.json"
KEY_DIR = Path.home() / ".agenttrustsec" / "keys"
NODE_HTTP = "http://localhost:4000"
SLIM_ENDPOINT = "http://127.0.0.1:46357"


@dataclass(frozen=True)
class AgentConfig:
    name: str
    metadata_id: str
    gateway_id: str
    key_path: Path
    node_http: str = NODE_HTTP
    slim_endpoint: str = SLIM_ENDPOINT


def load_agent(name: str, registry: Path = REGISTRY, key_dir: Path = KEY_DIR) -> AgentConfig:
    raw = yaml.safe_load(registry.read_text(encoding="utf-8"))
    agents = raw.get("agents") or {}
    if name not in agents:
        raise KeyError(f"agent {name!r} is not in {registry}")
    return AgentConfig(name, agents[name], raw["gateway"]["metadata_id"], key_dir / f"{name}.pem")


def result_body(result: Any) -> Any:
    """CallToolResult -> parsed JSON (or the plain text)."""
    text = " ".join(getattr(c, "text", "") for c in result.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


class AgentRuntime:
    def __init__(self, cfg: AgentConfig, trust_jwks: Path = TRUST_JWKS):
        self.cfg = cfg
        self.trust_jwks_path = trust_jwks
        self.endpoint = None
        self.badge: str | None = None

    async def start(self) -> AgentRuntime:
        from agenttrustsec.transport import slim       # needs the [slim] extra
        trust = json.loads(self.trust_jwks_path.read_text(encoding="utf-8"))["keys"]
        self._trust = trust
        self.badge = fetch_current_badge(self.cfg.node_http, self.cfg.metadata_id)
        name = slim_name(self.cfg.metadata_id)
        pem = self.cfg.key_path.read_text(encoding="utf-8")
        self.endpoint = await slim.connect(name, slim.jwt_identity(pem, name, trust), self.cfg.slim_endpoint)
        return self

    def server_verifier(self) -> AgntcyBadgeVerifier:
        return AgntcyBadgeVerifier(load_role_map(IDENTITIES, "mcp_servers"), badge_type=MCP_SERVER_BADGE,
                                   key_thumbprints=load_key_thumbprints(IDENTITIES))

    @asynccontextmanager
    async def gateway(self, session_token: str) -> AsyncIterator[Any]:
        """A TrustedClient to the gateway over an MLS SLIM session, with mutual peer checks."""
        from mcp import Client

        from agenttrustsec.mcpgate.client import TrustedClient
        from agenttrustsec.transport import slim
        if self.endpoint is None:
            raise RuntimeError("call start() first")
        transport = slim.SlimClientTransport(self.endpoint, slim_name(self.cfg.gateway_id))
        async with Client(transport) as c:
            yield TrustedClient(c, agent_id=self.cfg.metadata_id, badge=self.badge,
                                session_token=session_token, verifier=self.server_verifier(),
                                server_id=self.cfg.gateway_id, transport_peer=lambda: transport.peer,
                                peer_binding=PeerBinding(self._trust))
