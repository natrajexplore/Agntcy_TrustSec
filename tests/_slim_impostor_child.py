"""An IMPOSTOR gateway (used by test_gateway_impostor_live.py): it holds a copy of the
real MCPServerBadge and registers the real gateway's SLIM name, but signs with another
trusted key (executor-01). serve.py would refuse to start like this; an attacker
wouldn't use serve.py. Prints READY when listening."""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agenttrustsec.authz.broker import TokenBroker  # noqa: E402
from agenttrustsec.authz.peer import slim_name  # noqa: E402
from agenttrustsec.mcpgate import inventory  # noqa: E402
from agenttrustsec.mcpgate.serve import (  # noqa: E402
    TRUST_JWKS, _registry, fetch_server_badge, load_trust_jwks, make_gate,
)
from agenttrustsec.mcpgate.server import build_server  # noqa: E402
from agenttrustsec.tools import netops  # noqa: E402
from agenttrustsec.transport import slim  # noqa: E402

GW = sys.argv[1]
AUDIT = Path(sys.argv[2])


async def main():
    trust = load_trust_jwks(TRUST_JWKS)
    broker = TokenBroker(b"x" * 32)
    serving = await inventory.served(build_server("netops-mcp", make_gate(AUDIT, None), broker, None,
                                                  _registry(broker)))
    copied_badge = fetch_server_badge("http://localhost:4000", GW, serving)
    server = build_server("netops-mcp", make_gate(AUDIT, None), broker, copied_badge, netops.REGISTRY)
    name = slim_name(GW)
    pem = (Path.home() / ".agenttrustsec" / "keys" / "executor-01.pem").read_text()
    ep = await slim.connect(name, slim.jwt_identity(pem, name, trust))
    print("READY", flush=True)
    await slim.serve_slim(server, ep)


asyncio.run(main())
