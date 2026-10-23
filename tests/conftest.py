import secrets
from pathlib import Path

import pytest

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.broker import TokenBroker
from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.tbac import TbacPolicy
from agenttrustsec.identity.badge import LocalDevVerifier
from agenttrustsec.models import Intent, Session
from agenttrustsec.tools import netops

ROOT = Path(__file__).resolve().parents[1]


def signed_server(name, gate, broker, verifier, registry):
    """build_server() with a dev MCP-server badge that signs exactly what it serves (item C)."""
    import asyncio

    from agenttrustsec.mcpgate import inventory
    from agenttrustsec.mcpgate.server import build_server
    serving = asyncio.run(inventory.served(build_server(name, gate, broker, None, registry)))
    badge = verifier.issue(name, "mcp_server", tools=inventory.to_badge_tools(serving))
    return build_server(name, gate, broker, badge, registry)


@pytest.fixture
def verifier():
    return LocalDevVerifier(secrets.token_bytes(32))


@pytest.fixture
def policy():
    return TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "decisions.jsonl")


@pytest.fixture
def broker():
    return TokenBroker(secrets.token_bytes(32))


@pytest.fixture
def gate(verifier, policy, audit, broker):
    return Gate(verifier, policy, BaselineIntentChecker(), audit, approvals=broker)


@pytest.fixture
def read_session():
    return Session("Audit the ACLs on edge-fw-01 for permissive rules", Intent.READ)


@pytest.fixture
def change_session():
    return Session("Remove the permit any any rule from the ACL on edge-fw-01", Intent.CHANGE)


@pytest.fixture(autouse=True)
def clear_pushes():
    netops.PUSHED.clear()
    yield
    netops.PUSHED.clear()
