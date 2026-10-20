"""Mock external data source (threat-intel API). LAB ONLY.

Stands in for any third-party API an MCP tool reaches (threat intel, CMDB, ticketing).
It accepts ONLY a broker-minted token scoped to its audience and the calling tool.
No static API key exists in the agent or the MCP server.
"""
from __future__ import annotations

from agenttrustsec.authz.broker import CURRENT_TOKEN, TokenBroker, TokenError

AUDIENCE = "threat-intel-api"

_REPUTATION = {"203.0.113.66": "malicious", "198.51.100.7": "suspicious"}


class ThreatIntelAPI:
    def __init__(self, broker: TokenBroker):
        self.broker = broker
        self.served: list[dict] = []  # proves which calls actually got data

    def reputation(self, token: str | None, ip: str) -> dict:
        claims = self.broker.redeem(token, audience=AUDIENCE, tool="lookup_threat_intel")
        self.served.append({"sub": claims["sub"], "ip": ip})
        return {"ip": ip, "verdict": _REPUTATION.get(ip, "unknown")}


def make_registry(api: ThreatIntelAPI) -> dict:
    def lookup_threat_intel(ip: str) -> dict:
        token = CURRENT_TOKEN.get()
        if token is None:
            raise TokenError("no brokered token for this call")
        return api.reputation(token, ip)

    return {"lookup_threat_intel": lookup_threat_intel}
