"""Network tools. LAB ONLY — device tools are mocks (swap for pyATS / CML / DevNet sandbox).

`push_config` records what would have been pushed so tests can prove a blocked call
never reached the device. `review_change` runs RuleGate's deterministic review engine
(agenttrustsec.review, P5a) against the lab device's rulebase.
"""
from __future__ import annotations

from typing import Any

PUSHED: list[dict] = []

# Lab inventory (the CMDB stand-in): the only device names agents may plan against.
DEVICES = ("edge-fw-01", "edge-fw-02", "core-rtr-01", "core-rtr-02")

_ACLS = {
    "edge-fw-01": [
        "permit tcp any host 10.0.0.10 eq 443",
        "permit ip any any",            # finding: overly permissive
        "deny ip any any log",
    ]
}


def show_running_config(device: str) -> str:
    return f"! running-config for {device} (mock)\nhostname {device}\n"


def show_acl(device: str) -> list[str]:
    return list(_ACLS.get(device, []))


def show_bgp_neighbors(device: str) -> list[dict]:
    return [{"neighbor": "192.0.2.1", "state": "Established", "asn": 65001}]


def review_change(device: str, change: dict[str, Any] | None = None) -> dict:
    """Review a proposed firewall change (RuleGate change-request schema, `target` omitted:
    the device decides vendor and rulebase). Decision and findings are deterministic."""
    from agenttrustsec.review.engine import review_for_device, summary
    if not change:
        raise ValueError("review_change needs a change request (RuleGate schema, without target)")
    return {"device": device, **summary(review_for_device(device, change))}


def push_config(device: str, lines: list[str]) -> str:
    PUSHED.append({"device": device, "lines": list(lines)})
    return f"pushed {len(lines)} lines to {device} (mock)"


REGISTRY = {
    "show_running_config": show_running_config,
    "show_acl": show_acl,
    "show_bgp_neighbors": show_bgp_neighbors,
    "review_change": review_change,
    "push_config": push_config,
}
