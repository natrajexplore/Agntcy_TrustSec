"""Mock network tools. LAB ONLY — swap for pyATS / CML / DevNet sandbox in P5.

`push_config` records what would have been pushed so tests can prove a blocked call
never reached the device.
"""
from __future__ import annotations

PUSHED: list[dict] = []

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


def review_change(device: str, change: str = "") -> dict:
    findings = [r for r in _ACLS.get(device, []) if "any any" in r and r.startswith("permit")]
    return {"device": device, "risk": "high" if findings else "low", "findings": findings}


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
