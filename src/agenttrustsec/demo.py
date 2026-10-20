"""Run scenario files against the Gate and print a Live-Logs style table.

    python -m agenttrustsec.demo                      # all scenarios
    python -m agenttrustsec.demo scenarios/rogue_agent.yaml
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import yaml

from agenttrustsec.audit.log import AuditLog
from agenttrustsec.authz.gate import BlockedError, Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.tbac import TbacPolicy
from agenttrustsec.identity.badge import LocalDevVerifier
from agenttrustsec.models import Intent, Session, ToolCall
from agenttrustsec.tools import netops

ROOT = Path(__file__).resolve().parents[2]


def build_badge(kind: str, agent_id: str, role: str, v: LocalDevVerifier,
                attacker_v: LocalDevVerifier) -> str | None:
    if kind == "valid":
        return v.issue(agent_id, role)
    if kind == "none":
        return None
    if kind == "forged":
        return attacker_v.issue(agent_id, role)  # signed with the wrong key
    if kind == "stolen":
        return v.issue("executor-01", role)       # real badge, different subject
    if kind == "revoked":
        b = v.issue(agent_id, role, badge_id=f"revoked-{agent_id}")
        v.revoke(f"revoked-{agent_id}")
        return b
    raise ValueError(f"unknown badge kind {kind!r}")


def run_scenario(path: Path, gate: Gate, v: LocalDevVerifier,
                 attacker_v: LocalDevVerifier) -> bool:
    sc = yaml.safe_load(path.read_text())
    session = Session(sc["session"]["user_prompt"], Intent(sc["session"]["intent"]))
    print(f"\n=== {sc['name']} ===")
    print(f"Prompt: {session.user_prompt!r}   intent={session.intent.value}\n")
    print(f"{'':2}{'STEP':<52}{'VERDICT':<8}{'BLOCKED BY':<11}REASON")

    ok = True
    for step in sc["steps"]:
        badge = build_badge(step["badge"], step["agent_id"], step["role"], v, attacker_v)
        call = ToolCall(step["agent_id"], badge, step["tool"], session, step.get("args", {}))
        try:
            gate.execute(call, netops.REGISTRY)
            d = None
            verdict, by, reason = "ALLOW", "-", "all checks passed"
        except BlockedError as e:
            d = e.decision
            bad = next(c for c in d.checks if c.name == d.blocked_by)
            verdict, by, reason = "BLOCK", d.blocked_by, bad.reason
        match = verdict == step["expect"]
        ok &= match
        mark = "✔" if match else "✘"
        print(f"{mark} {step['label'][:50]:<52}{verdict:<8}{by:<11}{reason}")
    return ok


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or sorted((ROOT / "scenarios").glob("*.yaml"))
    v = LocalDevVerifier(secrets.token_bytes(32))
    attacker_v = LocalDevVerifier(secrets.token_bytes(32))
    audit_path = ROOT / "audit" / "decisions.jsonl"
    gate = Gate(v, TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml"),
                BaselineIntentChecker(), AuditLog(audit_path))

    all_ok = all([run_scenario(p, gate, v, attacker_v) for p in paths])
    print(f"\nDevice pushes that actually happened: {netops.PUSHED}")
    print(f"Audit log: {audit_path}")
    print("\nRESULT:", "all expectations met" if all_ok else "EXPECTATION MISMATCH")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
