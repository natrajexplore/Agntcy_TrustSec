"""Firewall change review — RuleGate's deterministic core (P5a, docs/P5-design.md E1/E2).

TrustSec analogy: the change board's rulebook. Facts (shadowing, address math, RG-xxx risk
checks, severity and decision) are computed by plain Python from `data/risk_policy.yaml`;
no agent and no LLM decides them. The gateway exposes this as the `review_change` tool, so
every review runs behind the gate (badge -> peer -> TBAC -> intent) and is audited.
"""
