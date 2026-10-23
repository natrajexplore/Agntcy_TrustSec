# P5 design — real agents on the secured fabric

Goal (CLAUDE.md P5): replace test stand-ins with real agents — **intake, reader, reviewer
(port of the CrewAI Palo Alto / FTD change reviewer), executor** — plus a **rogue agent**,
all running as separate processes on SLIM through the gated MCP gateway, local Ollama only.

TrustSec analogy: P0–P4 built the network (ISE, SGTs, SGACLs, MACsec, posture). P5 plugs real
endpoints into it and runs a real workflow end to end, so the Live Logs show actual work being
allowed and actual attacks being stopped.

## 1. What exists today

* Identities, keys, badges for `intake-01`, `reader-01`, `reviewer-01`, `executor-01` and the
  gateway; roles in `policies/identities.yaml`; TBAC in `policies/tbac.yaml`.
* Gateway (`serve.py --transport slim`): badge → peer → TBAC → intent (scope; local LLM for
  change tools); sealed sessions + token broker; audit.
* Attested reviewer group (`transport/slim_group.py`, moderator = intake).
* Agents today exist only as **test child processes** (`tests/_slim_agent_child.py`,
  `tests/_group_children.py`). `src/agenttrustsec/agents/` is empty.
* `tools/netops.py::review_change` is a **mock** (flags `permit … any any`).

## 2. RuleGate (sibling repo `crewai_fw_chg_reviewer`) — verified 2026-10-25

~4.1k lines. Pipeline docstring: *"Agents never compute facts; they read the ReviewContext
through tools."* Facts are deterministic Python: `analysis/address_math.py`, `shadow.py`,
`risk_rules.py` (checks RG-001…RG-013, severities and score from `config/risk_policy.yaml`,
"severity is decided here, never by an agent"), PAN-OS + FTD/FMC parsers, pydantic models
(`NormalizedChangeRequest`, findings), sample change requests + rulebases. The **CrewAI crew
(7 agents) only narrates** and writes the CAB report — and it is wired to a **paid API**
(`crewai[anthropic]`, `MODEL=anthropic/claude-sonnet-…`), which this project forbids.

## 3. Proposed design

**Agents** (`src/agenttrustsec/agents/`, one process each, dial OUT to SLIM, no ports):

| Agent | Does | Talks to |
|---|---|---|
| `intake-01` | takes the engineer's request (CLI), classifies intent (read / change), **seals the session** (owns the broker key), routes the work, moderates the reviewer group | engineer; reader (P2P); reviewer pool (attested group); executor (P2P) |
| `reader-01` | calls `show_*` tools through the gateway, returns the data | gateway |
| `reviewer-01` | joins the attested group, calls **`review_change`** through the gateway, replies approve / reject with findings | gateway; intake (group) |
| `executor-01` | applies an **approved** change with `push_config` through the gateway | gateway; intake |
| `rogue` | scripted attacks with real or stolen material (§5) | gateway / group |

**RuleGate port (E1, E2):** vendor RuleGate's **deterministic core** (analysis, parsers, models,
`risk_policy.yaml`, sample rulebases as lab data) into `src/agenttrustsec/review/`, and make the
gateway's `review_change` tool call it instead of the mock. The verdict stays deterministic and
**behind the gate** (badge + peer + TBAC + intent). CrewAI and its paid-API LLM are not ported.

**Change approval binding (E3):** today an executor with a `change` session could push without
any review. Proposed: intake mints a **single-use approval token** (broker, like the external-data
tokens) only after the reviewer pool approves, bound to `change_id` + device + a hash of the exact
lines; the gate requires it for `push_config` (new check, deny by default). TrustSec analogy: a
change-of-authorization issued only after posture remediation — the port opens for exactly this
change, once.

**Local LLM use (E4):** keep facts and verdicts deterministic. The LLM stays where P4 put it (the
gate's semantic check for change tools). Agents add no LLM calls in P5 (intake intent uses the
existing keyword classifier); optional local-LLM summaries can come later.

## 4. Workflow (change request)

```
engineer ─► intake: "remove permit any any on edge-fw-01"  → intent=change, session sealed
intake ─► reviewer group (attested): proposal {change_id, device, lines}
reviewer ─► gateway: review_change(device, change)  → RuleGate findings → reply approve/reject
intake: all reviewers approve → mint approval token (change_id + device + lines hash)
intake ─► executor (P2P): change + approval token + sealed session
executor ─► gateway: push_config(device, lines)  → badge, peer, TBAC, intent (scope + LLM),
                                                    approval token  → ALLOW → mock device
every step → audit/decisions.jsonl
```

## 5. Rogue scenarios (each must be BLOCKED, and audited)

1. Rogue with its own trusted key replays the executor's badge → `peer`.
2. Genuine reader tries `push_config` → `tbac`.
3. Genuine executor pushes during a read session → `intent` (change gate).
4. Executor pushes lines **different from the approved ones** → approval token (E3).
5. Executor replays a used approval token → approval token (single use).
6. Impostor joins the reviewer group under reviewer's name → group admission (`peer`).
7. Revoked agent → `badge`.

## 6. Work order (one PR each)

* **P5a** vendor RuleGate core → `review/`; `review_change` uses it; tests incl. RuleGate's
  own sample CRs (CR-1003 any/any must be rejected).
* **P5b** agent runtime (identity, SLIM endpoint, `TrustedClient`) + `reader-01` + CLI.
* **P5c** `intake-01`: session sealing, intent, routing, reviewer-group moderation.
* **P5d** `reviewer-01` + `executor-01` + approval token (E3) in broker and gate.
* **P5e** rogue scenarios + one end-to-end demo script on the live lab; README walkthrough.

## 7. Decisions

**Owner approved E1–E5 as recommended (2026-10-25).**


* **E1 RuleGate:** vendor the deterministic core (**recommended**: no CrewAI, no paid API) vs
  depend on the RuleGate package vs keep the mock.
* **E2 Where review runs:** as the gateway's `review_change` tool, behind the gate
  (**recommended**) vs inside the reviewer agent.
* **E3 Approval binding for `push_config`:** require a single-use reviewer-approval token
  (**recommended**) vs rely on the intent check only.
* **E4 LLM in agents:** none in P5, deterministic facts (**recommended**) vs local-LLM
  summaries now.
* **E5 Memory:** agents are light Python processes; only one Ollama model is ever loaded and only
  the gateway calls it. A full demo = lab containers + gateway + 4–5 agents + Ollama on the
  15.5 GB laptop — expected to fit, measured in P5e.
