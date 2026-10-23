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

## 5b. P5a as built (2026-10-25)

`src/agenttrustsec/review/`: RuleGate's analysis, parsers and models vendored verbatim (imports
renamed, provenance line per file; `crew_outputs.py` and all CrewAI/LLM code left out) +
`engine.py` (RuleGate `pipeline.py` logic; policy and rulebases from package `data/`, offline
only). `tools/netops.py::review_change(device, change)` now runs it; the **lab device decides
vendor + rulebase** (`edge-fw-01` → PAN-OS `DC-Core`, `edge-fw-02` → FTD `DC-Edge-ACP`); a
caller-supplied `target` is ignored; unknown device / missing / invalid change → tool error.
Proof of a faithful port: RuleGate's own deterministic tests ported (78), incl. its 11
labelled scenarios — **exact decision, exact check IDs, human-review flag all match**.
RuleGate treats unspecified request fields as `any`, so an empty request reviews as allow
any/any → REJECT, score 100 (fail-safe).
**Side effect:** the gateway's MCPServerBadge signs the tool inventory as issued; the new
`review_change` signature/description make that inventory stale until the badge is re-issued
(nothing checks drift yet — backlog item).

## 5c. P5b as built (2026-10-25)

* `lab/agents.yaml`: agent name → badge subject + gateway (public ids; a test checks each id
  has the expected role in `policies/identities.yaml`).
* `identity/agntcy.py::fetch_current_badge`: the agent's own **unrevoked** published badge;
  none → `BadgeError` (an agent never presents a revoked or missing badge).
* `agents/runtime.py::AgentRuntime`: key from `~/.agenttrustsec/keys/`, badge from the node,
  dials OUT to SLIM under its own name, `gateway(session)` = MLS session + `TrustedClient`
  with mutual peer checks on the gateway.
* `agents/reader.py`: runs `{tool, args}` jobs; refuses tools its role isn't allowed in TBAC
  (before any gateway contact); one-shot CLI with the lab intake stand-in.
* Live (real gateway): reader reads `show_acl` → ALLOW, audited under reader-01's id; reader
  asking for an unnamed device → gate `intent` scope BLOCK, reported cleanly. Full suite
  379 passed with the lab up.
* Bug found on the way: an MCP error raised inside the client's task group arrives as an
  ExceptionGroup; agents capture and re-raise outside it (same pattern as the test children).

## 5d. P5c1 as built (2026-10-25) — owner approved: agent-to-agent = MCP over SLIM + caller gate

* **Confused-deputy guard** (`agents/jobserver.py`): a worker acts under its own badge, so a job
  is accepted only if the caller's badge verifies, the caller's SLIM token is signed by that
  badge's key (peer check) and its role may dispatch (`reader` accepts only `intake`). One audit
  record per dispatch; the forwarded sealed session is never logged; the worker stamps its own
  badge so the caller verifies it (`TrustedClient(server_role=...)`).
* `agents/reader.py serve`: long-running job server on SLIM (`run_job(tool, args, session)`),
  forwards the session to the gateway; gateway blocks come back as results.
* `agents/intake.py`: classifies intent, **seals the session** (owns the broker key), plans one
  job deterministically — devices only from the lab inventory (`tools/netops.DEVICES`, whole
  tokens), IPv4 validated, exactly one tool group + its target, otherwise refused — and
  dispatches with mutual auth. Change requests are refused until P5c2/P5d.
* Planner reproduces every legitimate read case of `eval/netops_cases.yaml` exactly.
* Live: intake → reader → gateway ALLOW (both audit trails); **executor-01 with its genuine
  badge and key trying to dispatch to the reader → `caller` BLOCK**; unplannable request
  refused. Full suite 408 passed with the lab up.

## 5e. P5c2 + P5d as built (2026-10-23) — reviewer group, executor, approval token (E3)

* **Approval token (E3)** — `authz/broker.py::mint_approval / redeem_approval`: HMAC token
  (`typ: approval`) bound to `change_id` + device + SHA-256 of the exact ordered lines + the
  change session id, with the approver ids, 15 min ttl, **single use** (jti). `policies/tbac.yaml`:
  `push_config: requires_approval: true` (a test pins: every change tool requires it).
* **Gate** (`authz/gate.py`): new last check `approval`, only for `requires_approval` tools.
  SKIPPED (not consumed) if anything earlier failed; no approval authority configured → FAIL;
  wrong device / lines / session, expired, forged, wrong type, replay → FAIL; any other error →
  ERROR. All BLOCK. The token is never audited (`approval_presented: true|false` only). The MCP
  gateway reads it from `_meta["agenttrustsec/approval"]`; `serve.py` gives the gate the broker.
* `agents/reviewer.py serve`: waits for invites on `agenttrustsec/lab/reviewers`, verifies
  intake as moderator (badge + key + moderator role) before attesting, runs `review_change`
  through the gateway with the **read** session intake sealed for the review, replies to intake
  only. Approves only RuleGate `APPROVE` + no human review + same change_id + matching lines
  digest; APPROVE_WITH_CONDITIONS, errors, blocks, bad proposals → reject.
* `agents/executor.py serve`: `run_change(device, lines, session, approval)` behind the caller
  gate (only intake dispatches); forwards to `push_config`, decides nothing. Forwarded session
  and approval are never written to its dispatch audit.
* `agents/intake.py --change-file lab/changes/cr-XXXX.yaml "<request>"`: change order = device
  (must be the one device the request names) + exact lines + RuleGate change request. Intake
  moderates an attested group of every registered reviewer, broadcasts the proposal, and
  requires a **unanimous** approval for that proposal id + lines digest (no reviewer admitted,
  missing / stale / mismatched reply = no). Then it mints the approval for the change session and
  dispatches to executor-01.
* Live (real gateway, local LLM): **CR-1001 → reviewer APPROVE → executor push ALLOW**
  (intent `semantic: llm allow`, approval PASS CR-1001); **CR-1003 any/any → reviewer REJECT,
  only `review_change` reached the gateway, nothing pushed**; executor without approval / with
  an approval for other lines / replaying a used one → `approval` BLOCK; reader-01 dispatching to
  the executor → `caller` BLOCK. Full suite 465 passed with the lab up.
* **Known limits:** (1) reviewers judge the RuleGate change request and approve the lines digest
  they were shown, but nothing yet proves the lines *implement* that request (needs a
  deterministic CR → PAN-OS / FMC renderer; backlog). (2) Redeemed jtis live in the gateway's
  memory; a restart forgets them (15 min ttl limits the window). (3) One reviewer in the lab pool.

## 5f. P5e as built (2026-10-23) — rogue agent + live end-to-end demo (owner: full run, `--quick`)

* `agents/rogue.py`: the attacks of §5 as a real agent (`attack <name>`, raw `gateway`,
  `dispatch`, `group-impostor`), using real lab keys and copies of published badges; where an
  attack needs a sealed session or an approval it acts as a lab stand-in with the broker key
  (replaying genuine tokens). Replaces `tests/_slim_agent_child.py` / `_dispatch_child.py`; the
  live tests call it. New live case: reader `push_config` with a change session AND an approval
  → `tbac`.
* `demo_live.py`: preflight (SLIM, Identity Node, keys, Ollama — refuses otherwise), starts the
  gateway, runs four acts, prints expected vs actual + the gateway decisions as an ISE Live Logs
  view (`*` = claimed identity never verified), stops every process, exit 1 on mismatch. Act
  order is forced by SLIM routing by name: impersonation attacks run while the impersonated agent
  is offline (acts 1–3: gateway-level attacks, group impostor vs the real intake change path,
  rogue dispatch to the executor), then reader + reviewer start for the legitimate flows (act 4).
  `--quick` skips #4/#5 (extra LLM verdicts).
* Result: all 11 steps as expected. #6 end to end: intake proposes CR-1001, the impostor under
  reviewer-01's name is refused by `peer`, no reviewer admitted → no approval → nothing pushed.
* **E5 measured** (15.5 GB laptop, cold model): 8.9 GB in use before, 14.2 GB peak (+5.3 GB,
  ≈ the 5.5 GB qwen2.5:7b), 49 s full run; warm model 36 s, +0.3 GB for gateway + 4 agents.
  Fits, with ~1.3 GB headroom.
* Full suite 484 passed with the lab up.

## 6. Work order (one PR each)

* **P5a** ✅ vendor RuleGate core → `review/`; `review_change` uses it; tests incl. RuleGate's
  own sample CRs (CR-1003 any/any must be rejected).
* **P5b** ✅ agent runtime (identity, SLIM endpoint, `TrustedClient`) + `reader-01` + CLI.
* **P5c1** ✅ `intake-01`: session sealing, intent, planning, dispatch to an authenticated reader.
* **P5c2** ✅ intake proposes changes to the attested reviewer group (with P5d's reviewer).
* **P5d** ✅ `reviewer-01` + `executor-01` + approval token (E3) in broker and gate.
* **P5e** ✅ rogue scenarios + one end-to-end demo script on the live lab; README walkthrough.

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
