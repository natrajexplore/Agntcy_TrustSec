# AgentTrustSec — Architecture & Threat Model

## 1. Goals

1. Every agent and MCP server has a verifiable identity (AGNTCY Agent / MCP Server Badge).
2. Agent-to-agent traffic is end-to-end encrypted and needs no inbound ports (SLIM + MLS).
3. Tool access is least-privilege by role (TBAC) **and** scoped to the user's intent.
4. Every decision is explainable after the fact.

## 2. Actors

| Agent | Role (SGT) | Allowed tools | Notes |
|---|---|---|---|
| intake | `intake` | none (routes only) | Captures intent: `read` or `change` |
| reader | `reader` | `show_running_config`, `show_acl`, `show_bgp_neighbors` | Read-only |
| reviewer | `reviewer` | `review_change`, `show_acl` | Ports the CrewAI PA/FTD reviewer |
| executor | `executor` | `push_config`, `show_running_config` | Only role allowed change tools |
| rogue | claims `executor` | — | Invalid / revoked / forged badge, or valid badge abused |

## 3. Decision pipeline (the Gate)

```
ToolCall(agent_id, badge, tool, args, session)
  │
  ├─[1] Badge check    : signature valid, not expired, not revoked, subject == agent_id
  │                      → yields verified role
  ├─[2] TBAC check     : verified role ∈ policy[tool].allowed_roles     (deterministic)
  ├─[3] Intent check   : if tool.change → session.intent must be "change"
  │                      semantic score(user_prompt, tool) ≥ threshold
  │
  └─ Decision = ALLOW only if every check PASSES; any FAIL or ERROR → BLOCK
     → one audit record per call
```

Role is taken **only from the verified badge**, never from the caller's claim.

## 4. Threat model (what each layer stops)

| # | Attack | Stopped by |
|---|---|---|
| T1 | Unknown agent calls a tool | [1] badge missing → BLOCK |
| T2 | Forged / tampered badge | [1] signature fail → BLOCK |
| T3 | Revoked agent (old version) keeps acting | [1] revocation → BLOCK |
| T4 | Reader agent tries `push_config` | [2] TBAC → BLOCK |
| T5 | Legit executor pushes config during a read-only audit (prompt injection) | [3] intent → BLOCK |
| T6 | Allowed tool but irrelevant to request (data exfil via `show_running_config` on unrelated device) | [3] semantic → BLOCK (P4) |
| T7 | Eavesdrop / tamper on agent traffic | SLIM MLS (P3) |
| T8 | Agent exposed via inbound port gets scanned/attacked | SLIM outbound-only (P3) |

## 5. Phase mapping to AGNTCY / Outshift components

| Phase | Component | Repo |
|---|---|---|
| P2 | Identity Service, badges, `identity-cli` | agntcy/identity |
| P3 | SLIM node + Python bindings, MLS sessions | agntcy/slim |
| P4 | TBAC, CASA deterministic + semantic checks, ASTRA dataset | outshift-open/outshift-casa, outshift-open/ASTRA |
| P6 | Benchmarking, observability | outshift-open/mas-lab, insight module |

## 6. Open design questions (decide as you go)

- Semantic checker: embeddings only (fast) vs LLM verifier (accurate)? Measure on ASTRA.
- Run on plain Python processes first, or go straight to Kubernetes so CASA sidecars
  can be compared against the in-process gate?
- Badge revocation: poll the Identity Service vs cache with short TTL?
