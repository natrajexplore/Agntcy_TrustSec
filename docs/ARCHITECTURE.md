# AgentTrustSec — Architecture & Threat Model

## 1. Goals

1. Every agent and MCP server has a verifiable identity (AGNTCY Agent / MCP Server Badge).
2. Agent-to-agent traffic is end-to-end encrypted and needs no inbound ports (SLIM + MLS).
3. Tool access is least-privilege by role (TBAC) **and** scoped to the user's intent.
4. Every decision is explainable after the fact.
5. Agents and MCP servers authenticate **mutually**: the server proves its identity back.
6. No agent or MCP server holds a standing secret for external data; access is via
   short-lived, single-use tokens scoped to one tool + audience + session.

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
ToolCall(agent_id, badge, tool, args, session, peer)
  │
  ├─[1] Badge check    : signature valid, not expired, not revoked, subject == agent_id
  │                      → yields verified role + the key the badge binds
  ├─[1b] Peer check    : (SLIM deployments, mandatory) transport token sub == SLIM subject
  │                      == routing name == badge holder's SLIM name, AND the token
  │                      verifies with the badge-bound key (proof of possession)
  ├─[2] TBAC check     : verified role ∈ policy[tool].allowed_roles     (deterministic)
  ├─[3] Intent check   : if tool.change → session.intent must be "change"
  │                      semantic score(user_prompt, tool) ≥ threshold
  │
  └─ Decision = ALLOW only if every check PASSES; any FAIL or ERROR → BLOCK
     → one audit record per call
```

Role is taken **only from the verified badge**, never from the caller's claim.

## 3a. MCP enforcement point + external data (`mcpgate/`, `authz/broker.py`)

```
 Intake ──seal_session()──► sealed session token (intent + prompt, signed)
   │
 Agent ── TrustedClient ── tools/call  _meta{agent_id, badge, session} ──►  MCP server
   ▲                                                                   │ GateMiddleware
   │                                                [0] session token valid? (T11)
   │                                                [1-3] Gate: badge → TBAC → intent
   │                                                ALLOW + tool has `audience`:
   │                                                   broker.mint(agent, tool, sid, aud)
   │                                                   tool → External API.redeem(token)
   └── result _meta{server_badge} ◄── agent verifies server badge (T9) before using result
```

* Only `initialize`, `server/discover`, `ping`, `tools/list`, `tools/call` are served;
  every other MCP method is refused (deny by default).
* Access tokens: TTL 60 s, single use, bound to `aud` + `tool` + `sub` + `sid`.
* TrustSec analogy: ISE pushing a per-session authorization profile instead of a
  shared static key on every switch.

## 4. Threat model (what each layer stops)

| # | Attack | Stopped by |
|---|---|---|
| T1 | Unknown agent calls a tool | [1] badge missing → BLOCK |
| T2 | Forged / tampered badge | [1] signature fail → BLOCK |
| T3 | Revoked agent (old version) keeps acting | [1] revocation → BLOCK: node Verify + VC id must be in the node's published copies and not revoked (node alone misses a replayed pre-revocation copy) |
| T4 | Reader agent tries `push_config` | [2] TBAC → BLOCK |
| T5 | Legit executor pushes config during a read-only audit (prompt injection) | [3] intent → BLOCK |
| T6 | Allowed tool but irrelevant to request (data exfil via `show_running_config` on unrelated device) | [3] semantic → BLOCK (P4) |
| T7 | Eavesdrop / tamper on agent traffic | SLIM MLS (P3) |
| T8 | Agent exposed via inbound port gets scanned/attacked | SLIM outbound-only (P3) |
| T9 | Fake / impostor MCP server feeds poisoned results | client verifies server badge (`mcpgate/client.py`) |
| T10 | Leaked or replayed external-data token | broker: TTL + single-use + aud/tool scope |
| T11 | Agent self-upgrades session intent `read` → `change` over the wire | intake-sealed session token |

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
- Badge revocation: we now query the node's published copies on EVERY verification
  (one extra gRPC call). Cache with a short TTL? That reopens a revocation window = TTL.
- **Known gap (bearer badges):** the MCP server badge is a bearer credential, so a copied
  badge could be replayed by an impostor. Confirmed in P2 that AGNTCY badges don't close
  this: the Identity Node verifies issuer signature + revocation, not key possession.
  Proof of possession has to come from the transport (P3: SLIM/MLS sessions).
- The MCPServerBadge signs the server's tool inventory (`identity badge issue mcp`
  discovers it). Should the client compare live `tools/list` to the badge (drift check)?
- Should `tools/list` be filtered per verified role (hide tools an agent can't call)?
- AGNTCY badges without `expiration_date` are currently accepted (lifecycle via node
  revocation). Require expiry instead? Decide after seeing real badges.
