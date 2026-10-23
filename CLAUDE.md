# CLAUDE.md — AgentTrustSec

You are helping build **AgentTrustSec**: a zero-trust multi-agent network-operations
system secured end-to-end with the Cisco Outshift **AGNTCY** stack
(Identity badges, SLIM transport, TBAC + intent-scoped authorization, observability).

The owner is a network security engineer (Cisco ISE / TrustSec, Palo Alto, FTD).
Explain design choices using the TrustSec analogy below — it is the project's mental model.

## Mental model: TrustSec ↔ AGNTCY

| TrustSec / ISE concept          | AgentTrustSec equivalent                                  |
|---------------------------------|-----------------------------------------------------------|
| 802.1X identity + machine cert  | Agent Badge (Verifiable Credential, JSON-LD, JOSE-signed) |
| ISE as policy server            | Identity Service + `authz/` policy engine                 |
| SGT (Security Group Tag)        | Agent role (`intake`, `reader`, `reviewer`, `executor`)   |
| SGACL matrix                    | `policies/tbac.yaml` (role → allowed tools)               |
| Posture / context               | User intent (`read` vs `change`) bound to the session     |
| MACsec / encrypted fabric       | SLIM sessions with MLS end-to-end encryption              |
| Enforcement point (switch)      | `authz/gate.py` (later: CASA-style sidecar)               |
| ISE Live Logs                   | `audit/decisions.jsonl` + dashboard                       |
| Switch authenticating to ISE    | MCP server badge verified by the agent (mutual auth)      |
| Per-session dACL / authz profile| Broker-minted, single-use token scoped to tool + audience |

## Non-negotiable rules

1. **Deny by default.** Anything not explicitly allowed is BLOCK. Never add a wildcard
   allow, a "dev bypass", or a fallback-to-allow on error. Errors in any check = BLOCK.
2. **Never weaken a security check to make a test pass.** If a test fails, fix the code or
   ask the owner. Loosening policy, skipping verification, or catching-and-ignoring
   verification exceptions is forbidden.
3. **Every decision is audited.** Each tool call produces exactly one audit record with
   agent id, badge status, tool, intent, every check result, and final decision.
4. **Change tools are special.** Any tool tagged `change: true` requires ALL of:
   valid badge, role allowed by TBAC, session intent == `change`, and semantic check pass.
5. **No secrets in the repo.** API keys come from env vars (`.env` is git-ignored).
   Use `.env.example` for names only.
6. **Lab only.** Network tools hit mocks or a lab (CML / containerlab / DevNet sandbox),
   never production devices.
7. **Verify AGNTCY APIs before using them.** The AGNTCY SDKs move fast. Before writing
   code against `identityservice-sdk`, `slim-bindings`, or CASA, read the current docs /
   source and confirm signatures. Keep vendor calls behind the adapter interfaces in
   `identity/` and `transport/` so they can be swapped.

## Repo layout

```
src/agenttrustsec/
  models.py            # Decision, CheckResult, ToolCall, Session dataclasses
  identity/badge.py    # BadgeVerifier interface + LocalDevVerifier (dev HMAC)
  identity/agntcy.py   # AgntcyBadgeVerifier (agntcy-identity-sdk 0.0.26, Identity Node)
  identity/keys.py     # RFC 7638 thumbprints of the agent keys badges bind (P3)
  authz/tbac.py        # Deterministic role→tool policy engine (deny by default)
  authz/intent.py      # Semantic intent checker (baseline now, embeddings/LLM later)
  authz/gate.py        # Combines badge + [peer] + TBAC + intent → ALLOW/BLOCK, writes audit
  authz/peer.py        # P3: transport identity must hold the key the badge binds
  authz/broker.py      # Seals sessions at intake; mints scoped single-use access tokens
  mcpgate/server.py    # Gate as MCP (mcp 2.x) server middleware; stamps server badge
  mcpgate/client.py    # Agent-side MCP client: sends creds, verifies server badge
  mcpgate/serve.py     # Gateway runner: SLIM for tool calls (peer check ON); HTTP = issuance only
  audit/log.py         # JSONL audit writer
  tools/netops.py      # Mock network tools (show_*, push_config, ...)
  tools/extdata.py     # Mock external API (threat intel) — accepts brokered tokens only
  agents/              # Agent implementations (phase 5)
  transport/slim.py    # MCP over SLIM (MLS P2P); reports + pins the peer, gate decides
  transport/slim_group.py # Attested MLS group sessions: admission gate before any broadcast
  authz/groups.py      # Group admission: badge -> peer -> group policy (deny by default)
policies/tbac.yaml     # The "SGACL matrix"
policies/groups.yaml   # Who may moderate / join each SLIM group channel
policies/identities.yaml # Verified badge id -> role (ISE authz policy assigning SGT)
policies/trust-jwks.json # PUBLIC keys SLIM may accept (binding enforced by the peer check)
scenarios/             # Attack / demo scenarios (rogue agent etc.)
lab/identity/          # Lab Identity Node compose, OASF records, revoke_badge.py
eval/                  # ASTRA-based evaluation of the intent checker
tests/                 # pytest — must stay green
```

## Build phases (do them in order; one PR-sized step at a time)

- [x] **P0 Scaffold** — models, TBAC engine, gate, audit, mock tools, tests.
- [x] **PA MCP + external data** — MCP gateway middleware, mutual server badges,
      sealed sessions, token broker. Threats T9–T11. (`mcp` SDK is **2.x**: `MCPServer`,
      not FastMCP.)
- [ ] **P1 Learn by running** — run `agntcy/slim` examples and the `outshift-casa`
      Minikube standalone demo. Write findings to `docs/notes-p1.md`.
- [x] **P2 Identity** — `AgntcyBadgeVerifier` done + tested against a fake node
      (`uv pip install -e ".[agntcy]"`). Lab node (`lab/identity/`) running; 3 real agent
      badges issued, ids in `policies/identities.yaml`, live tests in
      `tests/test_agntcy_live.py` (skip if node down). MCP server badge issued from the
      live gateway (`python -m agenttrustsec.mcpgate.serve`). Revocation via
      `lab/identity/revoke_badge.py`; node Verify misses replayed pre-revocation copies,
      so the verifier also checks the node's published copy. Original scope: implement `AgntcyBadgeVerifier` using the AGNTCY Identity
      Python SDK (verify JOSE-enveloped badges). Issue badges for 2 toy A2A agents.
- [x] **P3 Transport** — design `docs/P3-design.md`. PR1 done: per-agent keys,
      badges re-issued with key thumbprint. PR2 done: `transport/slim.py` (MCP over
      MLS SLIM, `[slim]` extra, live tests vs `lab/slim/`). PR3 done: gate `peer` check
      (`authz/peer.py`, badge-bound key proof of possession). PR4 done: gateway + agents on
      SLIM (`serve.py --transport slim`, mutual peer checks, live attack matrix). PR5 design approved
      (§8 attested groups); PR5a done: `intake-01` identity (role intake, moderator). PR5b done:
      attested groups (`transport/slim_group.py`, `authz/groups.py`, `policies/groups.yaml`).
      Move agents onto SLIM: point-to-point first, then a group
      session for the reviewer pool. No agent opens an inbound port.
- [x] **P4 Authorization** — design `docs/P4-design.md` (D1 local Ollama qwen2.5:7b, D2 LLM only, D3 BLOCK). P4a done: eval harness (`eval/harness.py`, `astra_eval.py`,
      `netops_eval.py` + 48 cases), baseline in `eval/results/p4a-baseline.md`. P4b done: scope check
      (`scoped_args` in tbac.yaml, T6; D5 = BLOCK). P4c done: `EmbeddingMatcher` (fastembed,
      `semantic` extra) + `eval/results/p4c-embedding.md` — prefilter does not pay off on netops,
      so D2 revised to an LLM-only check. **No paid APIs in this project — local Ollama only**
      (owner, 2026-10-23): `LlmMatcher` + `ollama_judge` (qwen2.5:7b-instruct pinned by digest,
      temperature 0 + seed, fail closed). P4d done: ASTRA 1.2%/0% wrong/null allowed but
      26% legit blocked; catalog / top-5 prompt variants worse (`eval/results/p4d-*`). P4e done
      (D4 = change tools only): change tools judged by the local LLM, reads keep keywords;
      SLIM gateway refuses to start without Ollama. Verified live: change via real gateway
      judged by the local LLM; full suite 279 passed with lab + Ollama up.
      TBAC from `policies/tbac.yaml` (done locally), then a real
      semantic checker in `authz/intent.py` (embeddings → optional LLM verifier).
      Evaluate it with `eval/astra_eval.py` on ASTRA test splits before trusting it.
- [ ] **P5 Domain** — real agents: intake, reader (pyATS / mock), reviewer (port the
      CrewAI Palo Alto / FTD change reviewer), executor. Add the rogue agent.
- [ ] **P6 Observe & benchmark** — dashboard of ALLOW/BLOCK decisions; latency and
      block-rate numbers (optionally via `outshift-open/mas-lab`); README diagrams.

## Commands

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest -q
python -m agenttrustsec.demo      # runs scenarios/rogue_agent.yaml against the gate
# P3 gateway over SLIM (needs both lab nodes + keys): see docs/P3-design.md §7
python -m agenttrustsec.mcpgate.serve --transport slim --server-id <gateway metadata id>
```

## Reference repos

- https://github.com/orgs/outshift-open/repositories (CASA, ASTRA, mas-lab, insight module)
- https://github.com/agntcy (slim, identity, dir, oasf)
- Docs: https://docs.agntcy.org
