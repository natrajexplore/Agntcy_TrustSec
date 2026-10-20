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
  authz/gate.py        # Combines badge + TBAC + intent → ALLOW/BLOCK, writes audit
  authz/broker.py      # Seals sessions at intake; mints scoped single-use access tokens
  mcpgate/server.py    # Gate as MCP (mcp 2.x) server middleware; stamps server badge
  mcpgate/client.py    # Agent-side MCP client: sends creds, verifies server badge
  mcpgate/serve.py     # Lab HTTP runner (127.0.0.1); fetches + verifies its own badge
  audit/log.py         # JSONL audit writer
  tools/netops.py      # Mock network tools (show_*, push_config, ...)
  tools/extdata.py     # Mock external API (threat intel) — accepts brokered tokens only
  agents/              # Agent implementations (phase 5)
  transport/slim.py    # MCP over SLIM (MLS P2P); reports + pins the peer, gate decides
policies/tbac.yaml     # The "SGACL matrix"
policies/identities.yaml # Verified badge id -> role (ISE authz policy assigning SGT)
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
- [ ] **P3 Transport** — 🟡 design approved (`docs/P3-design.md`). PR1 done: per-agent keys,
      badges re-issued with key thumbprint. PR2 done: `transport/slim.py` (MCP over
      MLS SLIM, `[slim]` extra, live tests vs `lab/slim/`). Next: PR3 gate `peer` check.
      Move agents onto SLIM: point-to-point first, then a group
      session for the reviewer pool. No agent opens an inbound port.
- [ ] **P4 Authorization** — TBAC from `policies/tbac.yaml` (done locally), then a real
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
```

## Reference repos

- https://github.com/orgs/outshift-open/repositories (CASA, ASTRA, mas-lab, insight module)
- https://github.com/agntcy (slim, identity, dir, oasf)
- Docs: https://docs.agntcy.org
