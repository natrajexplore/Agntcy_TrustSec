# AgentTrustSec

**Zero-trust for AI agents, modeled on Cisco TrustSec, built on the AGNTCY stack.**

A multi-agent network-operations system where every agent proves *who it is* (Agent
Badge), proves it *holds the key* behind that identity, talks over an *encrypted fabric*
(SLIM + MLS), and may only call tools that match *its role* (TBAC) **and** *the user's
actual intent*. Anything not explicitly allowed is blocked, and every decision is logged.

> Lab project. Network tools are mocks or lab devices — never production.

---

## Why

AI agents are getting real tool access: they read device configs, review firewall
changes, and push configuration. That turns classic agent failures into network incidents:

* a **prompt-injected or compromised agent** tries a change during a read-only task
* a **stolen credential** is replayed by an impostor agent or a fake tool server
* an **over-privileged agent** calls tools far outside its job
* a **revoked agent** keeps working because nobody re-checks its identity
* an **eavesdropper** reads agent-to-agent traffic or slips into a review group

Network security solved the equivalent problems for users and devices a long time ago.
Cisco TrustSec / ISE does it with 802.1X identity, security-group tags, an SGACL matrix,
posture, MACsec, enforcement at the switch, and Live Logs. **AgentTrustSec applies the
same model to agents**, using the open AGNTCY stack from Cisco Outshift.

## Vision

An engineer asks for a read-only ACL audit. Behind the scenes an intake agent seals that
intent, reader and reviewer agents gather and assess data, and an executor exists for
approved changes only. If any agent goes rogue — or an attacker copies a badge, spoofs a
name, or stands up a fake tool server — the call is **blocked before the tool runs**, and
the audit trail shows exactly which layer stopped it and why.

Design principles (non-negotiable, see `CLAUDE.md`):

1. **Deny by default.** No wildcard allows, no dev bypass; an error in any check = BLOCK.
2. **Never weaken a check to pass a test.**
3. **Every decision is audited** — one record per call, every check result included.
4. **Change tools are special** — valid badge, allowed role, `change` intent, semantic pass.
5. **No secrets in the repo; lab only; verify fast-moving AGNTCY APIs before use.**

## The mental model: TrustSec ↔ AGNTCY

| TrustSec / ISE | AgentTrustSec |
|---|---|
| 802.1X identity + machine cert | **Agent Badge** — W3C Verifiable Credential, JOSE-signed (AGNTCY Identity) |
| EAP-TLS proof of private key | **`peer` check** — the agent's SLIM token must be signed by the key its badge binds |
| ISE as policy server | Identity Node + `authz/` policy engine |
| SGT (security group tag) | Agent role: `intake`, `reader`, `reviewer`, `executor` |
| SGACL matrix | `policies/tbac.yaml` (role → allowed tools) |
| Posture / context | User intent (`read` vs `change`) sealed into the session at intake |
| CRL / OCSP check | Badge must be **published and not revoked** on the Identity Node |
| MACsec / encrypted fabric | **SLIM** sessions with **MLS** end-to-end encryption |
| Enforcement point (switch) | `authz/gate.py`, run as MCP server middleware |
| Switch authenticating to ISE | Agent verifies the MCP gateway's badge **and key** (mutual auth) |
| Per-session dACL | Broker-minted, single-use token scoped to one tool + audience |
| ISE Live Logs | `audit/decisions.jsonl` |

## How a tool call is decided

```
 Engineer ─► Intake (seals intent) ─┬─► Reader   ─┐
                                    ├─► Reviewer ─┼──► MCP gateway ──► show_* / review_change
                                    └─► Executor ─┘    (Gate inside)    push_config (CHANGE)
                 Rogue / impostor ─────────X
 All agent ↔ gateway traffic: SLIM, MLS-encrypted; agents and gateway dial OUT
 (no inbound ports). The SLIM node forwards ciphertext.

 Gate, for every tools/call:
   [1]  badge   AGNTCY badge verifies on the Identity Node, is published + not revoked,
                subject == claimed agent            → verified role + bound key
   [1b] peer    SLIM token sub == SLIM subject == routing name == badge holder,
                and the token verifies with the badge-bound key   (proof of possession)
   [2]  tbac    role allowed for this tool                         (SGACL)
   [3]  intent  target (device/IP) named in the request (scope); change tools need a
                `change` session + a local-LLM verdict; reads need keyword relevance
   ALL pass → ALLOW (+ scoped token for external APIs)   else BLOCK
   → exactly one audit record (peer identity included, tokens never)
```

The agent side mirrors it: a result counts only if the gateway's badge verifies **and**
the gateway proves it holds the key bound to that badge.

## What building it has proven so far

Everything below was tested against live lab nodes (AGNTCY Identity Node 0.0.26,
SLIM 3.4.5 with `slim-bindings` 3.3.6, `mcp` 2.3). Details and reproducible probes are in
`docs/notes-p1.md`, `docs/P3-design.md` and `lab/`.

| Finding | What we did about it |
|---|---|
| AGNTCY badges carry **no role** | Role comes from our own map (`policies/identities.yaml`), never from the agent |
| The Identity Node's `Verify` checks revocation only **inside the presented badge** — a revoked agent replaying its original copy still gets `status=True` | Verifier also requires the badge to be among the node's **published, unrevoked** copies (OCSP-style) |
| AGNTCY badges are **bearer** credentials — no proof of key possession | Each agent has its own key; the issuer signs its thumbprint into the badge; the `peer` check demands a SLIM token signed by that key |
| SLIM shared-secret mode is a **group PSK**: any name is accepted with the secret | JWT identity with a per-agent key instead |
| SLIM JWT mode accepts **a trusted key claiming another name** | `peer` check binds name ↔ key itself |
| SLIM silently **ignores trust keys without `alg`** | Such keys are refused loudly at startup |
| In SLIM **group** sessions, an app registered under a reviewer's name with another trusted key is **admitted and can read** the next broadcast | Admission gate: no broadcast until every member attests (badge + key + group policy); the impostor is removed before the secret goes out |

Live attack matrix against the real gateway process (all stopped as designed):

| Attack | Stopped by |
|---|---|
| Trusted key + someone else's SLIM name + their badge | `peer` — not signed by the badge's key |
| Own key presenting another agent's badge | `peer` — not the badge holder |
| Spoofed token subject | `peer` — identity mismatch |
| Key outside the trust set | SLIM — never reaches the gate |
| Revoked agent | `badge` — revoked |
| Genuine executor pushing config in a read-only session | `intent` |
| Impostor gateway with a copied server badge | agent rejects the result |
| Impostor joins the reviewer group under a reviewer's name | admission `peer` — removed before any broadcast |
| Fake moderator (valid agent, wrong role) invites reviewers | reviewers refuse it before attesting |

## Quick start

Unit tests and the demo need no infrastructure:

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest -q                      # live tests skip themselves when the lab isn't running
python -m agenttrustsec.demo   # runs scenarios/*.yaml against the gate
```

Full lab (Identity Node, SLIM node, real badges, gateway over SLIM):

```bash
uv pip install -e ".[dev,agntcy,slim]"
docker compose -f lab/identity/docker-compose.yml up -d
docker compose -f lab/slim/docker-compose.yml up -d
export AGENTTRUSTSEC_BROKER_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export IDENTITY_NODE_GRPC_SERVER_URL=localhost:4001 IDENTITY_NODE_USE_SSL=0
python -m agenttrustsec.mcpgate.serve --transport slim --server-id <gateway metadata id>
```

Issuing badges and keys for your own lab: runbook in `docs/notes-p1.md` (Identity steps
1–9) and `docs/P3-design.md` §7. Keys live in `~/.agenttrustsec/keys/`, never in the repo.

## Repository layout

```
src/agenttrustsec/
  models.py              Decision, CheckResult, ToolCall, Session, TransportPeer
  identity/badge.py      BadgeVerifier interface + LocalDevVerifier (dev only)
  identity/agntcy.py     AgntcyBadgeVerifier: node verify + published/revoked check + bound key
  identity/keys.py       RFC 7638 key thumbprints, trust JWKs
  authz/tbac.py          role → tool policy (deny by default)
  authz/intent.py        intent checker (baseline now; semantic in P4)
  authz/peer.py          peer check: transport identity must hold the badge-bound key
  authz/gate.py          badge → peer → TBAC → intent → ALLOW/BLOCK + audit
  authz/broker.py        sealed sessions; single-use scoped tokens
  mcpgate/               gate as MCP middleware, agent-side client, gateway runner
  transport/slim.py      MCP over SLIM (MLS P2P); reports and pins the peer
  transport/slim_group.py  attested MLS group sessions (reviewer pool)
  authz/groups.py        group admission: badge → peer → group policy
  audit/log.py           JSONL audit writer
  tools/                 mock network tools and a mock external API
policies/                tbac.yaml, identities.yaml, groups.yaml, trust-jwks.json (public keys)
lab/                     Identity Node + SLIM compose files, key/revoke tools, probes
scenarios/  eval/        attack/demo scenarios; ASTRA-based intent evaluation (P4)
docs/                    ARCHITECTURE (threat model), notes-p1 (runbooks), P3-design
tests/                   unit tests + live tests against the lab
```

## Roadmap

| Phase | What | State |
|---|---|---|
| P0 | Gate, TBAC, audit, mock tools, tests | ✅ |
| PA | MCP gateway, mutual server badges, token broker for external data | ✅ |
| P1 | Learn by running SLIM, Identity, CASA | 🟡 SLIM + Identity done; CASA pending (needs Minikube) |
| P2 | Real AGNTCY badges: issue, verify, revoke | ✅ incl. the revocation-replay fix |
| P3 | SLIM transport with key-bound identity | ✅ keys, adapter, peer check, gateway on SLIM, attested reviewer groups |
| P4 | Intent: scope check + local LLM verifier for change tools, evaluated on ASTRA | ✅ (live gateway re-test pending) |
| P5 | Real agents: intake, reader (pyATS/mock), Palo Alto / FTD change reviewer, executor, rogue | ⏳ |
| P6 | Live decisions dashboard, latency and block-rate benchmarks, node admission control | ⏳ |

## Built on

* [AGNTCY](https://github.com/agntcy) — Identity (badges, Identity Node), SLIM (transport, MLS)
* [Outshift open source](https://github.com/orgs/outshift-open/repositories) — CASA, ASTRA, mas-lab
* [Model Context Protocol](https://modelcontextprotocol.io) Python SDK 2.x
* Docs: <https://docs.agntcy.org>

AGNTCY SDKs move fast; versions are pinned exactly in `pyproject.toml` and `lab/`.

## License

MIT — see `LICENSE`.
