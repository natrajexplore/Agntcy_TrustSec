# AgentTrustSec

**Zero-trust for AI agents, modeled on Cisco TrustSec, built on the AGNTCY stack.**

A multi-agent network-operations system where every agent proves *who it is*
(Agent Badge), talks over an *encrypted fabric* (SLIM + MLS), and may only call
tools that match *its role* (TBAC) **and** *the user's actual intent* (semantic check).

## The demo in one sentence

An engineer asks for a **read-only ACL audit**. A compromised agent tries to
`push_config` mid-session. AgentTrustSec blocks it before the tool runs, and the
audit trail shows exactly which layer stopped it.

## Architecture

```
 Engineer ──► Intake agent ──┬──► Reader agent ─────► show_* tools (read)
                             ├──► Reviewer agent ───► review_change (read)
                             └──► Executor agent ───► push_config (CHANGE)
                                      ▲
                 Rogue agent ─────────┘   (blocked)

 Every arrow passes through the Gate:
   [1] Badge valid?      → identity/badge.py   (≈ 802.1X + cert)
   [2] Role allows tool? → authz/tbac.py       (≈ SGACL)
   [3] Intent matches?   → authz/intent.py     (≈ posture/context)
   ALL pass → ALLOW, else BLOCK  → audit/decisions.jsonl (≈ Live Logs)
 Transport between agents: SLIM sessions, MLS end-to-end encrypted (≈ MACsec)
```

## Quick start

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest -q
python -m agenttrustsec.demo
```

## Status

| Phase | What | State |
|---|---|---|
| P0 | Scaffold: gate, TBAC, audit, mock tools, tests | ✅ |
| P1 | Run SLIM + CASA demos, take notes | ⏳ |
| P2 | Real AGNTCY badge issue/verify | ⏳ |
| P3 | SLIM transport | ⏳ |
| P4 | Semantic intent checker + ASTRA eval | ⏳ |
| P5 | Real agents incl. firewall change reviewer + rogue | ⏳ |
| P6 | Dashboard + benchmarks | ⏳ |

See `docs/ARCHITECTURE.md` for the threat model and design.
