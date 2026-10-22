# P4 design — semantic intent check, evaluated before trusted (DRAFT for owner sign-off)

Goal (CLAUDE.md P4): replace the keyword relevance test in `authz/intent.py` with a real
semantic check, and **measure it on ASTRA (plus our own netops cases) before the gate
relies on it**.

TrustSec analogy: identity (badge), key possession (peer) and SGT (TBAC) are all fine —
the device is who it says and its group may use this port. **Posture** decides whether
*this* action fits *this* session. P4 is the posture assessment: "does `push_config` on
`core-rtr-02` fit the request *audit the ACLs on edge-fw-01*?"

Why it matters now: P3 closed identity attacks. The remaining agent threat is a **genuine,
correctly-badged agent that has been steered** (prompt injection, poisoned tool output) to
call an allowed tool for the wrong purpose (T5, T6). Only the intent layer sees that.

## 1. Today

`BaselineIntentChecker`:
1. **change gate** — a `change: true` tool needs session intent `change` (rule 4) — keep as is
2. **relevance** — user prompt must share ≥1 word with the tool's `keywords` in `tbac.yaml`

Step 2 is weak both ways: "audit **acl** on edge-fw-01" passes `push_config` (its keywords
include `acl`), and a correct request phrased without listed keywords is blocked. It also
ignores **arguments** — T6 (allowed tool, unrelated device) is not checked at all.

## 2. Verified facts (2026-10-22)

**ASTRA** (`github.com/outshift-open/ASTRA`, Apache-2.0, last push 2025-10-31; paper
arXiv:2510.26702, El Helou et al., Cisco Outshift):
* Record schema (checked on `data/01_tool/ASTRA/test.json`; the `eval/astra_eval.py` stub
  guessed differently): `{"input": {"task", "tools": [...], "mcp_servers": [...]},
  "groundtruth": {"tools", "mcp_servers"}, "match_tag": "correct"|"wrong"|"null"}`.
  Tool descriptions live in `data/mcp_servers/ASTRA/<server>.json` (`name`, `tools[]` with
  `name`, `description`, `inputSchema`, …).
* Test split, per N ∈ {1, 3} tools: **947 tasks = 474 correct / 379 wrong / 94 null**, 4 servers,
  median task ~30–35 words. *wrong* = another tool on the **same** server (the hard case);
  *null* = a tool from a **different** server.
* Paper baselines, N=1 test (positive class = "correct match"):

  | Matcher | Model | Accuracy | Precision | Recall |
  |---|---|---|---|---|
  | SemSimM (embedding similarity, threshold tuned on validation) | OpenAI text-embedding-3-large | 0.77 | 0.99 | 0.55 |
  | LLM-ResM (LLM judges task vs tool name + description) | GPT-4o, temperature 0 | 0.96 | 0.93 | 0.99 |

  LLM-ResM at N=3: accuracy 0.72, recall 0.57. No per-class (wrong vs null) breakdown.
* Security reading: SemSimM rarely allows a bad call but **blocks ~45% of good ones**;
  LLM-ResM keeps good calls but **~7% of what it allows is a wrong/null match**.

**Claude API** (claude-api skill, cached 2026-10-06): `temperature`/`top_p`/`top_k` are
rejected (400) on every model as of 2026-10-21 → determinism can't be forced; it must be
**measured**. Structured output via `output_config.format` / `client.messages.parse()`;
refusals arrive as `stop_reason: "refusal"`; SDK retries 408/409/429/5xx (default 2) and
takes a per-request timeout. Candidate models: `claude-opus-5-5` ($4/$20 per MTok;
thinking always on, effort `low` available) and `claude-haiku-5-5` ($0.10/$0.50; effort
`low`). Latency is **not** documented for our shape — to be measured.

## 3. Design — the `intent` check becomes three ordered sub-checks

Each sub-result is recorded in the audit record's `intent` reason (rule 3); any FAIL or
error → BLOCK (rule 1).

1. **change gate** (deterministic, unchanged).
2. **scope** (deterministic, NEW — closes T6): every *entity* argument (`device`, `ip`) must
   be named in the sealed user prompt. `show_running_config(device="core-rtr-02")` during
   "audit edge-fw-01" → FAIL. Entity args are declared per tool in `tbac.yaml`
   (`scoped_args: [device]`), deny-by-default if a tool declares none and has args? → **D5**.
3. **semantic** (pluggable `SemanticMatcher`, NEW): does the requested tool fit the task?
   * `EmbeddingMatcher` — local, offline (SemSimM-style): cosine(task, tool description).
   * `LlmMatcher` — Claude (LLM-ResM-style): task + requested tool name/description
     (+ optionally the other tools on that server, so it can see a better fit) → strict JSON
     `{"verdict": "allow"|"deny", "better_tool": str|null, "reason": str}`.
   * `CascadeMatcher` — embedding as a cheap **deny-only** prefilter (clearly unrelated →
     BLOCK without an LLM call), everything else → LLM.

**Hardening built in:**
* The LLM sees the **sealed session prompt** and **our** tool descriptions from
  `tbac.yaml` — never tool arguments or results (injection surface), never the MCP
  server's self-advertised descriptions (could be poisoned).
* Fail closed: timeout, API/network error, refusal, `max_tokens`, unparseable or
  schema-invalid JSON, unknown verdict → ERROR → BLOCK. No retry beyond the SDK's.
* Cache verdicts per (session_id, tool) for the session — one LLM call per tool per
  session, not per call (args are covered by the deterministic scope check).
* API key from env only (`ANTHROPIC_API_KEY`; rule 5). Prompts leave the machine → lab data only.

## 4. Evaluation — before anything is trusted

`eval/astra_eval.py` (fix the loader to the real schema) + `eval/netops_cases.yaml` (new,
~60 hand-labelled cases on *our* 6 tools: correct, same-server near-misses like
`show_running_config` for an ACL audit, other-domain, and injection-flavoured tasks).

Report per matcher: **false-allow rate on wrong and on null separately** (security first),
false-block rate on correct, p50/p95 latency, cost per 1k checks, and **run-to-run
agreement** (3 runs on a 100-case subset — no temperature control). Tune thresholds/prompt on
ASTRA **validation**; report **test** once. N=1 and N=3 (multi-tool = one check per tool).

Proposed acceptance gate to make a matcher the gate default (**D4**): netops near-miss
false-allow = 0; ASTRA N=1 wrong+null false-allow ≤ 5%; correct false-block ≤ 10%;
p95 added latency ≤ 1.5 s (session cache makes it once per tool per session).

Cost (estimates, confirmed by a 20-case pilot before any full run): ~2–4k input +
≤0.5k output tokens per ASTRA case → Opus 5.5 ≈ $0.01–0.03/case (~$20–60 per full
validation+test pass), Haiku 5.5 ≈ 40× less (<$1). Embedding matcher: free (local).

## 5. Work order (one PR each)

* **P4a** eval harness: real ASTRA loader, `netops_cases.yaml`, metrics/report; **baseline
  numbers for today's keyword checker** (free, no API).
* **P4b** scope check (deterministic args) + `scoped_args` in `tbac.yaml` + tests.
* **P4c** `EmbeddingMatcher` (local model, pinned) + eval numbers.
* **P4d** `LlmMatcher` (+ cascade) + eval numbers — **paid runs only after you approve the budget**.
* **P4e** wire the winner into the gate behind a policy setting; keep `BaselineIntentChecker`
  for offline dev; README/ARCHITECTURE update.

## 6. Decisions for the owner

* **D1 Model:** evaluate **both** `claude-opus-5-5` (effort `low`; the default) and
  `claude-haiku-5-5` (effort `low`; ~40× cheaper, likely faster) on validation, then pick the
  cheapest that meets D4 (**recommended**) — or name one now.
* **D2 Architecture:** cascade embedding→LLM (**recommended**: cheap deny of obvious
  mismatches, LLM for near-misses) vs LLM-only vs embedding-only (offline, low recall).
* **D3 Outage:** LLM unreachable → BLOCK (**recommended**, rule 1 "errors = BLOCK") vs fall
  back to the embedding matcher (keeps working, weaker check).
* **D4 Acceptance gate:** the numbers in §4, or yours.
* **D5 Scope check strictness:** a tool with entity args but no `scoped_args` declared →
  BLOCK (**recommended**, deny by default) vs skip.
* **D6 Spend:** OK to spend up to ~$5 on pilots + Haiku runs and up to ~$60 on Opus runs
  (each run confirmed with a measured estimate first)? P4a–P4c cost nothing.
