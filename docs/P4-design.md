# P4 design — semantic intent check, evaluated before trusted

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

## 4b. Baseline (P4a, 2026-10-23) — `eval/results/p4a-baseline.md`

ASTRA pinned at `ee05b9b`, cloned into `eval/.astra/` (git-ignored). ASTRA tools have no
keyword lists, so today's check is approximated by a lexical matcher (task words ∩ tool
name + description).

| Today's check | false-allow wrong | false-allow null | false-block correct |
|---|---|---|---|
| ASTRA test, 1 tool (lexical) | **34.8%** | **30.9%** | 21.5% |
| ASTRA test, 3 tools (lexical) | 14.5% | 3.2% | **58.2%** |
| netops, real `BaselineIntentChecker` | 31.8% (all of it scope + args-content) | 0.0% | 0.0% |

* On an unbiased benchmark, today's relevance test lets **about a third of mismatched tool
  calls through** and still blocks a fifth of good ones.
* On our netops set the keyword check looks good on near-miss / off-domain (0/14, 0/8
  allowed) — but its `tbac.yaml` keywords and these tasks were written by the same author,
  so that is flattering. Its real gaps there: **6/7 scope cases allowed** (right tool,
  device/IP never named — T6) and the args-content case. P4b targets scope.

## 4c. P4b scope check — as built (2026-10-23), `eval/results/p4b-scope.md`

`tbac.yaml` `scoped_args` per tool (`[device]` / `[ip]`; `[]` = no targets; undeclared =
BLOCK, **D5 = BLOCK, confirmed by owner**). The intent check is now change gate → scope →
relevance; a scoped value must appear in the sealed request as a whole token
(`10.0.0.1` ≠ `10.0.0.10`, `edge-fw-01` ≠ `edge-fw-010`). Netops: scope cases allowed
6/7 → **0/7**, wrong-call false-allow 31.8% → **4.5%** (only a01, the args-content gap), no
correct call blocked. `test_mcp` request now names the IP it looks up; the unnamed-IP
variant is a new test that must BLOCK.

## 4d. P4c local embedding matcher — results (2026-10-23), `eval/results/p4c-embedding.md`

`fastembed==0.9.0` (`semantic` extra, ONNX, no torch), models cached under
`~/.cache/agenttrustsec/fastembed`. `EmbeddingMatcher` modes absolute / margin / rank / combo;
thresholds tuned on ASTRA validation, reported on test. bge-small: ~7.5 ms p50, ~15 ms p95
per call on CPU.

* **Standalone it is not a gate** (confirms the paper's SemSimM): best combo ≈ 77% accuracy
  on ASTRA test N=1 but ~19% wrong / 10–22% null false-allow and ~25% false-block.
* **As the cascade prefilter** (its deny is final):
  * combo/margin (bge-small): ASTRA test denies 32% wrong / 10% null at 1.7% false-block —
    but **netops false-block 11.1%**: c06/c07, legitimate `push_config` change requests,
    because `review_change`/`show_acl` (same ACL topic) outrank `push_config`. The margin
    rule assumes the right tool is clearly the best match; related-tool clusters break it.
  * absolute only: safe (ASTRA 0.2%, netops 0% false-block) but denies little (ASTRA ~5%
    wrong / 17% null; netops 1/8 off-domain).
* bge-base catches more but its validation threshold over-blocked on test (2.7–4%); the bge
  query prefix did not help.
* Not done on purpose: rewording `push_config`'s description until c06/c07 pass would tune
  policy to our own test cases (needs a held-out set first).

**→ D2 revisited 2026-10-23 — owner decision: Claude only.** The embedding prefilter is dropped from
the gate; `EmbeddingMatcher` and these results stay in the repo as evidence (and as a possible
future option once a held-out netops set exists).

## 4e. P4d — local LLM verifier (Ollama only, owner decision 2026-10-23)

**D1 revised: no paid API in this project.** The Claude adapter, the `anthropic` dependency and
`ANTHROPIC_API_KEY` were removed before any call was made ($0 spent). `LlmMatcher` is
provider-neutral; its judge is now `ollama_judge` (stdlib HTTP to `127.0.0.1:11434`, no new
dependency):
* model **`qwen2.5:7b-instruct`, pinned by digest** `845dbda0…697e` — the adapter refuses to
  start if the local model under that name changed or is missing;
* Ollama structured output: `format` = the strict verdict schema `{verdict: allow|deny, reason}`;
  `temperature 0` + fixed `seed` → reproducible (the hosted API no longer allows this);
* fail closed: finish reason other than `stop` (e.g. `length`), bad JSON, unknown verdict →
  deny; connection errors / timeouts (120 s) propagate → gate ERROR → BLOCK (D3);
* prompt = sealed task + our tool name/description as JSON data (optional `with_catalog`).

Probe on this laptop (Core Ultra 5 125H, 15.5 GB, Intel Arc iGPU): qwen2.5:7b ~6.5 s per
verdict warm (19 s cold load); `nemotron-3-nano:4b` 24–27 s and verbose → not used. Both
followed the schema and judged the 3 probe cases correctly. **The provisional D4 latency bar
(p95 ≤ 1.5 s) is not reachable locally** — the per-session verdict cache makes it a one-time
cost per tool per session; owner decides at P4e.

## 4f. P4d results — ASTRA + prompt variants (2026-10-24)

`eval/results/p4d-llm-astra.md`, `eval/results/p4d-llm-variants.md`.
* **Plain prompt, ASTRA test, 200 stratified single-tool tasks:** wrong false-allow **1.2%**, null
  **0.0%**, precision 98.7% (paper GPT-4o LLM-ResM: 93%) — but **false-block 26.0%** (paper ~1%);
  9.3 s p50 / 17.3 s p95 per check. The 3-tool half was stopped by low memory (not run).
* **Full catalog in the prompt:** ~111 s/check here (~4k-token prompts) — impractical.
* **Top-5 similar tools in the prompt:** on 20 paired legitimate tasks it blocks **75%** vs the
  plain prompt's **40%**, rescues none, and is 2× slower — dropped.
* Robustness added on the way: explicit `num_ctx` + "truncated" → deny, `keep_alive` 2 m,
  resumable eval (`--checkpoint`/`--batch`), `--label`/`--max-cases` for paired tests.

**Open for P4e:** the plain prompt's over-blocking (26% on ASTRA, 1/18 on netops) vs the
provisional D4 bar (false-block ≤ 10%, p95 ≤ 1.5 s — latency also unreachable locally).

## 4g. P4e — wired into the gate (2026-10-24), `eval/results/p4e-gate.md`

**D4 = change tools only (owner).** `BaselineIntentChecker(semantic)`: change gate → scope →
for `change: true` tools the local LLM verdict (rule 4's semantic check); read tools keep the
keyword relevance check (no LLM latency, no LLM over-blocking on reads). A matcher error
propagates → gate ERROR → BLOCK. `serve.py --transport slim` builds `LlmMatcher(ollama_judge())`
at startup and **refuses to start** if Ollama is down or the pinned model changed — no fallback
to keywords. Keyword-only mode remains for unit tests and the offline demo.
Netops: same as the keyword gate (only a01 wrongly allowed, 0 legitimate blocked); every
legitimate change passed the LLM; latency only on change calls (p95 ≈ 5 s here).
**Not yet verified live:** the SLIM gateway tests (lab containers were stopped; Docker +
gateway + Ollama's ~7 GB may hit the laptop's memory limit).

## 5. Work order (one PR each)

* **P4a** ✅ eval harness: real ASTRA loader, `netops_cases.yaml`, metrics/report; **baseline
  numbers for today's keyword checker** (free, no API).
* **P4b** ✅ scope check (deterministic args) + `scoped_args` in `tbac.yaml` + tests.
* **P4c** ✅ `EmbeddingMatcher` (local model, pinned) + eval numbers — D2 → Claude only.
* **P4d** ✅ `LlmMatcher` on local Ollama (pinned qwen2.5:7b) + local eval runs — **paid runs only after you approve the budget**.
* **P4e** ✅ wire the winner into the gate behind a policy setting; keep `BaselineIntentChecker`
  for offline dev; README/ARCHITECTURE update.

## 6. Decisions

**Owner decisions (2026-10-23):** D1 = `claude-opus-5-5`, **revised the same day to local Ollama only
(`qwen2.5:7b-instruct`, no paid API — §4e)**; D2 = cascade, **revised after P4c to Claude
only** (§4d); D3 = **BLOCK** when Claude is unreachable;
D6 = moot (no paid runs; local evals cost time, not money). D5 = **BLOCK** (confirmed 2026-10-23). D4 still provisional — raised again at P4e.

Options as proposed:

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
