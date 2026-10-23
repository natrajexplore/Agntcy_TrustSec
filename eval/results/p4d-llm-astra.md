# P4d — local LLM verifier on ASTRA (Ollama, qwen2.5:7b-instruct, pinned)

Generated 2026-10-24, `eval/astra_eval.py --matcher llm --split test --tools 01_tool --limit 200` (stratified, local only, temperature 0 + seed 7).
The planned 50-task 03_tools half was **stopped by Claude Code for low system memory** (Ollama held 6.9 GB of 15.5 GB RAM) and has no result yet.

```
ASTRA @ ee05b9b  split=test  matcher=llm

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| llm · 01_tool (n=200) | 100/80/20 | **1.2%** | **0.0%** | 26.0% | 86.5% | 98.7% | 74.0% | 9257.05 / 17345.13 |

Local model usage: 200 calls, 56239 in / 9017 out tokens (no API, no cost)

```

## Reading (vs paper LLM-ResM, GPT-4o, ASTRA test N=1: acc 0.96 / precision 0.93 / recall 0.99)

* Security side excellent: wrong (same-server near-miss) false-allow **1.2%**, null **0.0%**; precision **98.7%** (paper 93%).
* Usability side weak: false-block on correct **26.0%** (recall 74%; paper 99%). Over-blocks — the safe direction, but above the provisional D4 bar (≤10%).
* Latency on this laptop: 9.3 s p50 / 17.3 s p95 per check.
