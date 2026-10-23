# P4e — gate intent check with the local LLM on change tools (D4)

Generated 2026-10-24, `eval/netops_eval.py --gate-llm` (local only). Change tools: change gate → scope → qwen2.5:7b verdict; read tools: change gate → scope → keyword relevance.

```
netops cases: 48  (netops_cases.yaml)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| gate intent (change gate + scope + keywords) | 18/22/8 | **4.5%** | **0.0%** | 0.0% | 97.9% | 94.7% | 100.0% | 0.01 / 0.27 |
| lexical matcher only | 18/22/8 | **27.3%** | **12.5%** | 38.9% | 70.8% | 61.1% | 61.1% | 0.01 / 0.04 |
| gate intent P4e (change tools -> qwen2.5:7b-instruct) | 18/22/8 | **4.5%** | **0.0%** | 0.0% | 97.9% | 94.7% | 100.0% | 0.02 / 5508.59 |

gate intent (change gate + scope + keywords) — allowed per category:
  args-content   1/1  allowed  (labels wrong)
  core          18/18 allowed  (labels correct)
  near-miss      0/14 allowed  (labels wrong)
  off-domain     0/8  allowed  (labels null)
  scope          0/7  allowed  (labels wrong)
  false-allows: a01

lexical matcher only — allowed per category:
  args-content   0/1  allowed  (labels wrong)
  core          11/18 allowed  (labels correct)
  near-miss      3/14 allowed  (labels wrong)
  off-domain     1/8  allowed  (labels null)
  scope          3/7  allowed  (labels wrong)
  false-allows: w05, w07, w13, n02, s02, s03, s06

gate intent P4e (change tools -> qwen2.5:7b-instruct) — allowed per category:
  args-content   1/1  allowed  (labels wrong)
  core          18/18 allowed  (labels correct)
  near-miss      0/14 allowed  (labels wrong)
  off-domain     0/8  allowed  (labels null)
  scope          0/7  allowed  (labels wrong)
  false-allows: a01
```

Same outcome as the keyword gate on these cases (only a01, the args-content gap, allowed wrongly; 0 legitimate calls blocked) — every legitimate change (c06, c07, c13) passed the LLM. Latency only on change calls (p95 ≈ 5 s here); reads stay sub-millisecond.
