# P4b — scope check (T6) on the netops cases

Generated 2026-10-23 with `eval/netops_eval.py` (local, no API). ASTRA is unaffected: its records carry no tool arguments.
Compare with `p4a-baseline.md`: scope cases allowed 6/7 → **0/7**, wrong-call false-allow 31.8% → **4.5%** (only the known args-content gap, a01), no correct call newly blocked.

```
netops cases: 48  (netops_cases.yaml)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| gate intent (change gate + scope + keywords) | 18/22/8 | **4.5%** | **0.0%** | 0.0% | 97.9% | 94.7% | 100.0% | 0.01 / 0.22 |
| lexical matcher only | 18/22/8 | **27.3%** | **12.5%** | 38.9% | 70.8% | 61.1% | 61.1% | 0.01 / 0.02 |

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
```
