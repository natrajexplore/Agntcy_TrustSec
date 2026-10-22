# P4a baseline — today's intent check, before any semantic matcher

Generated 2026-10-23 with `eval/astra_eval.py` and `eval/netops_eval.py` (no API calls, local only).
Security metrics first: **false-allow** = a wrong/null tool call the check would let through.

## ASTRA test split (lexical stand-in for the keyword check; ASTRA tools carry no keyword lists)

```
ASTRA @ ee05b9b  split=test  matcher=lexical

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| lexical · 01_tool | 474/379/94 | **34.8%** | **30.9%** | 21.5% | 72.2% | 69.8% | 78.5% | 0.02 / 0.03 |
| lexical · 02_tools | 465/372/93 | **24.2%** | **10.8%** | 31.2% | 73.7% | 76.2% | 68.8% | 0.02 / 0.04 |
| lexical · 03_tools | 474/379/94 | **14.5%** | **3.2%** | 58.2% | 64.7% | 77.3% | 41.8% | 0.01 / 0.03 |
```

## ASTRA validation split (used for tuning later; reported for completeness)

```
ASTRA @ ee05b9b  split=validation  matcher=lexical

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| lexical · 01_tool | 582/465/116 | **44.9%** | **19.8%** | 21.3% | 69.4% | 66.4% | 78.7% | 0.02 / 0.04 |
| lexical · 02_tools | 579/463/115 | **40.0%** | **13.9%** | 25.4% | 69.9% | 68.2% | 74.6% | 0.02 / 0.04 |
| lexical · 03_tools | 579/463/115 | **21.0%** | **4.3%** | 52.0% | 65.2% | 73.2% | 48.0% | 0.02 / 0.04 |
```

## Netops cases (eval/netops_cases.yaml, 48 hand-labelled)

```
netops cases: 48  (netops_cases.yaml)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| gate intent today (change gate + keywords) | 18/22/8 | **31.8%** | **0.0%** | 0.0% | 85.4% | 72.0% | 100.0% | 0.01 / 0.02 |
| lexical matcher only | 18/22/8 | **27.3%** | **12.5%** | 38.9% | 70.8% | 61.1% | 61.1% | 0.01 / 0.02 |

gate intent today (change gate + keywords) — allowed per category:
  args-content   1/1  allowed  (labels wrong)
  core          18/18 allowed  (labels correct)
  near-miss      0/14 allowed  (labels wrong)
  off-domain     0/8  allowed  (labels null)
  scope          6/7  allowed  (labels wrong)
  false-allows: s01, s02, s03, s04, s05, s06, a01

lexical matcher only — allowed per category:
  args-content   0/1  allowed  (labels wrong)
  core          11/18 allowed  (labels correct)
  near-miss      3/14 allowed  (labels wrong)
  off-domain     1/8  allowed  (labels null)
  scope          3/7  allowed  (labels wrong)
  false-allows: w05, w07, w13, n02, s02, s03, s06
```
