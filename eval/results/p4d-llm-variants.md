# P4d — prompt variants for the local LLM verifier (qwen2.5:7b-instruct, Ollama)

Generated 2026-10-24. Goal: cut the plain prompt's over-blocking (26% of legitimate ASTRA calls denied) without letting more wrong calls through.

## Full catalog (`--matcher llm-catalog`) — not practical on this laptop

Prompts carry the server's whole tool list (~3–4k tokens). Measured **~111 s per check**; the 3rd check hit the 120 s timeout. 200 checks ≈ 6–7 h. Not pursued. (Two earlier full runs were also stopped by Claude Code for low system memory: Ollama's runner held ~7 GB of 15.5 GB.)

## Top-5 similar tools (`--matcher llm-rivals5`) — worse, dropped

Paired test, same 20 correct-labelled tasks (ASTRA test, stratified 200, `--label correct --max-cases 20`):

```
## plain prompt
| llm · 01_tool (n=20) | 20/0/0 | **—** | **—** | 40.0% | 60.0% | 100.0% | 60.0% | 10957.36 / 20520.99 |

Local model usage: 20 calls, 5815 in / 937 out tokens (no API, no cost)
## top-5 shortlist
| llm-rivals5 · 01_tool (n=20) | 20/0/0 | **—** | **—** | 75.0% | 25.0% | 100.0% | 25.0% | 20584.12 / 44928.52 |

Local model usage: 17 calls, 11435 in / 1073 out tokens (no API, no cost)
done after 675s

[exited with code 0]
```

| | plain | top-5 shortlist |
|---|---|---|
| legitimate calls allowed | **12/20** | 5/20 |
| false-block | **40%** | 75% |
| plain allowed, shortlist denied | — | 7 |
| shortlist allowed, plain denied | — | **0** |
| median s/check | **11.0** | 20.6 |

Seeing alternatives makes the model pick a 'better' tool and deny the requested one; it rescued no call the plain prompt denied. Code kept (tested) as evidence; not used.
