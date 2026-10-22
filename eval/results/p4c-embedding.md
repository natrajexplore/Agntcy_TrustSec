# P4c — local embedding matcher (fastembed 0.9.0, no API cost)

Generated 2026-10-23. Thresholds picked on ASTRA **validation** (single-tool), reported on **test**. Latency column is 0 here because scores are precomputed; live per-call latency is in the netops section (bge-small: ~7.5 ms p50 / ~15 ms p95 on CPU).

## ASTRA sweep (eval/embed_sweep.py)

ASTRA @ ee05b9b; thresholds from validation 01_tool; prefilter false-block budget 2%

### BAAI/bge-small-en-v1.5 · query prefix: none  (scored in 94s)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| absolute · standalone (th=0.593) · test 01_tool | 474/379/94 | **25.1%** | **4.3%** | 35.2% | 71.9% | 75.6% | 64.8% | 0.00 / 0.00 |
| absolute · standalone (th=0.593) · test 02_tools | 465/372/93 | **9.1%** | **0.0%** | 63.2% | 64.7% | 83.4% | 36.8% | 0.00 / 0.00 |
| absolute · standalone (th=0.593) · test 03_tools | 474/379/94 | **7.9%** | **1.1%** | 73.6% | 59.9% | 80.1% | 26.4% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4562) · test 01_tool | 474/379/94 | **94.7%** | **83.0%** | 0.2% | 53.7% | 52.0% | 99.8% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4562) · test 02_tools | 465/372/93 | **90.9%** | **65.6%** | 2.6% | 55.8% | 53.2% | 97.4% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4562) · test 03_tools | 474/379/94 | **78.9%** | **37.2%** | 10.1% | 59.7% | 56.1% | 89.9% | 0.00 / 0.00 |
| margin · standalone (th=-0.0511) · test 01_tool | 474/379/94 | **19.5%** | **28.7%** | 25.1% | 76.8% | 77.9% | 74.9% | 0.00 / 0.00 |
| margin · standalone (th=-0.0511) · test 02_tools | 465/372/93 | **6.5%** | **12.9%** | 72.7% | 59.8% | 77.9% | 27.3% | 0.00 / 0.00 |
| margin · standalone (th=-0.0511) · test 03_tools | 474/379/94 | **1.6%** | **12.8%** | 90.9% | 52.6% | 70.5% | 9.1% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1237) · test 01_tool | 474/379/94 | **67.8%** | **90.4%** | 1.9% | 62.9% | 57.6% | 98.1% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1237) · test 02_tools | 465/372/93 | **50.3%** | **83.9%** | 17.2% | 62.9% | 59.2% | 82.8% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1237) · test 03_tools | 474/379/94 | **29.6%** | **70.2%** | 38.6% | 61.9% | 62.0% | 61.4% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 01_tool | 474/379/94 | **14.2%** | **19.1%** | 39.5% | 72.7% | 79.9% | 60.5% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 02_tools | 465/372/93 | **0.5%** | **2.2%** | 81.5% | 58.8% | 95.6% | 18.5% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 03_tools | 474/379/94 | **0.5%** | **0.0%** | 96.8% | 51.3% | 88.2% | 3.2% | 0.00 / 0.00 |
| rank · prefilter | no threshold meets the budget | | | | | | | |
| combo · standalone (th=(0.5063, -0.0511)) · test 01_tool | 474/379/94 | **19.0%** | **22.3%** | 26.2% | 77.1% | 79.0% | 73.8% | 0.00 / 0.00 |
| combo · standalone (th=(0.5063, -0.0511)) · test 02_tools | 465/372/93 | **6.2%** | **5.4%** | 72.9% | 60.5% | 81.8% | 27.1% | 0.00 / 0.00 |
| combo · standalone (th=(0.5063, -0.0511)) · test 03_tools | 474/379/94 | **1.1%** | **2.1%** | 91.6% | 53.5% | 87.0% | 8.4% | 0.00 / 0.00 |
| combo · prefilter (th=(0.2967, -0.1251)) · test 01_tool | 474/379/94 | **67.8%** | **90.4%** | 1.7% | 63.0% | 57.7% | 98.3% | 0.00 / 0.00 |
| combo · prefilter (th=(0.2967, -0.1251)) · test 02_tools | 465/372/93 | **51.3%** | **83.9%** | 17.2% | 62.5% | 58.9% | 82.8% | 0.00 / 0.00 |
| combo · prefilter (th=(0.2967, -0.1251)) · test 03_tools | 474/379/94 | **30.6%** | **69.1%** | 38.0% | 61.9% | 61.9% | 62.0% | 0.00 / 0.00 |

### BAAI/bge-small-en-v1.5 · query prefix: bge-query  (scored in 132s)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| absolute · standalone (th=0.5803) · test 01_tool | 474/379/94 | **24.8%** | **2.1%** | 39.7% | 70.0% | 74.9% | 60.3% | 0.00 / 0.00 |
| absolute · standalone (th=0.5803) · test 02_tools | 465/372/93 | **11.6%** | **1.1%** | 62.2% | 64.2% | 80.0% | 37.8% | 0.00 / 0.00 |
| absolute · standalone (th=0.5803) · test 03_tools | 474/379/94 | **7.9%** | **1.1%** | 68.6% | 62.4% | 82.8% | 31.4% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4605) · test 01_tool | 474/379/94 | **91.6%** | **80.9%** | 1.9% | 54.4% | 52.4% | 98.1% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4605) · test 02_tools | 465/372/93 | **87.9%** | **63.4%** | 2.6% | 57.2% | 54.0% | 97.4% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4605) · test 03_tools | 474/379/94 | **84.7%** | **43.6%** | 6.1% | 58.7% | 55.1% | 93.9% | 0.00 / 0.00 |
| margin · standalone (th=-0.0518) · test 01_tool | 474/379/94 | **19.5%** | **36.2%** | 29.5% | 73.8% | 75.6% | 70.5% | 0.00 / 0.00 |
| margin · standalone (th=-0.0518) · test 02_tools | 465/372/93 | **5.9%** | **12.9%** | 75.1% | 58.8% | 77.3% | 24.9% | 0.00 / 0.00 |
| margin · standalone (th=-0.0518) · test 03_tools | 474/379/94 | **1.8%** | **10.6%** | 91.8% | 52.3% | 69.6% | 8.2% | 0.00 / 0.00 |
| margin · prefilter (th=-0.126) · test 01_tool | 474/379/94 | **69.4%** | **90.4%** | 2.1% | 62.2% | 57.1% | 97.9% | 0.00 / 0.00 |
| margin · prefilter (th=-0.126) · test 02_tools | 465/372/93 | **52.2%** | **87.1%** | 18.7% | 61.1% | 57.9% | 81.3% | 0.00 / 0.00 |
| margin · prefilter (th=-0.126) · test 03_tools | 474/379/94 | **28.5%** | **63.8%** | 40.5% | 62.0% | 62.7% | 59.5% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 01_tool | 474/379/94 | **14.2%** | **14.9%** | 42.4% | 71.6% | 80.1% | 57.6% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 02_tools | 465/372/93 | **0.5%** | **4.3%** | 85.8% | 56.5% | 91.7% | 14.2% | 0.00 / 0.00 |
| rank · standalone (th=5) · test 03_tools | 474/379/94 | **0.0%** | **0.0%** | 96.4% | 51.7% | 100.0% | 3.6% | 0.00 / 0.00 |
| rank · prefilter | no threshold meets the budget | | | | | | | |
| combo · standalone (th=(0.5451, -0.059)) · test 01_tool | 474/379/94 | **18.5%** | **10.6%** | 28.9% | 77.1% | 80.8% | 71.1% | 0.00 / 0.00 |
| combo · standalone (th=(0.5451, -0.059)) · test 02_tools | 465/372/93 | **7.0%** | **3.2%** | 72.3% | 60.8% | 81.6% | 27.7% | 0.00 / 0.00 |
| combo · standalone (th=(0.5451, -0.059)) · test 03_tools | 474/379/94 | **2.1%** | **0.0%** | 89.7% | 54.3% | 86.0% | 10.3% | 0.00 / 0.00 |
| combo · prefilter (th=(0.4547, -0.1361)) · test 01_tool | 474/379/94 | **72.8%** | **80.9%** | 2.5% | 61.6% | 56.8% | 97.5% | 0.00 / 0.00 |
| combo · prefilter (th=(0.4547, -0.1361)) · test 02_tools | 465/372/93 | **57.0%** | **64.5%** | 15.3% | 63.1% | 59.2% | 84.7% | 0.00 / 0.00 |
| combo · prefilter (th=(0.4547, -0.1361)) · test 03_tools | 474/379/94 | **33.5%** | **40.4%** | 32.9% | 66.1% | 65.8% | 67.1% | 0.00 / 0.00 |

To support symlinks on Windows, you either need to activate Developer Mode or to run Python as an administrator. In order to activate developer mode, see this article: https://docs.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development
  warnings.warn(message)
Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN to enable higher rate limits and faster downloads.
D:\Gen AI Program\Agntcy_TrustSec_Outshift\.venv\Lib\site-packages\huggingface_hub\file_download.py:149: UserWarning: `huggingface_hub` cache-system uses symlinks by default to efficiently store duplicated files but your machine does not support them in C:\Users\MC HP\.cache\agenttrustsec\fastembed\models--Qdrant--bge-base-en-v1.5-onnx-Q. Caching files will still work but in a degraded version that might require more space on your disk. This warning can be disabled by setting the `HF_HUB_DISABLE_SYMLINKS_WARNING` environment variable. For more details, see https://huggingface.co/docs/huggingface_hub/how-to-cache#limitations.
To support symlinks on Windows, you either need to activate Developer Mode or to run Python as an administrator. In order to activate developer mode, see this article: https://docs.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development
  warnings.warn(message)
### BAAI/bge-base-en-v1.5 · query prefix: none  (scored in 318s)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| absolute · standalone (th=0.525) · test 01_tool | 474/379/94 | **37.7%** | **4.3%** | 24.7% | 72.1% | 70.8% | 75.3% | 0.00 / 0.00 |
| absolute · standalone (th=0.525) · test 02_tools | 465/372/93 | **20.2%** | **1.1%** | 40.6% | 71.5% | 78.4% | 59.4% | 0.00 / 0.00 |
| absolute · standalone (th=0.525) · test 03_tools | 474/379/94 | **13.5%** | **4.3%** | 59.7% | 64.3% | 77.6% | 40.3% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4236) · test 01_tool | 474/379/94 | **90.5%** | **64.9%** | 0.4% | 57.1% | 53.9% | 99.6% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4236) · test 02_tools | 465/372/93 | **88.4%** | **48.4%** | 2.8% | 58.4% | 54.7% | 97.2% | 0.00 / 0.00 |
| absolute · prefilter (th=0.4236) · test 03_tools | 474/379/94 | **72.8%** | **28.7%** | 11.2% | 62.4% | 58.1% | 88.8% | 0.00 / 0.00 |
| margin · standalone (th=-0.0486) · test 01_tool | 474/379/94 | **19.5%** | **28.7%** | 28.1% | 75.3% | 77.1% | 71.9% | 0.00 / 0.00 |
| margin · standalone (th=-0.0486) · test 02_tools | 465/372/93 | **4.6%** | **11.8%** | 76.8% | 58.6% | 79.4% | 23.2% | 0.00 / 0.00 |
| margin · standalone (th=-0.0486) · test 03_tools | 474/379/94 | **0.3%** | **8.5%** | 94.3% | 51.8% | 75.0% | 5.7% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1187) · test 01_tool | 474/379/94 | **60.7%** | **78.7%** | 3.2% | 66.3% | 60.2% | 96.8% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1187) · test 02_tools | 465/372/93 | **42.7%** | **72.0%** | 23.7% | 63.9% | 61.1% | 76.3% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1187) · test 03_tools | 474/379/94 | **20.6%** | **69.1%** | 52.1% | 58.8% | 61.4% | 47.9% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 01_tool | 474/379/94 | **16.6%** | **21.3%** | 34.2% | 74.1% | 79.0% | 65.8% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 02_tools | 465/372/93 | **1.6%** | **6.5%** | 77.6% | 59.9% | 89.7% | 22.4% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 03_tools | 474/379/94 | **0.8%** | **3.2%** | 95.8% | 51.4% | 76.9% | 4.2% | 0.00 / 0.00 |
| rank · prefilter | no threshold meets the budget | | | | | | | |
| combo · standalone (th=(0.4737, -0.0614)) · test 01_tool | 474/379/94 | **25.1%** | **13.8%** | 24.1% | 76.6% | 76.9% | 75.9% | 0.00 / 0.00 |
| combo · standalone (th=(0.4737, -0.0614)) · test 02_tools | 465/372/93 | **8.6%** | **6.5%** | 68.4% | 61.7% | 79.5% | 31.6% | 0.00 / 0.00 |
| combo · standalone (th=(0.4737, -0.0614)) · test 03_tools | 474/379/94 | **1.6%** | **2.1%** | 89.9% | 54.2% | 85.7% | 10.1% | 0.00 / 0.00 |
| combo · prefilter (th=(0.405, -0.1221)) · test 01_tool | 474/379/94 | **61.2%** | **68.1%** | 2.7% | 67.4% | 60.9% | 97.3% | 0.00 / 0.00 |
| combo · prefilter (th=(0.405, -0.1221)) · test 02_tools | 465/372/93 | **44.6%** | **52.7%** | 21.1% | 66.3% | 63.1% | 78.9% | 0.00 / 0.00 |
| combo · prefilter (th=(0.405, -0.1221)) · test 03_tools | 474/379/94 | **20.6%** | **34.0%** | 50.2% | 63.3% | 68.2% | 49.8% | 0.00 / 0.00 |

### BAAI/bge-base-en-v1.5 · query prefix: bge-query  (scored in 337s)

| Run | n correct/wrong/null | false-allow wrong | false-allow null | false-block correct | accuracy | precision | recall | ms p50 / p95 |
|---|---|---|---|---|---|---|---|---|
| absolute · standalone (th=0.4972) · test 01_tool | 474/379/94 | **29.6%** | **2.1%** | 33.1% | 71.4% | 73.5% | 66.9% | 0.00 / 0.00 |
| absolute · standalone (th=0.4972) · test 02_tools | 465/372/93 | **13.2%** | **0.0%** | 53.1% | 68.2% | 81.6% | 46.9% | 0.00 / 0.00 |
| absolute · standalone (th=0.4972) · test 03_tools | 474/379/94 | **9.5%** | **2.1%** | 63.5% | 64.2% | 82.0% | 36.5% | 0.00 / 0.00 |
| absolute · prefilter (th=0.3824) · test 01_tool | 474/379/94 | **88.4%** | **66.0%** | 0.2% | 58.0% | 54.4% | 99.8% | 0.00 / 0.00 |
| absolute · prefilter (th=0.3824) · test 02_tools | 465/372/93 | **84.9%** | **49.5%** | 3.4% | 59.4% | 55.4% | 96.6% | 0.00 / 0.00 |
| absolute · prefilter (th=0.3824) · test 03_tools | 474/379/94 | **76.0%** | **33.0%** | 9.5% | 61.6% | 57.4% | 90.5% | 0.00 / 0.00 |
| margin · standalone (th=-0.047) · test 01_tool | 474/379/94 | **18.7%** | **26.6%** | 28.7% | 75.5% | 77.9% | 71.3% | 0.00 / 0.00 |
| margin · standalone (th=-0.047) · test 02_tools | 465/372/93 | **3.8%** | **10.8%** | 77.6% | 58.6% | 81.2% | 22.4% | 0.00 / 0.00 |
| margin · standalone (th=-0.047) · test 03_tools | 474/379/94 | **0.5%** | **10.6%** | 93.7% | 51.8% | 71.4% | 6.3% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1182) · test 01_tool | 474/379/94 | **60.9%** | **84.0%** | 4.0% | 65.3% | 59.5% | 96.0% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1182) · test 02_tools | 465/372/93 | **43.5%** | **71.0%** | 22.2% | 64.4% | 61.4% | 77.8% | 0.00 / 0.00 |
| margin · prefilter (th=-0.1182) · test 03_tools | 474/379/94 | **21.1%** | **66.0%** | 49.6% | 60.2% | 62.7% | 50.4% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 01_tool | 474/379/94 | **16.1%** | **21.3%** | 33.1% | 74.9% | 79.6% | 66.9% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 02_tools | 465/372/93 | **1.3%** | **6.5%** | 78.1% | 59.8% | 90.3% | 21.9% | 0.00 / 0.00 |
| rank · standalone (th=6) · test 03_tools | 474/379/94 | **0.5%** | **2.1%** | 94.5% | 52.3% | 86.7% | 5.5% | 0.00 / 0.00 |
| rank · prefilter | no threshold meets the budget | | | | | | | |
| combo · standalone (th=(0.4271, -0.0641)) · test 01_tool | 474/379/94 | **26.9%** | **21.3%** | 21.3% | 76.5% | 75.4% | 78.7% | 0.00 / 0.00 |
| combo · standalone (th=(0.4271, -0.0641)) · test 02_tools | 465/372/93 | **8.6%** | **9.7%** | 65.8% | 62.7% | 79.5% | 34.2% | 0.00 / 0.00 |
| combo · standalone (th=(0.4271, -0.0641)) · test 03_tools | 474/379/94 | **1.6%** | **5.3%** | 88.4% | 54.6% | 83.3% | 11.6% | 0.00 / 0.00 |
| combo · prefilter (th=(0.3534, -0.1191)) · test 01_tool | 474/379/94 | **59.4%** | **77.7%** | 3.8% | 66.6% | 60.5% | 96.2% | 0.00 / 0.00 |
| combo · prefilter (th=(0.3534, -0.1191)) · test 02_tools | 465/372/93 | **44.1%** | **54.8%** | 22.2% | 65.8% | 62.7% | 77.8% | 0.00 / 0.00 |
| combo · prefilter (th=(0.3534, -0.1191)) · test 03_tools | 474/379/94 | **22.2%** | **39.4%** | 49.2% | 62.6% | 66.6% | 50.8% | 0.00 / 0.00 |


## Netops, live (eval/netops_eval.py --embedding BAAI/bge-small-en-v1.5)

```
# combo prefilter (0.2967, -0.1251):
| embedding bge-small-en-v1.5 combo=(0.2967, -0.1251) (live) | 18/22/8 | **54.5%** | **87.5%** | 11.1% | 56.2% | 45.7% | 88.9% | 8.48 / 16.49 |
# absolute prefilter 0.4562:
| embedding bge-small-en-v1.5 absolute=0.4562 (live) | 18/22/8 | **95.5%** | **87.5%** | 0.0% | 41.7% | 39.1% | 100.0% | 8.66 / 12.09 |
```

Combo prefilter false-blocks on netops: c06, c07 (both legitimate push_config change requests: review_change / show_acl outrank push_config, so the margin rule denies the right tool).
