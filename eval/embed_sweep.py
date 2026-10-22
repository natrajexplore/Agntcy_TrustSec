"""P4c: tune and evaluate the local EmbeddingMatcher on ASTRA (no API cost).

    python eval/embed_sweep.py --models BAAI/bge-small-en-v1.5 BAAI/bge-base-en-v1.5

For each model x query-prefix x mode (absolute | margin | rank): score every requested
tool ONCE, pick thresholds on the VALIDATION split (single-tool tasks), then report TEST
metrics at two operating points:
  standalone  threshold with the best validation accuracy (SemSimM's role in the paper)
  prefilter   most aggressive DENY threshold whose validation false-block on correct is
              <= --max-false-block (its role in the D2 cascade: its deny is final, its
              allow just means "ask the LLM verifier")
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from astra_eval import DEFAULT_ROOT, PINNED, load_cases  # noqa: E402
from harness import TABLE_HEADER, markdown_row, metrics, run  # noqa: E402

from agenttrustsec.authz.semantic import (  # noqa: E402
    EmbeddingMatcher, fastembed_embedder,
)

BGE_QUERY = "Represent this sentence for searching relevant passages: "
NS = ("01_tool", "02_tools", "03_tools")


def score_all(matcher: EmbeddingMatcher, cases) -> dict:
    """{(case.id, tool.name): scores} — tasks embedded in one batch, tools cached."""
    tasks = sorted({c.task for c in cases})
    qvecs = dict(zip(tasks, matcher.embed([matcher.query_prefix + t for t in tasks])))
    real_embed = matcher.embed
    out = {}
    for c in cases:
        matcher.embed = lambda texts, _q=qvecs[c.task], _c=c: (     # task vector from batch
            [_q] if list(texts) == [matcher.query_prefix + _c.task] else real_embed(texts))
        for tool in c.tools:
            out[(c.id, tool.name)] = matcher.scores(c.task, tool, c.server_tools[tool.server])
    matcher.embed = real_embed
    return out


def decide_from(scores: dict, mode: str, threshold):
    judge = EmbeddingMatcher(lambda texts: [], threshold, mode)      # decide() only, no embedding

    def decide(case, tool):
        allow, v = judge.decide(scores[(case.id, tool.name)])
        return allow, f"{mode}={v:.3f}"
    return decide


def candidates(scores: dict, mode: str) -> list:
    if mode == "rank":
        return [float(k) for k in range(1, 11)]
    if mode == "combo":
        a = candidates(scores, "absolute")[::8]
        m = candidates(scores, "margin")[::8]
        return [(x, y) for x in a for y in m]
    vals = sorted({round(s[mode], 4) for s in scores.values()})
    step = max(1, len(vals) // 400)
    return vals[::step]


def pick(cases, scores, mode, max_false_block):
    best_acc, best_pref = None, None
    for th in candidates(scores, mode):
        m = metrics(run(decide_from(scores, mode, th), cases))
        if best_acc is None or m["accuracy"] > best_acc[1]["accuracy"]:
            best_acc = (th, m)
        # prefilter: deny as much as possible while false-block <= budget
        blocked_bad = 1 - ((m["false_allow_wrong"] or 0) * m["n"]["wrong"] + (m["false_allow_null"] or 0)
                           * m["n"]["null"]) / max(1, m["n"]["wrong"] + m["n"]["null"])
        if m["false_block_correct"] <= max_false_block and (best_pref is None or blocked_bad > best_pref[2]):
            best_pref = (th, m, blocked_bad)
    return best_acc[0], (best_pref[0] if best_pref else None)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--astra", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--models", nargs="+", default=["BAAI/bge-small-en-v1.5"])
    ap.add_argument("--max-false-block", type=float, default=0.02)
    args = ap.parse_args(argv)
    val = load_cases(args.astra, "01_tool", "validation")
    tests = {n: load_cases(args.astra, n, "test") for n in NS}
    print(f"ASTRA @ {PINNED[:7]}; thresholds from validation 01_tool; prefilter false-block budget "
          f"{args.max_false_block:.0%}\n")
    for model in args.models:
        embed = fastembed_embedder(model)
        for prefix_name, prefix in (("none", ""), ("bge-query", BGE_QUERY)):
            t0 = time.perf_counter()
            m = EmbeddingMatcher(embed, 0.0, query_prefix=prefix)
            vscores = score_all(m, val)
            tscores = {n: score_all(m, cs) for n, cs in tests.items()}
            secs = time.perf_counter() - t0
            print(f"### {model} · query prefix: {prefix_name}  (scored in {secs:.0f}s)\n")
            print(TABLE_HEADER)
            for mode in EmbeddingMatcher.MODES:
                acc_th, pref_th = pick(val, vscores, mode, args.max_false_block)
                for point, th in (("standalone", acc_th), ("prefilter", pref_th)):
                    if th is None:
                        print(f"| {mode} · {point} | no threshold meets the budget | | | | | | | |")
                        continue
                    label = f"({th[0]:.4g}, {th[1]:.4g})" if isinstance(th, tuple) else f"{th:g}"
                    for n in NS:
                        mm = metrics(run(decide_from(tscores[n], mode, th), tests[n]))
                        print(markdown_row(f"{mode} · {point} (th={label}) · test {n}", mm))
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
