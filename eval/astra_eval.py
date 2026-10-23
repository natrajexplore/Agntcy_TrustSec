"""P4: evaluate a semantic matcher on the Outshift ASTRA dataset before trusting it.

    git clone https://github.com/outshift-open/ASTRA eval/.astra
    git -C eval/.astra checkout ee05b9b6e6c1c91688db45b187da68f6b2ecb8e7      # pinned
    python eval/astra_eval.py --matcher lexical --split test --tools 01_tool 03_tools
    python eval/astra_eval.py --matcher llm --limit 20     # local Ollama (free, ~6.5 s/check)
    python eval/astra_eval.py --matcher llm-catalog --limit 200 --checkpoint eval/.runs/cat.jsonl --batch 50
        # resumable: each verdict is saved as it is made; re-run the same command to continue

Schema verified on that commit (2026-10-23): a record is
  {"input": {"task", "tools": [...], "mcp_servers": [...]},
   "groundtruth": {"tools", "mcp_servers"}, "match_tag": "correct"|"wrong"|"null"}
Tool descriptions come from data/mcp_servers/ASTRA/*.json, keyed by each file's "name".
In multi-tool "wrong" tasks no requested tool is in the ground truth, so every tool of a
task carries the task's label; a task is allowed only if all its tools are.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from harness import TABLE_HEADER, Case, markdown_row, metrics, run  # noqa: E402

from agenttrustsec.authz.semantic import LexicalMatcher, LlmMatcher, ToolRef, ollama_judge  # noqa: E402

DEFAULT_ROOT = HERE / ".astra"
PINNED = "ee05b9b6e6c1c91688db45b187da68f6b2ecb8e7"


def load_servers(root: Path) -> dict[str, tuple[ToolRef, ...]]:
    servers = {}
    for f in sorted((root / "data" / "mcp_servers" / "ASTRA").glob("*.json")):
        spec = json.loads(f.read_text(encoding="utf-8"))
        servers[spec["name"]] = tuple(ToolRef(t["name"], t.get("description") or "", spec["name"])
                                      for t in spec["tools"])
    return servers


def load_cases(root: Path, tools: str, split: str) -> list[Case]:
    servers = load_servers(root)
    records = json.loads((root / "data" / tools / "ASTRA" / f"{split}.json").read_text(encoding="utf-8"))
    cases = []
    for i, r in enumerate(records):
        label = r["match_tag"]
        if label not in ("correct", "wrong", "null"):
            raise ValueError(f"record {i}: unknown match_tag {label!r}")
        refs = []
        for name, server in zip(r["input"]["tools"], r["input"]["mcp_servers"]):
            by_name = {t.name: t for t in servers[server]}       # KeyError = schema drift: fail loudly
            refs.append(by_name[name])
        cases.append(Case(r["input"]["task"], tuple(refs), label,
                          {s: servers[s] for s in set(r["input"]["mcp_servers"])},
                          id=f"{tools}/{split}/{i}"))
    return cases


MATCHERS = {"lexical": lambda: LexicalMatcher(),
            "llm": lambda: LlmMatcher(ollama_judge()),
            "llm-catalog": lambda: LlmMatcher(ollama_judge(), with_catalog=True)}


def stratified(cases: list[Case], limit: int) -> list[Case]:
    """Deterministic sample keeping the label mix: every k-th case of each label."""
    if not limit or limit >= len(cases):
        return cases
    out = []
    for label in ("correct", "wrong", "null"):
        group = [c for c in cases if c.label == label]
        k = max(1, round(limit * len(group) / len(cases)))
        step = max(1, len(group) // k)
        out += group[::step][:k]
    return out


def report_usage(matcher) -> None:
    u = getattr(matcher, "usage", None)
    if not u or not u["calls"]:
        return
    print(f"\nLocal model usage: {u['calls']} calls, {u['input_tokens']} in / {u['output_tokens']} out "
          f"tokens (no API, no cost)")


class BatchDone(Exception):
    """This run made its --batch quota of model calls; re-run to continue."""


def load_checkpoint(path: Path) -> dict:
    done = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done[(r["id"], r["tool"])] = r
    return done


def run_checkpointed(matcher, cases: list[Case], path: Path, batch: int = 0):
    """Resume-safe evaluation. Returns (outcomes or None if unfinished, checks done, total).
    Verdicts are appended to `path` immediately. A matcher exception is NOT saved (it is an
    infrastructure failure, not a verdict): the run stops and that check is retried next time."""
    path.parent.mkdir(parents=True, exist_ok=True)
    done = load_checkpoint(path)
    total = sum(len(c.tools) for c in cases)
    calls = 0
    with path.open("a", encoding="utf-8") as f:
        for c in cases:
            for tool in c.tools:
                if (c.id, tool.name) in done:
                    continue
                if batch and calls >= batch:
                    return None, len(done), total
                t0 = time.perf_counter()
                r = matcher.match(c.task, tool, c.server_tools.get(tool.server, ()))
                rec = {"id": c.id, "tool": tool.name, "allow": r.allow, "reason": r.reason,
                       "ms": (time.perf_counter() - t0) * 1000}
                f.write(json.dumps(rec) + "\n")
                f.flush()
                done[(c.id, tool.name)] = rec
                calls += 1
    outcomes = run(lambda case, tool: (done[(case.id, tool.name)]["allow"],
                                       done[(case.id, tool.name)]["reason"]), cases)
    for o in outcomes:                       # replace lookup timing with the recorded model latency
        o.latency_ms[:] = [done[(o.case.id, t.name)]["ms"] for t in o.case.tools]
    return outcomes, len(done), total


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--astra", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--tools", nargs="+", default=["01_tool"], choices=["01_tool", "02_tools", "03_tools"])
    ap.add_argument("--split", default="validation", choices=["validation", "test"])
    ap.add_argument("--matcher", default="lexical", choices=sorted(MATCHERS))
    ap.add_argument("--limit", type=int, default=0, help="stratified sample size per --tools set")
    ap.add_argument("--checkpoint", type=Path, help="JSONL file: save each verdict, resume on re-run")
    ap.add_argument("--batch", type=int, default=0, help="with --checkpoint: max new model calls this run")
    args = ap.parse_args(argv)
    if args.batch and not args.checkpoint:
        ap.error("--batch needs --checkpoint")
    if args.checkpoint and len(args.tools) != 1:
        ap.error("--checkpoint takes one --tools set per file")
    matcher = MATCHERS[args.matcher]()

    def decide(case, tool):
        r = matcher.match(case.task, tool, case.server_tools.get(tool.server, ()))
        return r.allow, r.reason

    print(f"ASTRA @ {PINNED[:7]}  split={args.split}  matcher={args.matcher}\n")
    print(TABLE_HEADER)
    for tools in args.tools:
        cases = stratified(load_cases(args.astra, tools, args.split), args.limit)
        if args.checkpoint:
            outcomes, n_done, n_total = run_checkpointed(matcher, cases, args.checkpoint, args.batch)
            if outcomes is None:
                print(f"| (partial) {args.matcher} · {tools} | {n_done}/{n_total} checks saved to "
                      f"{args.checkpoint} — re-run to continue | | | | | | | |")
                continue
            m = metrics(outcomes)
        else:
            m = metrics(run(decide, cases))
        print(markdown_row(f"{args.matcher} · {tools}" + (f" (n={len(cases)})" if args.limit else ""), m))
    report_usage(matcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
