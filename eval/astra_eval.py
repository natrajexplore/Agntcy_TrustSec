"""P4: evaluate a semantic matcher on the Outshift ASTRA dataset before trusting it.

    git clone https://github.com/outshift-open/ASTRA eval/.astra
    git -C eval/.astra checkout ee05b9b6e6c1c91688db45b187da68f6b2ecb8e7      # pinned
    python eval/astra_eval.py --matcher lexical --split test --tools 01_tool 03_tools

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
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from harness import TABLE_HEADER, Case, markdown_row, metrics, run  # noqa: E402

from agenttrustsec.authz.semantic import LexicalMatcher, ToolRef  # noqa: E402

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


MATCHERS = {"lexical": lambda: LexicalMatcher()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--astra", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--tools", nargs="+", default=["01_tool"], choices=["01_tool", "02_tools", "03_tools"])
    ap.add_argument("--split", default="validation", choices=["validation", "test"])
    ap.add_argument("--matcher", default="lexical", choices=sorted(MATCHERS))
    args = ap.parse_args(argv)
    matcher = MATCHERS[args.matcher]()

    def decide(case, tool):
        r = matcher.match(case.task, tool, case.server_tools.get(tool.server, ()))
        return r.allow, r.reason

    print(f"ASTRA @ {PINNED[:7]}  split={args.split}  matcher={args.matcher}\n")
    print(TABLE_HEADER)
    for tools in args.tools:
        m = metrics(run(decide, load_cases(args.astra, tools, args.split)))
        print(markdown_row(f"{args.matcher} · {tools}", m))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
