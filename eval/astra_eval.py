"""P4: evaluate an intent checker on the Outshift ASTRA dataset before trusting it.

    git clone https://github.com/outshift-open/ASTRA ../ASTRA
    python eval/astra_eval.py --astra ../ASTRA --tools 01_tool

STATUS: skeleton. Before filling in `load_cases`, open one record from
ASTRA/data/01_tool/ASTRA/test.json and confirm the field names (CLAUDE.md rule 7).
ASTRA labels three match types per task: correct, wrong (same MCP server) and
null (different server). A good checker ALLOWS correct and BLOCKS wrong + null.

Report: per match type, block rate; plus false-block rate on correct matches and
median latency per check. Security bias: a missed wrong/null match is worse than a
false block, so report recall on wrong/null first.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_cases(astra_root: Path, tools: str) -> list[dict]:
    path = astra_root / "data" / tools / "ASTRA" / "test.json"
    data = json.loads(path.read_text())
    # TODO(P4): map ASTRA records -> {"task": str, "tool": str, "tool_desc": str,
    #                                  "label": "correct" | "wrong" | "null"}
    raise NotImplementedError(
        f"Inspect the schema of {path} (loaded {type(data).__name__}) and map it here."
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--astra", type=Path, required=True)
    ap.add_argument("--tools", default="01_tool", choices=["01_tool", "02_tools", "03_tools"])
    args = ap.parse_args()
    cases = load_cases(args.astra, args.tools)
    print(f"{len(cases)} cases loaded")


if __name__ == "__main__":
    main()
