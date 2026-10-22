"""P4: evaluate intent checks on our own netops cases (eval/netops_cases.yaml).

    python eval/netops_eval.py

Runs (1) today's gate intent check, BaselineIntentChecker (change gate + tbac.yaml keyword
overlap), and (2) each semantic matcher alone (no change gate), so both the full check and
the semantic part are visible. Tool descriptions come from OUR policies/tbac.yaml.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

from harness import TABLE_HEADER, Case, by_category, markdown_row, metrics, run  # noqa: E402

from agenttrustsec.authz.intent import BaselineIntentChecker  # noqa: E402
from agenttrustsec.authz.semantic import LexicalMatcher, ToolRef  # noqa: E402
from agenttrustsec.authz.tbac import TbacPolicy  # noqa: E402
from agenttrustsec.models import Intent, Session  # noqa: E402

CASES = HERE / "netops_cases.yaml"
SERVER = "netops-mcp"


def load(policy: TbacPolicy, path: Path = CASES) -> list[Case]:
    tools = tuple(ToolRef(n, s.description, SERVER) for n, s in sorted(policy.tools.items()))
    by_name = {t.name: t for t in tools}
    out = []
    for c in yaml.safe_load(path.read_text(encoding="utf-8"))["cases"]:
        if c.get("label") not in ("correct", "wrong", "null"):   # YAML null -> None: quote it
            raise ValueError(f"{c.get('id')}: label must be correct|wrong|\"null\", got {c.get('label')!r}")
        case = Case(c["task"], (by_name[c["tool"]],), c["label"], {SERVER: tools},
                    category=c["category"], id=c["id"])
        object.__setattr__(case, "intent", Intent(c["intent"]))   # frozen dataclass extras
        object.__setattr__(case, "args", c.get("args") or {})
        out.append(case)
    return out


def main() -> int:
    policy = TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")
    cases = load(policy)
    baseline = BaselineIntentChecker()

    def gate_intent(case, tool):
        r = baseline.check(Session(case.task, case.intent), policy.spec(tool.name))
        return r.passed, r.reason

    lexical = LexicalMatcher()

    def lexical_only(case, tool):
        r = lexical.match(case.task, tool, case.server_tools[SERVER])
        return r.allow, r.reason

    print(f"netops cases: {len(cases)}  ({CASES.name})\n")
    print(TABLE_HEADER)
    runs = {"gate intent today (change gate + keywords)": run(gate_intent, cases),
            "lexical matcher only": run(lexical_only, cases)}
    for name, outcomes in runs.items():
        print(markdown_row(name, metrics(outcomes)))
    for name, outcomes in runs.items():
        print(f"\n{name} — allowed per category:")
        for cat, s in by_category(outcomes).items():
            print(f"  {cat:<13} {s['allowed']:>2}/{s['n']:<2} allowed  (labels {','.join(s['labels'])})")
        missed = [o.case.id for o in outcomes if o.allowed and o.case.label != "correct"]
        print(f"  false-allows: {', '.join(missed) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
