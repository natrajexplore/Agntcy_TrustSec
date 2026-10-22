"""Shared evaluation harness for semantic matchers (P4a, docs/P4-design.md §4).

A case is one task plus the tool(s) an agent asked for, labelled
  correct  the requested tools are the right ones
  wrong    a near-miss: other tool(s) on the SAME server (ASTRA "wrong")
  null     tool(s) from an unrelated server / domain (ASTRA "null")
A task is ALLOWED only if every requested tool is allowed (one gate check per tool call).

Security first: report false-allow on wrong and null separately, then false-block on
correct; the paper-comparable numbers (positive class = correct match) come last.
"""
from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field

LABELS = ("correct", "wrong", "null")


@dataclass(frozen=True)
class Case:
    task: str
    tools: tuple            # tuple[ToolRef, ...] requested by the agent
    label: str              # correct | wrong | null
    server_tools: dict = field(default_factory=dict, compare=False)   # server -> tuple[ToolRef]
    category: str = ""      # optional finer tag (netops: scope, injection, ...)
    id: str = ""


@dataclass
class Outcome:
    case: Case
    allowed: bool
    per_tool: list          # [(tool name, allow, reason)]
    latency_ms: list        # per tool check


def run(decide: Callable, cases: list[Case]) -> list[Outcome]:
    """`decide(case, tool) -> (allow: bool, reason: str)`; exceptions count as BLOCK."""
    out = []
    for case in cases:
        per_tool, lat = [], []
        for tool in case.tools:
            t0 = time.perf_counter()
            try:
                allow, reason = decide(case, tool)
            except Exception as e:  # noqa: BLE001 - fail closed, like the gate
                allow, reason = False, f"ERROR {type(e).__name__}: {e}"
            lat.append((time.perf_counter() - t0) * 1000)
            per_tool.append((tool.name, bool(allow), reason))
        out.append(Outcome(case, all(a for _, a, _ in per_tool), per_tool, lat))
    return out


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def metrics(outcomes: list[Outcome]) -> dict:
    by = {lab: [o for o in outcomes if o.case.label == lab] for lab in LABELS}
    allowed = {lab: sum(o.allowed for o in by[lab]) for lab in LABELS}
    tp, fn = allowed["correct"], len(by["correct"]) - allowed["correct"]
    fp = allowed["wrong"] + allowed["null"]
    tn = len(by["wrong"]) + len(by["null"]) - fp
    lat = [ms for o in outcomes for ms in o.latency_ms]
    return {
        "n": {lab: len(by[lab]) for lab in LABELS},
        "false_allow_wrong": _rate(allowed["wrong"], len(by["wrong"])),
        "false_allow_null": _rate(allowed["null"], len(by["null"])),
        "false_block_correct": _rate(fn, len(by["correct"])),
        "accuracy": _rate(tp + tn, len(outcomes)),
        "precision": _rate(tp, tp + fp),
        "recall": _rate(tp, tp + fn),
        "latency_ms_p50": statistics.median(lat) if lat else None,
        "latency_ms_p95": statistics.quantiles(lat, n=20)[-1] if len(lat) >= 20 else (max(lat) if lat else None),
    }


def by_category(outcomes: list[Outcome]) -> dict:
    cats: dict[str, list[Outcome]] = {}
    for o in outcomes:
        cats.setdefault(o.case.category or "-", []).append(o)
    return {c: {"n": len(os), "allowed": sum(o.allowed for o in os),
                "labels": sorted({o.case.label for o in os})} for c, os in sorted(cats.items())}


def pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.1%}"


def ms(v: float | None) -> str:
    return "—" if v is None else f"{v:.2f}"


def markdown_row(name: str, m: dict) -> str:
    return (f"| {name} | {m['n']['correct']}/{m['n']['wrong']}/{m['n']['null']} | "
            f"**{pct(m['false_allow_wrong'])}** | **{pct(m['false_allow_null'])}** | "
            f"{pct(m['false_block_correct'])} | {pct(m['accuracy'])} | {pct(m['precision'])} | "
            f"{pct(m['recall'])} | {ms(m['latency_ms_p50'])} / {ms(m['latency_ms_p95'])} |")


TABLE_HEADER = ("| Run | n correct/wrong/null | false-allow wrong | false-allow null | "
                "false-block correct | accuracy | precision | recall | ms p50 / p95 |\n"
                "|---|---|---|---|---|---|---|---|---|")
