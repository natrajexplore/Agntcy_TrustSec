"""Semantic task<->tool matching for the intent check (P4, docs/P4-design.md §3).

TrustSec analogy: posture assessment — identity and SGT already passed; this asks whether
*this* tool fits *this* request. Matchers are pluggable and must be evaluated
(eval/astra_eval.py, eval/netops_eval.py) before the gate trusts one.

`match()` returns allow/deny; any exception inside a matcher is the caller's ERROR -> BLOCK.
LexicalMatcher is the measurement baseline (what today's keyword check approximates);
EmbeddingMatcher (P4c) and LlmMatcher (P4d) implement the same Protocol.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

# Small, fixed stopword list: words that carry no tool-relevance signal.
_STOP = frozenset("""
a an and are as at be by can could do does for from get gets given has have how i if in into
is it its me my of on or our please set that the their them then there these this those to
up use using via want was we what when where which while who will with would you your all any
""".split())


@dataclass(frozen=True)
class ToolRef:
    name: str
    description: str
    server: str = ""


@dataclass(frozen=True)
class MatchResult:
    allow: bool
    score: float
    reason: str


class SemanticMatcher(Protocol):
    def match(self, task: str, tool: ToolRef, server_tools: tuple[ToolRef, ...] = ()) -> MatchResult:
        ...


def content_words(text: str) -> set[str]:
    """Lower-cased word tokens (snake_case split), minus stopwords and 1-char tokens."""
    words = re.findall(r"[a-z0-9]+", text.lower().replace("_", " "))
    return {w for w in words if len(w) > 1 and w not in _STOP}


class LexicalMatcher:
    """BASELINE ONLY: allow if the task shares >= `min_overlap` content words with the
    tool's name + description. Mirrors BaselineIntentChecker's keyword overlap for
    datasets (ASTRA) whose tools carry no keyword lists."""

    def __init__(self, min_overlap: int = 1):
        self.min_overlap = min_overlap

    def match(self, task: str, tool: ToolRef, server_tools: tuple[ToolRef, ...] = ()) -> MatchResult:
        overlap = content_words(task) & content_words(f"{tool.name} {tool.description}")
        allow = len(overlap) >= self.min_overlap
        return MatchResult(allow, float(len(overlap)),
                           f"overlap {sorted(overlap)[:8]}" if overlap else "no overlap")
