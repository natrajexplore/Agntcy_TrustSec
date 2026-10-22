"""Semantic task<->tool matching for the intent check (P4, docs/P4-design.md §3).

TrustSec analogy: posture assessment — identity and SGT already passed; this asks whether
*this* tool fits *this* request. Matchers are pluggable and must be evaluated
(eval/astra_eval.py, eval/netops_eval.py) before the gate trusts one.

`match()` returns allow/deny; any exception inside a matcher is the caller's ERROR -> BLOCK.
LexicalMatcher is the measurement baseline (what today's keyword check approximates);
EmbeddingMatcher (P4c) and LlmMatcher (P4d) implement the same Protocol.
"""
from __future__ import annotations

import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
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


# --- P4c: local embedding matcher -------------------------------------------------------

# texts -> one vector per text. Vendor code stays behind this callable (CLAUDE.md rule 7).
Embedder = Callable[[Sequence[str]], list[list[float]]]

DEFAULT_EMBED_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_CACHE = Path.home() / ".cache" / "agenttrustsec" / "fastembed"


def fastembed_embedder(model: str = DEFAULT_EMBED_MODEL, cache_dir: Path = DEFAULT_CACHE) -> Embedder:
    """Local ONNX embeddings via fastembed (the `semantic` extra). Downloads the model from
    Hugging Face once into `cache_dir` (never into the repo)."""
    from fastembed import TextEmbedding

    engine = TextEmbedding(model_name=model, cache_dir=str(cache_dir))

    def embed(texts: Sequence[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in engine.embed(list(texts))]
    return embed


def tool_text(tool: ToolRef) -> str:
    return f"{tool.name.replace('_', ' ')}: {tool.description}"


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class EmbeddingMatcher:
    """SemSimM-style task<->tool similarity (P4c). Modes, threshold tuned on ASTRA validation:
      absolute  allow if cos(task, tool) >= threshold
      margin    allow if cos(task, tool) - max cos(task, other tools on its server) >= threshold
                (a near-miss on the same server is usually NOT the best match)
      rank      allow if the tool is in the server's top-`threshold` for the task
      combo     allow if cos >= threshold[0] AND margin >= threshold[1] — absolute catches
                unrelated tools, margin catches same-server near-misses (P4c sweep)
    In the D2 cascade only its DENY is final; ALLOW means "ask the LLM verifier"."""

    MODES = ("absolute", "margin", "rank", "combo")

    def __init__(self, embed: Embedder, threshold: float | tuple[float, float],
                 mode: str = "absolute", query_prefix: str = ""):
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        if (mode == "combo") != isinstance(threshold, tuple):
            raise ValueError("combo needs a (cos, margin) threshold pair; other modes a number")
        self.embed, self.threshold, self.mode, self.query_prefix = embed, threshold, mode, query_prefix
        self._tool_vecs: dict[ToolRef, list[float]] = {}

    def _vecs(self, tools: Sequence[ToolRef]) -> list[list[float]]:
        missing = [t for t in tools if t not in self._tool_vecs]
        if missing:
            for t, v in zip(missing, self.embed([tool_text(t) for t in missing])):
                self._tool_vecs[t] = v
        return [self._tool_vecs[t] for t in tools]

    def scores(self, task: str, tool: ToolRef, server_tools: Sequence[ToolRef] = ()) -> dict:
        q, = self.embed([self.query_prefix + task])
        others = [t for t in server_tools if t != tool]
        own = cosine(q, self._vecs([tool])[0])
        rivals = [cosine(q, v) for v in self._vecs(others)] if others else []
        return {"absolute": own, "margin": own - max(rivals, default=-1.0),
                "rank": 1 + sum(r > own for r in rivals)}

    def decide(self, s: dict) -> tuple[bool, float]:
        if self.mode == "combo":
            return s["absolute"] >= self.threshold[0] and s["margin"] >= self.threshold[1], s["absolute"]
        v = s[self.mode]
        return (v <= self.threshold if self.mode == "rank" else v >= self.threshold), float(v)

    def match(self, task: str, tool: ToolRef, server_tools: tuple[ToolRef, ...] = ()) -> MatchResult:
        s = self.scores(task, tool, server_tools)
        allow, v = self.decide(s)
        return MatchResult(allow, v, f"{self.mode}: cos={s['absolute']:.3f} margin={s['margin']:.3f} "
                                     f"rank={s['rank']} vs threshold {self.threshold}")
