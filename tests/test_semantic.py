"""P4c EmbeddingMatcher logic with a fake embedder (no model download, CI-safe)."""
import pytest

from agenttrustsec.authz.semantic import EmbeddingMatcher, ToolRef, cosine

AXES = ("acl", "bgp", "config", "budget")


class FakeEmbed:
    """Bag-of-axes vectors: each text points along the AXES words it mentions."""
    def __init__(self):
        self.calls = []

    def __call__(self, texts):
        self.calls.append(list(texts))
        return [[1.0 if a in t.lower() else 0.0 for a in AXES] + [0.1] for t in texts]


ACL = ToolRef("show_acl", "list acl entries", "netops")
BGP = ToolRef("show_bgp", "bgp neighbor state", "netops")
CFG = ToolRef("show_config", "running config", "netops")
SERVER = (ACL, BGP, CFG)
TASK = "audit the acl on edge-fw-01"


def scores(tool, embed=None):
    return EmbeddingMatcher(embed or FakeEmbed(), 0.0).scores(TASK, tool, SERVER)


def test_scores_absolute_margin_rank():
    best, near = scores(ACL), scores(BGP)
    assert best["rank"] == 1 and best["margin"] > 0
    assert near["rank"] > 1 and near["margin"] < 0
    assert best["absolute"] > near["absolute"]


@pytest.mark.parametrize("mode,threshold,tool,allow", [
    ("absolute", 0.5, ACL, True), ("absolute", 0.5, BGP, False),
    ("margin", 0.0, ACL, True), ("margin", 0.0, BGP, False),
    ("rank", 1, ACL, True), ("rank", 1, BGP, False),
    ("combo", (0.5, 0.0), ACL, True), ("combo", (0.5, 0.0), BGP, False),
    ("combo", (1.01, -1.0), ACL, False),                    # fails the absolute half (cos <= 1)
])
def test_modes(mode, threshold, tool, allow):
    r = EmbeddingMatcher(FakeEmbed(), threshold, mode).match(TASK, tool, SERVER)
    assert r.allow is allow and mode in r.reason


@pytest.mark.parametrize("mode,threshold", [("combo", 0.5), ("absolute", (0.5, 0.0)), ("fuzzy", 0.5)])
def test_bad_config_rejected(mode, threshold):
    with pytest.raises(ValueError):
        EmbeddingMatcher(FakeEmbed(), threshold, mode)


def test_tool_vectors_cached_task_embedded_per_call():
    embed = FakeEmbed()
    m = EmbeddingMatcher(embed, 0.5)
    m.match(TASK, ACL, SERVER)
    m.match("check bgp", BGP, SERVER)
    tool_batches = [c for c in embed.calls if len(c) > 1 or c[0].startswith("show")]
    assert sum(len(c) for c in tool_batches) == 3              # each tool embedded once


def test_no_rivals_means_margin_is_generous_not_crash():
    s = EmbeddingMatcher(FakeEmbed(), 0.0).scores(TASK, ACL, ())
    assert s["rank"] == 1 and s["margin"] > 1


def test_cosine_zero_vector():
    assert cosine([0, 0], [1, 1]) == 0.0
