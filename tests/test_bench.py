"""P6a: benchmark helpers (eval/bench.py). The offline run must exercise the real gate."""
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "eval"))
import bench  # noqa: E402


def test_nearest_rank_percentiles():
    v = [float(x) for x in range(1, 101)]
    assert (bench.pct(v, 50), bench.pct(v, 95), bench.pct(v, 100)) == (50.0, 95.0, 100.0)
    assert bench.pct([], 50) is None and bench.pct([7.0], 95) == 7.0


def test_format_picks_units():
    assert bench.fmt(0.123) == "0.12 ms" and bench.fmt(42) == "42 ms" and bench.fmt(4600) == "4.60 s"
    assert bench.fmt(None) == "-"


def test_per_check_split_filters_and_skips_untimed():
    recs = [{"tool": "show_acl", "verdict": "ALLOW", "elapsed_ms": 2.0,
             "checks": [{"name": "badge", "elapsed_ms": 1.5}, {"name": "intent", "elapsed_ms": 0.5}]},
            {"tool": "push_config", "verdict": "BLOCK", "elapsed_ms": 1.0,
             "checks": [{"name": "badge", "elapsed_ms": 1.0}, {"name": "intent", "elapsed_ms": None}]}]
    s = bench.per_check(recs, "show_acl", "ALLOW")
    assert s["badge"] == [1.5] and s["intent"] == [0.5] and s["decision"] == [2.0]
    assert bench.per_check(recs)["intent"] == [0.5]                  # SKIPPED (None) not counted


def test_offline_bench_runs_the_real_gate():
    out = "\n".join(bench.offline(20))
    for case in ("read ALLOW", "read BLOCK at tbac", "change ALLOW"):
        assert case in out
    assert "`approval` | 20 |" in out                 # every change call redeemed an approval
