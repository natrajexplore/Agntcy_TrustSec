"""Control Center: per-layer status from real evidence only, fail-closed probes, and a localhost
server that a web page in the browser can neither drive nor read (Host / Origin / token)."""
import json
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest

from agenttrustsec import controlcenter as cc
from agenttrustsec import dashboard

from conftest import ROOT

ROW = {"timestamp": "2026-10-23T15:48:49.308488+00:00", "agent_id": "A", "tool": "show_acl", "verdict": "BLOCK",
       "blocked_by": "peer", "verified_role": None,
       "checks": [{"name": "badge", "status": "PASS", "reason": "ok"},
                  {"name": "peer", "status": "FAIL", "reason": "not signed by the badge's key </script>"}]}
RESULT = {"act": "1", "label": "#1 copied badge", "expect": "BLOCK", "expect_by": "peer",
          "verdict": "BLOCK", "by": "peer", "reason": "r", "ok": True}


@pytest.fixture
def run_dir(tmp_path):
    (tmp_path / "gateway.jsonl").write_text(json.dumps(ROW) + "\n")
    (tmp_path / "results.json").write_text(json.dumps([RESULT]))
    return tmp_path


def layer(view, lid):
    return next(x for x in view if x["id"] == lid)


# --- registry --------------------------------------------------------------------------------

def test_registry_covers_eleven_layers_plus_audit():
    assert [x.n for x in cc.LAYERS] == [str(i) for i in range(1, 12)] + ["—"]
    assert len({x.id for x in cc.LAYERS}) == len(cc.LAYERS)
    probes = {p for x in cc.LAYERS for p in x.probes}
    assert probes == set(cc.PROBE_LABELS) == set(cc.SYNC_PROBES) | set(cc.ASYNC_PROBES)


def test_every_covered_by_test_exists():
    defined = set(re.findall(r"^\s*def (test_\w+)", "\n".join(p.read_text(encoding="utf-8")   # incl. class methods
                                                          for p in (ROOT / "tests").glob("test_*.py")), re.M))
    missing = {t for x in cc.LAYERS for t in x.tests} - defined
    assert not missing, f"Control Center points at tests that don't exist: {sorted(missing)}"


def test_every_where_path_exists():
    for x in cc.LAYERS:
        for w in x.where:
            assert (ROOT / "src" / "agenttrustsec" / w).exists() or (ROOT / w).exists(), w


# --- status: evidence only, deny by default ------------------------------------------------------

@pytest.mark.parametrize("oks,status", [
    ([True, True], "verified"), ([True, None], "not verified"), ([True, False], "failing"),
    ([None], "not verified"), ([], "not verified"), ([False, None], "failing"),
])
def test_status_is_verified_only_with_every_piece_of_evidence(oks, status):
    assert cc.status_of([{"ok": o} for o in oks]) == status


def test_audit_and_demo_evidence_verify_a_layer(run_dir):
    v = cc.layers_view(dashboard.collect(run_dir), None)
    peer = layer(v, "peer")
    assert peer["status"] == "verified" and [i["kind"] for i in peer["items"]] == ["audit", "demo"]
    assert "not signed by the badge's key" in peer["items"][0]["detail"]


def test_no_evidence_is_never_green():
    v = cc.layers_view(None, None)
    assert {x["status"] for x in v} == {"not verified"}


def test_probe_only_layers_wait_for_probes(run_dir):
    data = dashboard.collect(run_dir)
    assert layer(cc.layers_view(data, None), "node")["status"] == "not verified"
    ok = {p: {"ok": True, "detail": "d"} for p in cc.PROBE_LABELS}
    assert layer(cc.layers_view(data, ok), "node")["status"] == "verified"
    bad = {**ok, "node_admission": {"ok": False, "detail": "a PLAINTEXT client was admitted"}}
    assert layer(cc.layers_view(data, bad), "node")["status"] == "failing"


def test_a_failed_demo_step_fails_its_layer(run_dir):
    (run_dir / "results.json").write_text(json.dumps([{**RESULT, "ok": False, "verdict": "ALLOW", "by": "-"}]))
    assert layer(cc.layers_view(dashboard.collect(run_dir), None), "peer")["status"] == "failing"


def test_incomplete_audit_record_fails_the_audit_layer(run_dir):
    (run_dir / "executor.jsonl").write_text(json.dumps({**ROW, "verdict": "BLOCK", "blocked_by": None}) + "\n")
    assert layer(cc.layers_view(dashboard.collect(run_dir), None), "audit")["status"] == "failing"


# --- probes fail closed ------------------------------------------------------------------------

def test_offline_probes_pass_without_the_lab(tmp_path):
    for pid in ("policy", "intent_offline", "replay_store", "review_crosscheck"):
        ok, detail = cc.SYNC_PROBES[pid](tmp_path)
        assert ok is True, (pid, detail)


def test_lab_probes_report_not_verified_when_the_lab_is_down(tmp_path, monkeypatch):
    import asyncio
    monkeypatch.setattr(cc, "_up", lambda port: False)
    assert cc.probe_badges(tmp_path)[0] is None and cc.probe_inventory(tmp_path)[0] is None
    assert asyncio.run(cc._node_admission())[0] is None and asyncio.run(cc._slim_identity())[0] is None


def test_a_probe_that_raises_is_a_failure(monkeypatch):
    monkeypatch.setattr(cc, "SYNC_PROBES", {"policy": lambda t: 1 / 0})
    monkeypatch.setattr(cc, "ASYNC_PROBES", {})
    out = cc.run_probes()
    assert out["policy"]["ok"] is False and "ZeroDivisionError" in out["policy"]["detail"]


@pytest.mark.parametrize("behaviour", ["no result", "timeout"])
def test_a_broken_probe_process_fails_every_probe(monkeypatch, behaviour):
    def fake(*a, **k):
        if behaviour == "timeout":
            raise subprocess.TimeoutExpired("x", 1)
        return subprocess.CompletedProcess(a, 1, stdout="crashed\n", stderr="")
    monkeypatch.setattr(cc.subprocess, "run", fake)
    probes = cc.probe_in_child()["probes"]
    assert set(probes) == set(cc.PROBE_LABELS) and all(p["ok"] is False for p in probes.values())


# --- health ------------------------------------------------------------------------------------

def test_health_flags_missing_pki_and_a_leaked_ca_key(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTTRUSTSEC_PKI", str(tmp_path))
    monkeypatch.setattr(cc, "_up", lambda port: False)
    h = {x["name"]: x for x in cc.health(None)}
    assert h["SLIM node certificate"]["status"] == "fail" and h["Latest live demo"]["status"] == "warn"
    (tmp_path / "node").mkdir()
    (tmp_path / "node" / "ca.key").write_text("-----BEGIN PRIVATE KEY-----\nx\n")
    h = {x["name"]: x for x in cc.health(None)}
    assert h["CA private key kept out of the node mount"]["status"] == "fail"


# --- page + server -----------------------------------------------------------------------------

def test_page_embeds_data_safely(run_dir):
    html = cc.render_page(cc.view(dashboard.collect(run_dir), None), "tok123")
    assert "</script>\"" not in html and "\\u003c/script>" in html and '"token": "tok123"' in html


@pytest.fixture
def server(run_dir):
    gate = threading.Event()
    calls = []

    def probe():
        calls.append(1)
        gate.wait(5)
        return {"ran_at": "2026-10-23T17:00:00+00:00", "probes": {p: {"ok": True, "detail": "d"} for p in cc.PROBE_LABELS}}
    httpd = dashboard.make_server(run_dir, 0, probe=probe)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    yield f"http://127.0.0.1:{port}", port, gate, calls
    gate.set()
    httpd.shutdown()
    httpd.server_close()


def req(url, method="GET", headers=None):
    r = urllib.request.Request(url, method=method, headers=headers or {}, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def token(base):
    return re.search(r'"token": "([^"]+)"', req(base + "/control")[2]).group(1)


def test_server_binds_loopback_only(server):
    assert server[0].startswith("http://127.0.0.1:")


def test_pages_carry_security_headers(server):
    base = server[0]
    for path in ("/", "/control"):
        code, h, _ = req(base + path)
        assert code == 200 and h["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff" and "Access-Control-Allow-Origin" not in h


@pytest.mark.parametrize("path", ["/", "/data.json", "/control", "/control.json"])
def test_foreign_host_is_refused_dns_rebinding(server, path):
    assert req(server[0] + path, headers={"Host": f"rebind.example:{server[1]}"})[0] == 403


def test_run_needs_post_origin_and_token(server):
    base, port, gate, calls = server
    good = {"Origin": f"http://127.0.0.1:{port}"}
    assert req(base + "/control/run")[0] == 404                                       # GET can't run
    assert req(base + "/control/run", "POST")[0] == 403                               # no Origin, no token
    assert req(base + "/control/run", "POST", {**good, "X-AgentTrustSec-Token": "guess"})[0] == 403
    tok = token(base)
    assert req(base + "/control/run", "POST", {"Origin": "https://evil.example", "X-AgentTrustSec-Token": tok})[0] == 403
    assert req(base + "/control/run", "POST", {"Origin": f"https://127.0.0.1:{port}", "X-AgentTrustSec-Token": tok})[0] == 403
    assert calls == []                                                                 # nothing ran
    gate.set()
    code, _, body = req(base + "/control/run", "POST", {**good, "X-AgentTrustSec-Token": tok})
    assert code == 200 and calls == [1] and json.loads(body)["probes_ran_at"] == "2026-10-23T17:00:00+00:00"


def test_only_one_probe_run_at_a_time(server):
    base, port, gate, calls = server
    hdr = {"Origin": f"http://localhost:{port}", "X-AgentTrustSec-Token": token(base)}
    first = threading.Thread(target=req, args=(base + "/control/run", "POST", hdr))
    first.start()
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    assert req(base + "/control/run", "POST", hdr)[0] == 409
    gate.set()
    first.join(10)


def test_token_differs_per_server_launch(run_dir):
    a, b = (dashboard.make_server(run_dir, 0, probe=dict) for _ in range(2))
    try:
        for s in (a, b):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        ta, tb = (token(f"http://127.0.0.1:{s.server_address[1]}") for s in (a, b))
        assert ta != tb and len(ta) >= 40
    finally:
        for s in (a, b):
            s.shutdown()
            s.server_close()


# --- live ------------------------------------------------------------------------------------

def test_every_probe_passes_on_the_live_lab():
    from agenttrustsec import demo_live
    missing = demo_live.preflight()
    if missing:
        pytest.skip(f"needs the live lab: {missing}")
    probes = cc.probe_in_child()["probes"]
    assert {p: v["ok"] for p, v in probes.items()} == {p: True for p in cc.PROBE_LABELS}, probes
