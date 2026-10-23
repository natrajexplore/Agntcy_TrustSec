"""P6b: the decisions dashboard — data collection, safe embedding, file output, live server."""
import json
import threading
import urllib.request

import pytest

from agenttrustsec import dashboard

GATE = {"timestamp": "2026-10-23T07:32:39+00:00", "agent_id": "AGNTCY-x", "tool": "show_acl",
        "verdict": "BLOCK", "blocked_by": "peer", "verified_role": None, "intent": "read",
        "session_id": "s1", "user_prompt": "Audit </script><img src=x onerror=alert(1)> edge-fw-01",
        "elapsed_ms": 61.0, "checks": [
            {"name": "badge", "status": "PASS", "reason": "verified", "elapsed_ms": 60.0},
            {"name": "peer", "status": "FAIL", "reason": "not the badge holder", "elapsed_ms": 1.0},
            {"name": "tbac", "status": "SKIPPED", "reason": "no verified role", "elapsed_ms": None}]}
JOIN = {"timestamp": "2026-10-23T07:33:10+00:00", "agent_id": "AGNTCY-r", "tool": "group.join",
        "verdict": "ALLOW", "blocked_by": None, "verified_role": "reviewer", "checks": []}


@pytest.fixture
def run_dir(tmp_path):
    (tmp_path / "gateway.jsonl").write_text(json.dumps(GATE) + "\n")
    (tmp_path / "intake-group.jsonl").write_text(json.dumps(JOIN) + "\nnot json\n")
    (tmp_path / "results.json").write_text(json.dumps([{"act": "1", "label": "#1 x", "expect": "BLOCK",
                                                        "expect_by": "peer", "verdict": "BLOCK", "by": "peer",
                                                        "reason": "r", "ok": True}]))
    return tmp_path


def test_collect_merges_sources_in_time_order(run_dir, monkeypatch):
    monkeypatch.setattr(dashboard, "names", lambda: {"AGNTCY-x": "reader-01"})
    d = dashboard.collect(run_dir)
    assert [r["source"] for r in d["rows"]] == ["gateway", "intake group"]
    gw = d["rows"][0]
    assert gw["agent"] == "reader-01" and gw["verified"] is False and gw["reason"] == "not the badge holder"
    assert [c["elapsed_ms"] for c in gw["checks"]] == [60.0, 1.0, None]
    assert d["results"][0]["ok"] is True
    assert d["errors"] == ["intake-group.jsonl:2: Expecting value: line 1 column 1 (char 0)"]


def test_audit_text_cannot_break_out_of_the_page(run_dir):
    html = dashboard.render(dashboard.collect(run_dir))
    data = html.split('<script type="application/json" id="data">', 1)[1].split("</script>", 1)[0]
    assert "<" not in data                                     # every '<' escaped inside the JSON
    assert json.loads(data)["rows"][0]["prompt"].startswith("Audit </script><img")   # still intact as data
    assert "innerHTML" not in html                             # audit text is rendered with textContent


def test_cli_writes_one_self_contained_file(run_dir, capsys):
    assert dashboard.main([str(run_dir)]) == 0
    html = (run_dir / "dashboard.html").read_text(encoding="utf-8")
    assert "http://" not in html.replace("http://127.0.0.1", "") and "https://" not in html   # no CDN
    assert "2 decisions" in capsys.readouterr().out


def test_latest_run_prefers_newest_demo_dir(tmp_path):
    (tmp_path / "demo-20261023-120000").mkdir()
    (tmp_path / "demo-20261023-130000").mkdir()
    assert dashboard.latest_run(tmp_path).name == "demo-20261023-130000"
    assert dashboard.latest_run(tmp_path / "demo-20261023-120000") == tmp_path / "demo-20261023-120000"


def test_live_server_serves_page_and_fresh_data_on_loopback(run_dir):
    httpd = dashboard.make_server(run_dir, 0)
    assert httpd.server_address[0] == "127.0.0.1"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + "/").read().decode()
        assert '"live": true' in page
        (run_dir / "gateway.jsonl").write_text(json.dumps(GATE) + "\n" + json.dumps(GATE) + "\n")
        data = json.loads(urllib.request.urlopen(base + "/data.json").read())
        assert len(data["rows"]) == 3                          # re-read on every request
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(base + "/../../etc/passwd")
    finally:
        httpd.shutdown()
        httpd.server_close()
