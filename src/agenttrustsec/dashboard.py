"""Decisions dashboard (P6b): one self-contained HTML page built from the audit trails.

TrustSec analogy: ISE Live Logs + the authorization dashboard, offline. Reads every *.jsonl in
an audit directory (gateway decisions, intake's group admissions, each agent's dispatch log) and a
demo run's results.json, and writes ONE HTML file with the data embedded — no server, no CDN, no
external libraries. Filter by source / agent / tool / verdict / blocking check, click a row for
every check with its reason and time.

    python -m agenttrustsec.dashboard                       # latest audit/demo-*/ -> its dashboard.html
    python -m agenttrustsec.dashboard audit/demo-XXXX -o out.html
    python -m agenttrustsec.dashboard --serve [--port 8765] # live: re-reads the trails every 2 s
                                                            # + /control = Control Center (controlcenter.py)

--serve binds 127.0.0.1 only (stdlib http.server). Audit text is rendered as text, never HTML;
the audit never holds tokens or raw badges (models.Decision.to_audit_record).
"""
from __future__ import annotations

import argparse
import hmac
import json
import secrets
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "audit"
SOURCES = {"gateway": "gateway", "intake-group": "intake group", "reader": "reader dispatch",
           "executor": "executor dispatch", "reviewer": "reviewer group", "decisions": "gateway"}


def latest_run(audit: Path = AUDIT) -> Path:
    runs = sorted(p for p in audit.glob("demo-*") if p.is_dir())
    return runs[-1] if runs else audit


def names() -> dict[str, str]:
    """Agent metadata id -> lab name (public registry). Empty if the registry can't be read."""
    try:
        from agenttrustsec.demo_live import names as lab_names
        return lab_names()
    except Exception:  # noqa: BLE001 - names are cosmetic; ids still show
        return {}


def row(source: str, r: dict[str, Any], who: dict[str, str]) -> dict[str, Any]:
    blocked = r.get("blocked_by")
    bad = next((c for c in r.get("checks", []) if c.get("name") == blocked), None)
    return {
        "source": source, "ts": r.get("timestamp", ""), "agent_id": r.get("agent_id", ""),
        "agent": who.get(r.get("agent_id", ""), r.get("agent_id", "")),
        "verified": bool(r.get("verified_role")), "role": r.get("verified_role"),
        "tool": r.get("tool", ""), "verdict": r.get("verdict", ""), "blocked_by": blocked or "",
        "reason": (bad or {}).get("reason", ""), "intent": r.get("intent", ""),
        "session": r.get("session_id", ""), "prompt": r.get("user_prompt", ""),
        "elapsed_ms": r.get("elapsed_ms"),
        "checks": [{"name": c.get("name"), "status": c.get("status"), "reason": c.get("reason", ""),
                    "elapsed_ms": c.get("elapsed_ms")} for c in r.get("checks", [])],
    }


def collect(run_dir: Path) -> dict[str, Any]:
    who = names()
    rows, errors = [], []
    for path in sorted(run_dir.glob("*.jsonl")):
        source = SOURCES.get(path.stem, path.stem)
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(row(source, json.loads(line), who))
            except (ValueError, AttributeError) as e:
                errors.append(f"{path.name}:{i}: {e}")
    rows.sort(key=lambda x: x["ts"])
    results = None
    if (run_dir / "results.json").exists():
        results = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    return {"run": str(run_dir), "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "rows": rows, "results": results, "errors": errors}


def render(data: dict[str, Any], live: bool = False) -> str:
    payload = json.dumps({**data, "live": live}).replace("<", "\\u003c")   # safe inside <script>
    return PAGE.replace("/*DATA*/", payload)


CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; "
       "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def make_server(run_dir: Path, port: int, probe=None) -> ThreadingHTTPServer:
    """Live server, 127.0.0.1 only: / = decisions page, /data.json = fresh data, /control = Control
    Center, /control.json = its view, POST /control/run = read-only probes (controlcenter.py).

    Hardening (a web page in your browser must not drive or read this server): every request needs
    Host = 127.0.0.1 / localhost on this port (DNS rebinding); POST also needs a matching Origin and
    the per-launch random token embedded in the Control Center page (CSRF); no CORS; one probe run
    at a time; strict CSP, no framing. `probe` is injectable for tests."""
    from agenttrustsec import controlcenter
    token = secrets.token_urlsafe(32)
    state: dict[str, Any] = {"last": None}
    lock = threading.Lock()
    probe = probe or controlcenter.probe_in_child

    class Handler(BaseHTTPRequestHandler):
        def _origins(self) -> set[str]:
            p = self.server.server_address[1]
            return {f"127.0.0.1:{p}", f"localhost:{p}"}

        def _send(self, code: int, body: bytes, kind: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _refuse(self, code: int, why: str) -> None:
            self._send(code, json.dumps({"error": why}).encode(), "application/json")

        def _cc_view(self) -> dict[str, Any]:
            data = collect(run_dir) if run_dir.exists() else None
            return controlcenter.view(data, state["last"])

        def do_GET(self):  # noqa: N802 - http.server API
            if self.headers.get("Host") not in self._origins():
                return self._refuse(403, "bad Host")
            if self.path in ("/", "/index.html"):
                self._send(200, render(collect(run_dir), live=True).encode(), "text/html; charset=utf-8")
            elif self.path == "/data.json":
                self._send(200, json.dumps(collect(run_dir)).encode(), "application/json")
            elif self.path == "/control":
                self._send(200, controlcenter.render_page(self._cc_view(), token).encode(), "text/html; charset=utf-8")
            elif self.path == "/control.json":
                self._send(200, json.dumps(self._cc_view()).encode(), "application/json")
            else:
                self._refuse(404, "not found")

        def do_POST(self):  # noqa: N802 - http.server API
            if self.path != "/control/run":
                return self._refuse(404, "not found")
            origin = self.headers.get("Origin") or ""
            if (self.headers.get("Host") not in self._origins()
                    or origin.removeprefix("http://") not in self._origins() or not origin.startswith("http://")):
                return self._refuse(403, "bad Host or Origin")
            if not hmac.compare_digest(self.headers.get("X-AgentTrustSec-Token") or "", token):
                return self._refuse(403, "bad token")
            if not lock.acquire(blocking=False):
                return self._refuse(409, "a probe run is already in progress")
            try:
                state["last"] = probe()
            finally:
                lock.release()
            self._send(200, json.dumps(self._cc_view()).encode(), "application/json")

        def log_message(self, *a):  # quiet
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(run_dir: Path, port: int) -> None:
    httpd = make_server(run_dir, port)
    print(f"dashboard for {run_dir} at http://127.0.0.1:{port}/  ·  Control Center at "
          f"http://127.0.0.1:{port}/control  (Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir", nargs="?", type=Path, help="audit directory (default: latest audit/demo-*)")
    ap.add_argument("-o", "--out", type=Path, help="output HTML (default: <run_dir>/dashboard.html)")
    ap.add_argument("--serve", action="store_true", help="serve live on 127.0.0.1 instead of writing a file")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)
    run_dir = a.run_dir or latest_run()
    if not run_dir.is_dir():
        ap.error(f"{run_dir} is not a directory")
    if a.serve:
        serve(run_dir, a.port)
        return 0
    data = collect(run_dir)
    out = a.out or run_dir / "dashboard.html"
    out.write_text(render(data), encoding="utf-8")
    print(f"{len(data['rows'])} decisions from {run_dir} -> {out}")
    return 0


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentTrustSec Decisions</title>
<style>
:root {
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --bar: #2a78d6; --good: #0ca30c; --good-text: #006300; --critical: #d03b3b; --critical-text: #b12f2f;
  --wash: rgba(42,120,214,0.08);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --bar: #5598e7; --good: #0ca30c; --good-text: #0ca30c; --critical: #d03b3b; --critical-text: #ec6a6a;
    --wash: rgba(85,152,231,0.12);
  }
}
:root[data-theme="dark"] {
  --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --bar: #5598e7; --good: #0ca30c; --good-text: #0ca30c; --critical: #d03b3b; --critical-text: #ec6a6a;
  --wash: rgba(85,152,231,0.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1280px; margin: 0 auto; padding: 24px 16px 48px; }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; margin-bottom: 16px; }
h1 { font-size: 20px; margin: 0; } h2 { font-size: 15px; margin: 0 0 10px; }
.sub { color: var(--ink-2); font-size: 12px; overflow-wrap: anywhere; }
.live { color: var(--good-text); font-weight: 600; }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 16px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 12px; }
.tile .k { color: var(--ink-2); font-size: 12px; } .tile .v { font-size: 28px; font-weight: 650; font-variant-numeric: tabular-nums; }
.tile .d { color: var(--muted); font-size: 12px; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; margin-bottom: 12px; }
.pill { display: inline-flex; align-items: center; gap: 4px; font-weight: 600; font-size: 12px; white-space: nowrap; }
.pill .dot { width: 8px; height: 8px; border-radius: 50%; }
.allow { color: var(--good-text); } .allow .dot { background: var(--good); }
.block { color: var(--critical-text); } .block .dot { background: var(--critical); }
.other { color: var(--ink-2); } .other .dot { background: var(--muted); }
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
select, input { font: inherit; color: var(--ink); background: var(--surface); border: 1px solid var(--axis);
  border-radius: 6px; padding: 5px 8px; min-width: 0; }
input[type=search] { flex: 1 1 180px; }
button { font: inherit; color: var(--ink-2); background: transparent; border: 1px solid var(--axis); border-radius: 6px; padding: 5px 10px; cursor: pointer; }
.tablewrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px; padding: 6px 8px; border-bottom: 1px solid var(--axis); white-space: nowrap; }
td { padding: 6px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }
tr.r { cursor: pointer; } tr.r:hover { background: var(--wash); }
tr.r:focus-visible { outline: 2px solid var(--bar); outline-offset: -2px; }
td.reason { color: var(--ink-2); max-width: 520px; }
td.num { text-align: right; white-space: nowrap; }
.mono { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; }
tr.x td { background: var(--wash); }
.checks td { border: none; padding: 3px 8px; }
.unv { color: var(--critical-text); font-weight: 700; }
.legend { color: var(--muted); font-size: 12px; margin-top: 8px; }
.bars { display: grid; grid-template-columns: max-content 1fr max-content; gap: 6px 10px; align-items: center; }
.bars .lbl { color: var(--ink-2); font-size: 12px; }
.bars .track { height: 14px; position: relative; }
.bars .fill { height: 100%; background: var(--bar); border-radius: 0 4px 4px 0; min-width: 2px; }
.bars .val { font-size: 12px; font-variant-numeric: tabular-nums; }
.bars .hit { cursor: default; }
.bars .hit:hover .fill { filter: brightness(1.15); }
#tip { position: fixed; pointer-events: none; background: var(--surface); color: var(--ink); border: 1px solid var(--ring);
  border-radius: 6px; padding: 6px 8px; font-size: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.15); display: none; z-index: 10; }
.empty { color: var(--muted); padding: 12px 0; }
@media (max-width: 640px) { .hide-sm { display: none; } }
</style>
</head>
<body>
<main>
  <header>
    <h1>AgentTrustSec decisions</h1>
    <span class="sub" id="meta"></span>
    <span style="flex:1"></span>
    <nav id="nav" aria-label="Views" hidden style="gap:6px"><a href="./" aria-current="page"
      style="color:var(--ink);text-decoration:none;border:1px solid var(--ink-2);border-radius:6px;padding:5px 10px;font-size:13px;font-weight:600">Decisions</a><a href="control"
      style="color:var(--ink-2);text-decoration:none;border:1px solid var(--axis);border-radius:6px;padding:5px 10px;font-size:13px">Control Center</a></nav>
    <button id="theme" type="button" aria-label="Toggle light or dark theme">Theme</button>
  </header>
  <section class="tiles" id="tiles"></section>
  <section class="grid2">
    <div class="card"><h2>Blocks by check</h2><div id="byCheck"></div></div>
    <div class="card"><h2>Decision time (gate, all checks)</h2><div id="latency"></div>
      <div class="legend">Per-check p50 / p95 are in each row's details and in eval/results/p6a-latency.md.</div></div>
  </section>
  <section class="card" id="storyCard" style="margin-bottom:12px; display:none">
    <h2>Demo story: expected vs actual</h2>
    <div class="tablewrap"><table id="story"></table></div>
  </section>
  <section class="card">
    <h2>Live log</h2>
    <div class="filters" id="filters">
      <select id="f-source" aria-label="Source"></select>
      <select id="f-agent" aria-label="Agent"></select>
      <select id="f-tool" aria-label="Tool"></select>
      <select id="f-verdict" aria-label="Verdict"></select>
      <select id="f-by" aria-label="Blocked by"></select>
      <input type="search" id="f-q" placeholder="Search reason, prompt, session" aria-label="Search">
      <button type="button" id="f-clear">Clear</button>
    </div>
    <div class="tablewrap"><table id="log"></table></div>
    <div class="legend"><span class="unv">*</span> claimed identity, never verified (badge or peer failed): the name is only what the caller said. Times are UTC.</div>
  </section>
</main>
<div id="tip" role="tooltip"></div>
<script type="application/json" id="data">/*DATA*/</script>
<script>
(function () {
  "use strict";
  let DATA = JSON.parse(document.getElementById("data").textContent);
  const $ = (id) => document.getElementById(id);
  const open = new Set();
  const FILTERS = [["f-source", "source", "All sources"], ["f-agent", "agent", "All agents"],
                   ["f-tool", "tool", "All tools"], ["f-verdict", "verdict", "All verdicts"],
                   ["f-by", "blocked_by", "Any blocking check"]];

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v);
    }
    for (const k of kids) if (k != null) n.append(k);
    return n;
  }
  function ms(v) {
    if (v == null) return "–";
    return v >= 1000 ? (v / 1000).toFixed(2) + " s" : v < 10 ? v.toFixed(2) + " ms" : Math.round(v) + " ms";
  }
  function verdictPill(v) {
    const cls = v === "ALLOW" ? "allow" : v === "BLOCK" ? "block" : "other";
    const icon = v === "ALLOW" ? "✓" : v === "BLOCK" ? "✕" : "•";
    return el("span", {class: "pill " + cls}, el("span", {class: "dot", "aria-hidden": "true"}),
              el("span", {text: icon + " " + (v || "—")}));
  }
  function statusPill(s) {
    const bad = s === "FAIL" || s === "ERROR";
    const cls = s === "PASS" ? "allow" : bad ? "block" : "other";
    const icon = s === "PASS" ? "✓" : bad ? "✕" : "–";
    return el("span", {class: "pill " + cls}, el("span", {class: "dot", "aria-hidden": "true"}),
              el("span", {text: icon + " " + s}));
  }

  // ---- tooltip ----
  const tip = $("tip");
  function showTip(e, text) { tip.textContent = text; tip.style.display = "block"; moveTip(e); }
  function moveTip(e) {
    const x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + "px"; tip.style.top = (e.clientY + 14) + "px";
  }
  function hideTip() { tip.style.display = "none"; }

  // ---- bars (single series, horizontal) ----
  function bars(target, items, unit) {
    target.replaceChildren();
    if (!items.length) { target.append(el("div", {class: "empty", text: "No data."})); return; }
    const max = Math.max(...items.map((i) => i.value), 1);
    const g = el("div", {class: "bars", role: "table", "aria-label": target.id});
    for (const it of items) {
      const fill = el("div", {class: "fill"});
      fill.style.width = (100 * it.value / max) + "%";
      if (!it.value) fill.style.minWidth = "0";          // an empty bucket draws nothing
      const track = el("div", {class: "track hit", role: "cell"}, fill);
      const text = it.label + ": " + it.value + " " + unit + (it.note ? " — " + it.note : "");
      track.addEventListener("mouseenter", (e) => showTip(e, text));
      track.addEventListener("mousemove", moveTip);
      track.addEventListener("mouseleave", hideTip);
      g.append(el("div", {class: "lbl", role: "rowheader", text: it.label}), track,
               el("div", {class: "val", role: "cell", text: String(it.value)}));
    }
    target.append(g);
  }

  function tiles(rows) {
    const t = $("tiles"); t.replaceChildren();
    const allow = rows.filter((r) => r.verdict === "ALLOW").length;
    const block = rows.filter((r) => r.verdict === "BLOCK").length;
    const unv = rows.filter((r) => r.verdict === "BLOCK" && !r.verified).length;
    const add = (k, v, d) => t.append(el("div", {class: "card tile"}, el("div", {class: "k", text: k}),
                                         el("div", {class: "v", text: v}), el("div", {class: "d", text: d || ""})));
    add("Decisions", String(rows.length), "every call, admission and dispatch");
    add("Allowed", String(allow), rows.length ? Math.round(100 * allow / rows.length) + "% of decisions" : "");
    add("Blocked", String(block), unv + " from unverified identities");
    const res = DATA.results;
    if (res) {
      const ran = res.filter((r) => r.ok !== null);
      add("Demo story", ran.filter((r) => r.ok).length + " / " + ran.length,
          "steps as expected" + (res.length > ran.length ? " (" + (res.length - ran.length) + " skipped)" : ""));
    }
  }

  function byCheck(rows) {
    const c = {};
    for (const r of rows) if (r.verdict === "BLOCK") c[r.blocked_by || "?"] = (c[r.blocked_by || "?"] || 0) + 1;
    const order = ["badge", "peer", "tbac", "intent", "approval", "caller", "group", "session", "server_badge"];
    const rank = (k) => (order.includes(k) ? order.indexOf(k) : order.length);   // gate order, unknown last
    const items = Object.entries(c).map(([k, v]) => ({label: k, value: v}))
      .sort((a, b) => rank(a.label) - rank(b.label) || a.label.localeCompare(b.label));
    bars($("byCheck"), items, "blocks");
  }

  function latency(rows) {
    const edges = [[0, 1, "< 1 ms"], [1, 10, "1–10 ms"], [10, 100, "10–100 ms"], [100, 1000, "0.1–1 s"],
                   [1000, 10000, "1–10 s"], [10000, Infinity, "≥ 10 s"]];
    const timed = rows.filter((r) => r.elapsed_ms != null);
    const items = edges.map(([lo, hi, label]) => {
      const n = timed.filter((r) => r.elapsed_ms >= lo && r.elapsed_ms < hi);
      const tools = [...new Set(n.map((r) => r.tool))].slice(0, 4).join(", ");
      return {label, value: n.length, note: tools};
    });
    bars($("latency"), timed.length ? items : [], "decisions");
  }

  function story() {
    const res = DATA.results, card = $("storyCard"), t = $("story");
    if (!res) { card.style.display = "none"; return; }
    card.style.display = "";
    t.replaceChildren(el("thead", {}, el("tr", {}, ...["", "Act", "Step", "Expected", "Got", "Reason"]
      .map((h, i) => el("th", {class: i === 5 ? "hide-sm" : "", text: h})))));
    const body = el("tbody");
    for (const r of res) {
      const mark = r.ok === null ? "–" : r.ok ? "✓" : "✕";
      body.append(el("tr", {},
        el("td", {class: r.ok === false ? "block" : r.ok ? "allow" : "other", text: mark,
                  "aria-label": r.ok === null ? "skipped" : r.ok ? "as expected" : "mismatch"}),
        el("td", {text: r.act}), el("td", {text: r.label}),
        el("td", {}, verdictPill(r.expect), el("span", {class: "mono", text: " " + (r.expect_by === "-" ? "" : r.expect_by)})),
        el("td", {}, r.verdict ? verdictPill(r.verdict) : el("span", {class: "other", text: "skipped"}),
                  el("span", {class: "mono", text: " " + (r.by && r.by !== "-" ? r.by : "")})),
        el("td", {class: "reason hide-sm", text: r.reason || ""})));
    }
    t.append(body);
  }

  function options() {
    for (const [id, key, all] of FILTERS) {
      const sel = $(id), cur = sel.value;
      const vals = [...new Set(DATA.rows.map((r) => r[key]).filter((v) => v))].sort();
      sel.replaceChildren(el("option", {value: "", text: all}), ...vals.map((v) => el("option", {value: v, text: v})));
      sel.value = vals.includes(cur) ? cur : "";
    }
  }

  function filtered() {
    const q = $("f-q").value.trim().toLowerCase();
    return DATA.rows.filter((r) => FILTERS.every(([id, key]) => !$(id).value || r[key] === $(id).value) &&
      (!q || [r.reason, r.prompt, r.session, r.agent, r.tool].join(" ").toLowerCase().includes(q)));
  }

  function log() {
    const rows = filtered(), t = $("log");
    t.replaceChildren(el("thead", {}, el("tr", {}, ...[["Time", ""], ["Source", "hide-sm"], ["Agent", ""],
      ["Tool", ""], ["Verdict", ""], ["Blocked by", ""], ["Reason", "hide-sm"], ["Time taken", "num"]]
      .map(([h, c]) => el("th", {class: c, text: h})))));
    const body = el("tbody");
    if (!rows.length) body.append(el("tr", {}, el("td", {colspan: "8", class: "empty", text: "No decisions match."})));
    rows.slice().reverse().forEach((r) => {
      const key = r.source + r.ts + r.tool + r.agent_id;
      const tr = el("tr", {class: "r", tabindex: "0", "aria-expanded": String(open.has(key))},
        el("td", {class: "mono", text: (r.ts || "").slice(11, 19)}),
        el("td", {class: "hide-sm", text: r.source}),
        el("td", {}, el("span", {text: r.agent}), r.verified ? null : el("span", {class: "unv", text: "*", title: "claimed identity, never verified"})),
        el("td", {class: "mono", text: r.tool}),
        el("td", {}, verdictPill(r.verdict)),
        el("td", {class: "mono", text: r.blocked_by || "–"}),
        el("td", {class: "reason hide-sm", text: r.reason}),
        el("td", {class: "num", text: ms(r.elapsed_ms)}));
      const toggle = () => { open.has(key) ? open.delete(key) : open.add(key); log(); };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      body.append(tr);
      if (open.has(key)) {
        const inner = el("table", {class: "checks"});
        inner.append(el("tr", {}, el("td", {colspan: "3", class: "sub",
          text: "intent " + (r.intent || "–") + " · session " + (r.session || "–") + " · role " + (r.role || "unverified") +
                (r.prompt ? " · request: " + r.prompt : "")})));
        for (const c of r.checks) inner.append(el("tr", {}, el("td", {}, statusPill(c.status)),
          el("td", {class: "mono", text: c.name}), el("td", {class: "reason", text: c.reason + "  (" + ms(c.elapsed_ms) + ")"})));
        body.append(el("tr", {class: "x"}, el("td", {colspan: "8"}, inner)));
      }
    });
    t.append(body);
  }

  function renderAll() {
    $("meta").replaceChildren(...[el("span", {text: DATA.rows.length + " decisions · " + DATA.run + " · built " + DATA.generated}),
      DATA.live ? el("span", {class: "live", text: "  ● live"}) : null,
      DATA.errors && DATA.errors.length ? el("span", {class: "block", text: "  " + DATA.errors.length + " unreadable lines"}) : null]
      .filter(Boolean));
    options(); tiles(DATA.rows); byCheck(DATA.rows); latency(DATA.rows); story(); log();
  }

  for (const [id] of FILTERS) $(id).addEventListener("change", log);
  $("f-q").addEventListener("input", log);
  $("f-clear").addEventListener("click", () => { for (const [id] of FILTERS) $(id).value = ""; $("f-q").value = ""; log(); });
  $("theme").addEventListener("click", () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
  });
  renderAll();
  if (DATA.live) { const nav = $("nav"); nav.hidden = false; nav.style.display = "flex"; }   // /control exists only when served
  if (DATA.live) setInterval(() => {
    fetch("data.json", {cache: "no-store"}).then((r) => r.json()).then((d) => { DATA = {...d, live: true}; renderAll(); })
      .catch(() => {});
  }, 2000);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
