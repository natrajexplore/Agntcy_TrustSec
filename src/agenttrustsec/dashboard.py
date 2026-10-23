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
  /* navy (default) - contrast-checked: every text pair >= 4.5:1, every mark >= 3:1 */
  --page: #07182D; --surface: #0C2140; --surface-2: #0F2A4F; --ink: #F4F7FB; --ink-2: #C2CCDA; --muted: #94A3B8;
  --grid: #18355C; --axis: #24466F; --ring: rgba(255,255,255,0.10);
  --bar: #3A8DFF; --accent: #0A60FF; --accent-text: #6CB2FF;
  --good: #22C55E; --good-text: #4ADE80; --critical: #F05252; --critical-text: #FF8A8A;
  --warn: #F59E0B; --warn-text: #FBBF4C; --wash: rgba(58,141,255,0.10);
  --shadow: 0 1px 2px rgba(0,0,0,.25), 0 8px 24px rgba(0,0,0,.18);
  color-scheme: dark;
}
:root[data-theme="light"] {
  --page: #F5F7FA; --surface: #FFFFFF; --surface-2: #F0F3F8; --ink: #07182D; --ink-2: #3D4B61; --muted: #5E6B7E;
  --grid: #E3E8EF; --axis: #CBD3DF; --ring: rgba(7,24,45,0.10);
  --bar: #0A60FF; --accent: #0A60FF; --accent-text: #0A57E8;
  --good: #1E9E52; --good-text: #13703A; --critical: #D92D20; --critical-text: #B42318;
  --warn: #B76E00; --warn-text: #8A5300; --wash: rgba(10,96,255,0.06);
  --shadow: 0 1px 2px rgba(7,24,45,.06), 0 8px 24px rgba(7,24,45,.06);
  color-scheme: light;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink); -webkit-font-smoothing: antialiased;
  font: 14px/1.5 Inter, "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 24px; }
main { max-width: 1280px; margin: 0 auto; padding: 28px 24px 56px; }
@media (max-width: 640px) { .wrap, main { padding-left: 16px; padding-right: 16px; } }

/* top bar + hero: always navy, the brand frame in both themes */
.topbar { background: #061426; border-bottom: 1px solid rgba(255,255,255,.08); color: #F4F7FB; }
.topbar .wrap { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 18px; min-height: 60px; padding-top: 8px; padding-bottom: 8px; }
.brand { display: inline-flex; align-items: center; gap: 10px; font-weight: 600; font-size: 16px; letter-spacing: -.01em; color: #fff; }
.mark { flex: none; display: block; }
.tagline { color: #94A3B8; font-size: 12px; }
.grow { flex: 1; }
.tabs[hidden] { display: none; }
.tabs { display: inline-flex; gap: 2px; padding: 3px; border-radius: 999px; background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.10); }
.tabs a { color: #C2CCDA; text-decoration: none; font-size: 13px; font-weight: 500; padding: 6px 14px; border-radius: 999px; }
.tabs a:hover { color: #fff; background: rgba(255,255,255,.06); }
.tabs a[aria-current="page"] { color: #07182D; background: #F4F7FB; }
.tabs a:focus-visible, .btn:focus-visible, button:focus-visible { outline: 2px solid #6CB2FF; outline-offset: 2px; }
.hero { color: #F4F7FB; border-bottom: 1px solid rgba(255,255,255,.06);
  background: radial-gradient(900px 340px at 88% -20%, rgba(58,141,255,.30), transparent 65%),
              radial-gradient(700px 300px at -5% 120%, rgba(10,96,255,.22), transparent 60%), #07182D; }
.hero .wrap { padding-top: 36px; padding-bottom: 32px; }
.eyebrow { color: #6CB2FF; font-size: 12px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
.hero h1 { font-size: clamp(28px, 4vw, 44px); line-height: 1.12; font-weight: 300; letter-spacing: -.02em; margin: 8px 0 10px; color: #fff; }
.hero .sub { color: #C2CCDA; }
.hero .tiles { margin: 26px 0 0; }
.hero .tile { background: rgba(255,255,255,.03); border: 1px solid rgba(255,255,255,.08); border-left: 2px solid #3A8DFF;
  border-radius: 10px; box-shadow: none; padding: 14px 16px; }
.hero .tile .k { color: #C2CCDA; } .hero .tile .d { color: #94A3B8; }
.hero .tile .v { color: #fff; font-size: 36px; font-weight: 300; letter-spacing: -.02em; }

h1 { font-size: 20px; margin: 0; } h2 { font-size: 16px; font-weight: 600; letter-spacing: -.01em; margin: 0 0 12px; }
.sub { color: var(--ink-2); font-size: 12px; overflow-wrap: anywhere; }
.live { color: #4ADE80; font-weight: 600; }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 18px; box-shadow: var(--shadow); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 14px; }
.tile .k { color: var(--ink-2); font-size: 12px; font-weight: 500; } .tile .v { font-size: 30px; font-weight: 600; font-variant-numeric: tabular-nums; }
.tile .d { color: var(--muted); font-size: 12px; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(340px, 100%), 1fr)); gap: 14px; margin-bottom: 14px; }
.pill { display: inline-flex; align-items: center; gap: 5px; font-weight: 600; font-size: 12px; white-space: nowrap; }
.pill .dot { width: 8px; height: 8px; border-radius: 50%; }
.allow { color: var(--good-text); } .allow .dot { background: var(--good); }
.block { color: var(--critical-text); } .block .dot { background: var(--critical); }
.other { color: var(--ink-2); } .other .dot { background: var(--muted); }
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
select, input { font: inherit; color: var(--ink); background: var(--surface-2); border: 1px solid var(--axis);
  border-radius: 999px; padding: 6px 12px; min-width: 0; }
select:focus-visible, input:focus-visible { outline: 2px solid var(--bar); outline-offset: 1px; }
input[type=search] { flex: 1 1 200px; }
button, .btn { font: inherit; font-size: 13px; font-weight: 500; color: var(--ink); background: transparent; border: 1px solid var(--axis);
  border-radius: 999px; padding: 7px 16px; cursor: pointer; }
button:hover { border-color: var(--ink-2); }
.topbar button { color: #F4F7FB; border-color: rgba(255,255,255,.22); }
.topbar button:hover { border-color: rgba(255,255,255,.5); }
button.primary { color: #fff; background: var(--accent); border-color: var(--accent); font-weight: 600; }
button.primary:hover { filter: brightness(1.1); }
.tablewrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
  padding: 8px 10px; border-bottom: 1px solid var(--axis); white-space: nowrap; }
td { padding: 9px 10px; border-bottom: 1px solid var(--grid); vertical-align: top; }
tr.r { cursor: pointer; } tr.r:hover { background: var(--wash); }
tr.r:focus-visible { outline: 2px solid var(--bar); outline-offset: -2px; }
td.reason { color: var(--ink-2); max-width: 520px; }
td.num { text-align: right; white-space: nowrap; }
.mono { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; }
tr.x td { background: var(--wash); }
.checks td { border: none; padding: 3px 8px; }
.unv { color: var(--critical-text); font-weight: 700; }
.legend { color: var(--muted); font-size: 12px; margin-top: 10px; }
.bars { display: grid; grid-template-columns: max-content 1fr max-content; gap: 8px 12px; align-items: center; }
.bars .lbl { color: var(--ink-2); font-size: 12px; }
.bars .track { height: 14px; position: relative; }
.bars .fill { height: 100%; background: var(--bar); border-radius: 0 4px 4px 0; min-width: 2px; }
.bars .val { font-size: 12px; font-variant-numeric: tabular-nums; }
.bars .hit { cursor: default; }
.bars .hit:hover .fill { filter: brightness(1.15); }
#tip { position: fixed; pointer-events: none; background: var(--surface-2); color: var(--ink); border: 1px solid var(--ring);
  border-radius: 8px; padding: 6px 10px; font-size: 12px; box-shadow: var(--shadow); display: none; z-index: 10; }
.empty { color: var(--muted); padding: 12px 0; }
.foot { color: var(--muted); font-size: 12px; border-top: 1px solid var(--grid); margin-top: 28px; padding-top: 16px; }
@media (max-width: 640px) { .hide-sm { display: none; } .tagline { display: none; } }
</style>
</head>
<body>
<div class="topbar"><div class="wrap">
  <span class="brand"><svg class="mark" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><defs><linearGradient id="mk" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3A8DFF"/><stop offset="1" stop-color="#0A60FF"/></linearGradient></defs><path d="M12 2.5 4 5.6v6.1c0 4.6 3.3 8.6 8 9.8 4.7-1.2 8-5.2 8-9.8V5.6L12 2.5Z" fill="url(#mk)"/><path d="m8.4 12.2 2.6 2.6 4.8-5.1" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>AgentTrustSec</span>
  <span class="tagline">Zero-trust for AI agents · lab</span>
  <span class="grow"></span>
  <nav class="tabs" id="nav" aria-label="Views" hidden><a href="./" aria-current="page">Decisions</a><a href="control">Control Center</a></nav>
  <button id="theme" type="button" aria-label="Toggle light or dark theme">Theme</button>
</div></div>
<section class="hero"><div class="wrap">
  <div class="eyebrow">Decisions</div>
  <h1>Every call, admission and dispatch</h1>
  <div class="sub" id="meta"></div>
  <section class="tiles" id="tiles"></section>
</div></section>
<main>
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
  $("theme").addEventListener("click", () => {      // navy is the default; light is one click away
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("ats-theme", root.dataset.theme); } catch (e) { /* storage blocked: fine */ }
  });
  try { const t = localStorage.getItem("ats-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }
  renderAll();
  if (DATA.live) $("nav").hidden = false;   // /control exists only when served
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
