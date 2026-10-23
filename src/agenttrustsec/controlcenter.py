"""Control Center: is every security control working RIGHT NOW? (served at /control by the dashboard)

TrustSec analogy: the ISE dashboard's posture + Live Logs view, per enforcement layer. Each of the
11 layers (+ audit) shows a status backed by real evidence only:
  * audit evidence — the latest demo run's actual BLOCK / ALLOW records (dashboard.collect)
  * demo results   — expected vs actual for that layer (results.json)
  * read-only probes — for what the gate's audit can't show (mTLS admission, SLIM identity,
                       revocation, tool-inventory drift, replay store, the lines cross-check)
Deny by default in the UI too: a layer is Verified only when EVERY piece of its evidence is
present and good; anything missing is "Not verified", anything contradicting it is "Failing".

Probes only observe: they never change lab state (temp replay store, throwaway SLIM names,
fresh keys that are never enrolled). They run in a child process with a timeout
(`python -m agenttrustsec.controlcenter probe`) so the web server never loads SLIM.

    python -m agenttrustsec.controlcenter status [run dir]    # terminal view (runs the probes)
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
KEY_DIR = Path.home() / ".agenttrustsec" / "keys"
NODE_HTTP = "http://localhost:4000"
PROBE_TIMEOUT_S = 150
AGENTS = ("netops-mcp", "intake-01", "reader-01", "reviewer-01", "executor-01")


@dataclass(frozen=True)
class Rule:
    """Audit evidence: the newest row from `sources` with this verdict / blocking check."""
    label: str
    sources: tuple[str, ...]
    verdict: str
    blocked_by: str | None = None
    reason_has: str | None = None


@dataclass(frozen=True)
class Layer:
    id: str
    n: str
    name: str
    analogy: str
    stops: str
    where: tuple[str, ...]
    tests: tuple[str, ...]
    rules: tuple[Rule, ...] = ()
    demo: tuple[str, ...] = ()            # results.json expect_by values for this layer
    probes: tuple[str, ...] = ()


GW = ("gateway",)
LAYERS: tuple[Layer, ...] = (
    Layer("node", "1", "Node admission (mTLS)", "802.1X + MACsec on the uplink",
          "devices without a lab-CA cert, plaintext clients, foreign-CA certs",
          ("transport/tls.py", "lab/slim/pki.py"),
          ("test_unenrolled_device_is_refused_by_the_node", "test_plaintext_endpoint_is_refused",
           "test_cert_for_another_key_is_refused", "test_client_config_is_mtls_verified_tls13"),
          probes=("node_admission",)),
    Layer("slim", "2", "SLIM identity (JWT)", "EAP identity on the fabric",
          "app keys outside the trust set, even on an enrolled device",
          ("transport/slim.py", "policies/trust-jwks.json"),
          ("test_key_outside_trust_never_reaches_the_gate_even_on_an_enrolled_device",
           "test_agent_key_not_in_trust_jwks_cannot_reach_gateway"),
          probes=("slim_identity",)),
    Layer("badge", "3", "Badge", "machine cert + CRL / OCSP",
          "forged, unpublished, expired or revoked badges, incl. replayed pre-revocation copies",
          ("identity/agntcy.py",),
          ("test_published_status_must_be_proven", "test_no_unrevoked_badge_refused"),
          rules=(Rule("revoked agent blocked", GW, "BLOCK", "badge"),), demo=("badge",),
          probes=("badge_revocation",)),
    Layer("peer", "4", "Peer (key possession)", "EAP-TLS proof of private key",
          "copied badges and spoofed names: the transport identity must hold the badge-bound key",
          ("authz/peer.py",),
          ("test_gate_blocks_unbound_peer_and_drops_role", "test_gate_peer_error_blocks"),
          rules=(Rule("copied badge blocked", GW, "BLOCK", "peer"),), demo=("peer",)),
    Layer("tbac", "5", "TBAC", "SGT + SGACL matrix",
          "roles calling tools outside their job; targets not named in the request",
          ("authz/tbac.py", "policies/tbac.yaml"),
          ("test_genuine_reader_cannot_push_even_with_change_session_and_approval",
           "test_every_change_tool_requires_approval", "test_gate_blocks_t6_and_audits_scope_reason"),
          rules=(Rule("reader push blocked", GW, "BLOCK", "tbac"),), demo=("tbac",), probes=("policy",)),
    Layer("intent", "6", "Intent", "posture / context",
          "change tools in a read session; changes the user didn't ask for (local-LLM verdict)",
          ("authz/intent.py", "authz/semantic.py"),
          ("test_T5_executor_cannot_push_during_read_session", "test_T11_session_intent_cannot_be_upgraded",
           "test_legitimate_change_judged_by_local_llm"),
          rules=(Rule("push in a read session blocked", GW, "BLOCK", "intent"),), demo=("intent",),
          probes=("intent_offline",)),
    Layer("approval", "7", "Approval (single use)", "Change-of-Authorization after posture",
          "unreviewed pushes, other lines than approved, replay (also after a gateway restart)",
          ("authz/broker.py", "authz/replay.py"),
          ("test_approved_change_is_allowed_once", "test_B_used_approval_stays_used_across_a_gateway_restart",
           "test_E3_replayed_approval_is_blocked"),
          rules=(Rule("other lines blocked", GW, "BLOCK", "approval", "lines differ"),
                 Rule("replay blocked", GW, "BLOCK", "approval", "replay")),
          demo=("approval",), probes=("replay_store",)),
    Layer("review", "8", "Review cross-check", "change board signs off what is deployed",
          "config lines that don't implement the reviewed change request",
          ("review/render.py", "agents/reviewer.py"),
          ("test_reviewer_rejects_lines_that_do_not_implement_the_reviewed_change",
           "test_render_is_byte_identical_to_rulegate", "test_bad_change_orders_are_refused"),
          demo=("review",), probes=("review_crosscheck",)),
    Layer("server", "9", "Server trust (agent side)", "switch authenticating to ISE",
          "impostor gateways; gateways serving tools their badge doesn't sign",
          ("mcpgate/client.py", "mcpgate/inventory.py"),
          ("test_agent_rejects_gateway_holding_a_copied_badge", "test_gateway_refuses_to_start_with_a_drifted_badge",
           "test_agent_refuses_results_the_server_badge_does_not_vouch_for"),
          probes=("server_inventory",)),
    Layer("group", "10", "Group admission", "MACsec key agreement only with authenticated peers",
          "impostors joining the reviewer group, fake moderators, before any broadcast",
          ("transport/slim_group.py", "authz/groups.py"),
          ("test_q7_impostor_under_reviewer_name_removed_before_any_broadcast",
           "test_impostor_moderator_gets_no_attestation", "test_admission_refusals"),
          rules=(Rule("impostor refused admission", ("intake group",), "BLOCK", "peer"),), demo=("group/peer",)),
    Layer("caller", "11", "Caller gate", "who may send a CoA",
          "worker agents giving each other jobs (confused deputy)",
          ("agents/jobserver.py",),
          ("test_rogue_dispatch_to_executor_is_refused", "test_rogue_dispatch_to_reader_is_refused"),
          rules=(Rule("worker-to-worker job blocked", ("executor dispatch", "reader dispatch"), "BLOCK", "caller"),),
          demo=("caller",)),
    Layer("audit", "—", "Audit", "ISE Live Logs",
          "silent failures: one record per decision, every check, its reason and time",
          ("audit/log.py",),
          ("test_audit_record_shape_has_peer_not_token", "test_forwarded_session_token_is_never_audited")),
)


# --- evidence from the latest demo run ---------------------------------------------------------

def _item(kind: str, label: str, ok: bool | None, detail: str = "", ts: str = "") -> dict[str, Any]:
    return {"kind": kind, "label": label, "ok": ok, "detail": detail, "ts": ts}


def audit_items(layer: Layer, data: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = (data or {}).get("rows") or []
    out = []
    for r in layer.rules:
        hit = next((x for x in reversed(rows) if x["source"] in r.sources and x["verdict"] == r.verdict
                    and (r.blocked_by is None or x["blocked_by"] == r.blocked_by)
                    and (r.reason_has is None or r.reason_has in x["reason"])), None)
        out.append(_item("audit", r.label, True, f"{hit['source']}: {hit['tool']} {hit['verdict']} "
                                                 f"{hit['blocked_by']} — {hit['reason']}", hit["ts"])
                   if hit else _item("audit", r.label, None, "not in the latest run's audit trails"))
    if layer.id == "audit":
        out.append(_audit_shape(rows, (data or {}).get("errors") or []))
    return out


def _audit_shape(rows: list[dict[str, Any]], errors: list[str]) -> dict[str, Any]:
    if not rows:
        return _item("audit", "every record complete", None, "no audit records yet (run the live demo)")
    bad = [x for x in rows if x["verdict"] not in ("ALLOW", "BLOCK") or not x["checks"]
           or (x["verdict"] == "BLOCK" and not x["blocked_by"])]
    ok = not bad and not errors
    return _item("audit", "every record complete", ok,
                 f"{len(rows)} records, each with verdict + every check" if ok else
                 f"{len(bad)} incomplete record(s), {len(errors)} unreadable line(s)")


def demo_items(layer: Layer, data: dict[str, Any] | None) -> list[dict[str, Any]]:
    results = (data or {}).get("results") or []
    out = []
    for by in layer.demo:
        hits = [r for r in results if r.get("expect_by") == by]
        if not hits:
            out.append(_item("demo", f"demo: blocked by {by}", None, "no demo result for this layer"))
        for r in hits:
            out.append(_item("demo", r["label"], r.get("ok") is True,
                             f"expected {r['expect']} {r['expect_by']}, got {r['verdict']} {r['by']} — {r['reason']}"))
    return out


def probe_items(layer: Layer, probes: dict[str, Any] | None) -> list[dict[str, Any]]:
    out = []
    for pid in layer.probes:
        p = (probes or {}).get(pid)
        out.append(_item("probe", PROBE_LABELS[pid], None, "not run yet — use Run checks")
                   if p is None else _item("probe", PROBE_LABELS[pid], p["ok"], p["detail"]))
    return out


def status_of(items: list[dict[str, Any]]) -> str:
    if any(i["ok"] is False for i in items):
        return "failing"
    if items and all(i["ok"] is True for i in items):
        return "verified"
    return "not verified"


def layers_view(data: dict[str, Any] | None, probes: dict[str, Any] | None) -> list[dict[str, Any]]:
    out = []
    for layer in LAYERS:
        items = audit_items(layer, data) + demo_items(layer, data) + probe_items(layer, probes)
        out.append({"id": layer.id, "n": layer.n, "name": layer.name, "analogy": layer.analogy,
                    "stops": layer.stops, "where": list(layer.where), "tests": list(layer.tests),
                    "items": items, "status": status_of(items)})
    return out


# --- health ------------------------------------------------------------------------------------

def _up(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def _h(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _expiry(path: Path, what: str) -> dict[str, str]:
    from cryptography import x509
    if not path.exists():
        return _h(what, "fail", f"missing ({path.name}) — run lab/slim/pki.py")
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    left = cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)
    days = left.days
    status = "fail" if left.total_seconds() <= 0 else "warn" if days < 7 else "ok"
    return _h(what, status, f"expires {cert.not_valid_after_utc:%Y-%m-%d} ({days} days)")


def health(data: dict[str, Any] | None = None) -> list[dict[str, str]]:
    from agenttrustsec.transport import tls
    out = [_h(name, "ok" if _up(port) else "fail", f"127.0.0.1:{port}") for name, port in
           (("SLIM node", 46357), ("Identity Node HTTP", 4000), ("Identity Node gRPC", 4001))]
    try:
        from agenttrustsec.authz.semantic import OLLAMA_DIGEST, OLLAMA_MODEL
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as r:
            found = {m.get("name"): m.get("digest") for m in json.load(r).get("models", [])}
        out.append(_h("Ollama (pinned model)", "ok" if found.get(OLLAMA_MODEL) == OLLAMA_DIGEST else "fail",
                      f"{OLLAMA_MODEL} " + ("digest matches the pin" if found.get(OLLAMA_MODEL) == OLLAMA_DIGEST
                                            else "missing or digest differs from the pin")))
    except OSError:
        out.append(_h("Ollama (pinned model)", "fail", "not reachable on 127.0.0.1:11434"))
    d = tls.pki_dir()
    out.append(_expiry(d / "node" / "server.crt", "SLIM node certificate"))
    out.append(_expiry(d / "ca.crt", "Lab CA certificate"))
    enrolled = []
    for name in AGENTS:
        try:
            tls.client_cert((KEY_DIR / f"{name}.pem").read_text())
            enrolled.append(name)
        except (OSError, tls.NotEnrolled):
            pass
    out.append(_h("Agents enrolled for mTLS", "ok" if len(enrolled) == len(AGENTS) else "fail",
                  f"{len(enrolled)} / {len(AGENTS)}: {', '.join(enrolled) or 'none'}"))
    node_dir = d / "node"
    if not node_dir.exists():
        out.append(_h("CA private key kept out of the node mount", "fail", "node mount missing"))
    else:   # the only private key the node may see is its own server.key
        leaked = [p.name for p in node_dir.iterdir()
                  if p.is_file() and p.name != "server.key" and b"PRIVATE KEY" in p.read_bytes()]
        out.append(_h("CA private key kept out of the node mount", "fail" if leaked else "ok",
                      f"private key(s) in the node mount: {leaked}" if leaked
                      else "node mount holds only the node cert/key and the CA certificate"))
    results = (data or {}).get("results")
    if results is None:
        out.append(_h("Latest live demo", "warn", "no demo run yet — python -m agenttrustsec.demo_live"))
    else:
        ok = sum(1 for r in results if r.get("ok") is True)
        out.append(_h("Latest live demo", "ok" if ok == len(results) else "fail",
                      f"{ok} / {len(results)} steps as expected — {Path((data or {}).get('run', '')).name}"))
    return out


# --- read-only probes (child process) ----------------------------------------------------------

PROBE_LABELS = {
    "node_admission": "probe: plaintext + unenrolled refused, enrolled admitted",
    "slim_identity": "probe: untrusted app key dropped on an enrolled device",
    "badge_revocation": "probe: revoked badge + its replayed copy rejected",
    "policy": "probe: unknown tool and wrong role blocked; change tools need approval",
    "intent_offline": "probe: change tool in a read session blocked",
    "replay_store": "probe: second claim refused, also after a restart (temp store)",
    "review_crosscheck": "probe: tampered lines rejected, rendered lines approved",
    "server_inventory": "probe: gateway badge verifies and signs exactly the served tools",
}


def _key(name: str) -> str:
    return (KEY_DIR / f"{name}.pem").read_text()


def _lab_env() -> None:
    import os
    os.environ.setdefault("IDENTITY_NODE_GRPC_SERVER_URL", "localhost:4001")
    os.environ.setdefault("IDENTITY_NODE_USE_SSL", "0")


def _offline_gate(tmp: Path, approvals=None):
    import secrets

    from agenttrustsec.audit.log import AuditLog
    from agenttrustsec.authz.gate import Gate
    from agenttrustsec.authz.intent import BaselineIntentChecker
    from agenttrustsec.authz.tbac import TbacPolicy
    from agenttrustsec.identity.badge import LocalDevVerifier
    v = LocalDevVerifier(secrets.token_bytes(32))
    return v, Gate(v, TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml"), BaselineIntentChecker(),
                   AuditLog(tmp / "probe.jsonl"), approvals=approvals)


def probe_policy(tmp: Path) -> tuple[bool | None, str]:
    from agenttrustsec.authz.tbac import TbacPolicy
    from agenttrustsec.models import Intent, Session, ToolCall, Verdict
    policy = TbacPolicy.from_yaml(ROOT / "policies" / "tbac.yaml")
    change = [n for n, s in policy.tools.items() if s.change]
    unapproved = [n for n in change if not policy.spec(n).requires_approval]
    v, gate = _offline_gate(tmp)
    s = Session("Remove the permit ip any any rule from the ACL on edge-fw-01", Intent.CHANGE)
    unknown = gate.authorize(ToolCall("executor-01", v.issue("executor-01", "executor"), "format_disk", s,
                                      {"device": "edge-fw-01"}))
    reader = gate.authorize(ToolCall("reader-01", v.issue("reader-01", "reader"), "push_config", s,
                                     {"device": "edge-fw-01", "lines": ["x"]}))
    ok = (not unapproved and unknown.verdict is Verdict.BLOCK and unknown.blocked_by == "tbac"
          and reader.verdict is Verdict.BLOCK and reader.blocked_by == "tbac")
    return ok, (f"unknown tool -> BLOCK {unknown.blocked_by}; reader push_config -> BLOCK {reader.blocked_by}; "
                f"{len(change)} change tool(s), {len(unapproved)} without approval")


def probe_intent(tmp: Path) -> tuple[bool | None, str]:
    from agenttrustsec.models import Intent, Session, ToolCall, Verdict
    v, gate = _offline_gate(tmp)
    d = gate.authorize(ToolCall("executor-01", v.issue("executor-01", "executor"), "push_config",
                                Session("Audit the ACLs on edge-fw-01", Intent.READ),
                                {"device": "edge-fw-01", "lines": ["no permit ip any any"]}))
    return d.verdict is Verdict.BLOCK and d.blocked_by == "intent", f"executor push_config in a read session -> {d.verdict.value} {d.blocked_by}"


def probe_replay(tmp: Path) -> tuple[bool | None, str]:
    import secrets

    from agenttrustsec.authz.broker import TokenBroker, TokenError
    from agenttrustsec.authz.replay import SqliteJtiStore
    db, key = tmp / "jti.sqlite3", secrets.token_bytes(32)
    tok = TokenBroker(key).mint_approval("CR-PROBE", "edge-fw-01", ["x"], "s1", ["reviewer-01"])
    TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem_approval(tok, "edge-fw-01", ["x"], "s1")
    try:
        TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem_approval(tok, "edge-fw-01", ["x"], "s1")
    except TokenError as e:
        return "already used" in str(e), f"first use accepted; after a restart (new store instance): {e}"
    return False, "a used approval was accepted again after a restart"


def probe_review(tmp: Path) -> tuple[bool | None, str]:
    from agenttrustsec.agents import reviewer
    from agenttrustsec.agents.intake import load_change
    from agenttrustsec.authz.broker import lines_digest
    from agenttrustsec.demo_live import CR1001_REQ
    from agenttrustsec.review.engine import review_for_device, summary
    o = load_change(ROOT / "lab" / "changes" / "cr-1001.yaml", CR1001_REQ)
    s = summary(review_for_device(o.device, o.change))
    base = {"proposal_id": "probe", "change_id": o.change_id, "device": o.device, "change": o.change, "session": "x"}
    good = reviewer.verdict({**base, "lines": o.lines, "lines_digest": lines_digest(o.lines)}, s)
    bad_lines = ["set device-group DC-Core pre-rulebase security rules X action allow"]
    bad = reviewer.verdict({**base, "lines": bad_lines, "lines_digest": lines_digest(bad_lines)}, s)
    ok = good["approve"] is True and bad["approve"] is False and "do not implement" in bad["reason"]
    return ok, f"rendered {len(o.lines)} lines -> approve={good['approve']}; tampered lines -> {bad['reason']}"


def probe_badges(tmp: Path) -> tuple[bool | None, str]:
    if not (_up(4000) and _up(4001)):
        return None, "Identity Node not reachable"
    _lab_env()
    from agenttrustsec.agents.rogue import REVOKED, agent_id, current_badge
    from agenttrustsec.agents.runtime import IDENTITIES
    from agenttrustsec.identity.agntcy import AgntcyBadgeVerifier, load_key_thumbprints, load_role_map
    from agenttrustsec.identity.badge import BadgeError
    v = AgntcyBadgeVerifier(load_role_map(IDENTITIES, "agents"), key_thumbprints=load_key_thumbprints(IDENTITIES))
    reader = agent_id("reader-01")
    v.verify(current_badge(reader), reader)                                 # positive control
    refused = []
    for what, jose in (("published revoked copy", current_badge(REVOKED)),
                       ("replayed pre-revocation copy",
                        (ROOT / "tests" / "fixtures" / "revoke-test-01.original.jose").read_text().strip())):
        try:
            v.verify(jose, REVOKED)
        except BadgeError as e:
            if "revoked" in str(e):
                refused.append(what)
                continue
            return False, f"{what}: refused for another reason: {e}"
        return False, f"{what} was ACCEPTED"
    return True, f"reader-01 verifies; revoked agent refused: {', '.join(refused)}"


def probe_inventory(tmp: Path) -> tuple[bool | None, str]:
    if not _up(4000):
        return None, "Identity Node not reachable"
    _lab_env()
    import secrets

    import yaml

    from agenttrustsec.authz.broker import TokenBroker
    from agenttrustsec.mcpgate import inventory, serve
    from agenttrustsec.mcpgate.server import build_server
    b = TokenBroker(secrets.token_bytes(32))
    served = asyncio.run(inventory.served(build_server("netops-mcp", serve.make_gate(tmp / "gw.jsonl", None),
                                                       b, None, serve._registry(b))))
    gw = yaml.safe_load((ROOT / "lab" / "agents.yaml").read_text(encoding="utf-8"))["gateway"]["metadata_id"]
    serve.fetch_server_badge(NODE_HTTP, gw, served)                         # raises on drift / no badge
    extra = inventory.vouches_for(served, "push_config", {"device": "edge-fw-01", "lines": [], "evil": 1})
    return extra is not None, f"badge signs exactly the {len(served)} served tools; unsigned argument -> refused"


async def _node_admission() -> tuple[bool | None, str]:
    if not _up(46357):
        return None, "SLIM node not reachable"
    import slim_bindings as sb

    from agenttrustsec.agents import rogue
    from agenttrustsec.mcpgate.serve import TRUST_JWKS, load_trust_jwks
    from agenttrustsec.transport import slim
    trust, tag, pem = load_trust_jwks(TRUST_JWKS), uuid.uuid4().hex[:8], _key("reader-01")
    name = f"agenttrustsec/lab/cc-ok-{tag}"
    await slim.connect(name, slim.jwt_identity(pem, name, trust), key_pem=pem)      # must be admitted
    svc = slim._get_service()
    try:
        conn = await svc.connect_async(sb.new_insecure_client_config("http://127.0.0.1:46357"))
        plain = sb.Name.from_string(f"agenttrustsec/lab/cc-plain-{tag}")
        app = svc.create_app(plain, *slim.jwt_identity(pem, str(plain), trust))
        await app.subscribe_async(plain, conn)
        return False, "a PLAINTEXT client was admitted"
    except Exception as e:  # noqa: BLE001 - the expected outcome
        plain_err = "h2 protocol error" if "h2 protocol error" in str(e) else type(e).__name__
    try:
        rogue_name = f"agenttrustsec/lab/cc-rogue-{tag}"
        await rogue.rogue_connect(rogue_name, rogue.private_pem("__ephemeral__"), rogue_name, trust)
        return False, "an UNENROLLED device was admitted"
    except rogue.NodeRefused:
        pass
    return True, f"enrolled reader-01 admitted; plaintext refused ({plain_err}); unenrolled device refused at TLS"


async def _slim_identity() -> tuple[bool | None, str]:
    if not _up(46357):
        return None, "SLIM node not reachable"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from mcp import Client
    from mcp.server.mcpserver import MCPServer

    from agenttrustsec.identity.keys import public_jwk
    from agenttrustsec.transport import slim
    device = _key("reader-01")

    def keypair(kid):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode()
        return pem, {**public_jwk(k.public_key()), "kid": kid, "alg": "RS256", "use": "sig"}

    async def exchange(agent_pem, trust):
        tag = uuid.uuid4().hex[:8]
        gw_name, ag_name = f"agenttrustsec/lab/cc-gw-{tag}", f"agenttrustsec/lab/cc-ag-{tag}"
        gw_pem, gw_jwk = keypair("gw")
        trust = trust + [gw_jwk]
        server = MCPServer("echo")
        server.add_tool(lambda text: f"echo:{text}", name="echo")
        gw = await slim.connect(gw_name, slim.jwt_identity(gw_pem, gw_name, trust), key_pem=device)
        ag = await slim.connect(ag_name, slim.jwt_identity(agent_pem, ag_name, trust), key_pem=device)
        serving = asyncio.create_task(slim.serve_slim(server, gw))
        try:
            async with Client(slim.SlimClientTransport(ag, gw_name)) as c:
                return (await c.call_tool("echo", {"text": "hi"})).content[0].text
        finally:
            serving.cancel()

    trusted_pem, trusted_jwk = keypair("agent")
    if await exchange(trusted_pem, [trusted_jwk]) != "echo:hi":                      # positive control
        return False, "trusted app key could not complete an exchange"
    rogue_pem, _ = keypair("rogue")
    _, someone = keypair("someone-else")
    try:
        await exchange(rogue_pem, [someone])
        return False, "an UNTRUSTED app key completed an exchange"
    except Exception as e:  # noqa: BLE001 - SessionError: failed to add participant
        if "failed to add participant" not in str(e):
            return False, f"untrusted key failed for another reason: {str(e)[:120]}"
    return True, "trusted app key exchanges over MLS; untrusted app key dropped by SLIM (failed to add participant)"


SYNC_PROBES: dict[str, Callable[[Path], tuple[bool | None, str]]] = {
    "policy": probe_policy, "intent_offline": probe_intent, "replay_store": probe_replay,
    "review_crosscheck": probe_review, "badge_revocation": probe_badges, "server_inventory": probe_inventory,
}
ASYNC_PROBES = {"node_admission": _node_admission, "slim_identity": _slim_identity}


def run_probes() -> dict[str, Any]:
    """Every probe; an exception in a probe is a FAIL (fail closed), never a pass."""
    out: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as t:
        for pid, fn in SYNC_PROBES.items():
            t0 = time.perf_counter()
            try:
                ok, detail = fn(Path(t))
            except Exception as e:  # noqa: BLE001
                ok, detail = False, f"probe error: {type(e).__name__}: {str(e)[:160]}"
            out[pid] = {"ok": ok, "detail": detail, "ms": round((time.perf_counter() - t0) * 1000)}

    async def run_async():
        for pid, fn in ASYNC_PROBES.items():
            t0 = time.perf_counter()
            try:
                ok, detail = await asyncio.wait_for(fn(), 45)
            except Exception as e:  # noqa: BLE001
                ok, detail = False, f"probe error: {type(e).__name__}: {str(e)[:160]}"
            out[pid] = {"ok": ok, "detail": detail, "ms": round((time.perf_counter() - t0) * 1000)}
    try:
        import slim_bindings  # noqa: F401
        asyncio.run(run_async())
    except ImportError:
        for pid in ASYNC_PROBES:
            out[pid] = {"ok": None, "detail": "slim-bindings not installed", "ms": 0}
    return out


def probe_in_child(timeout_s: float = PROBE_TIMEOUT_S) -> dict[str, Any]:
    """Run the probes in a child process: the server never loads SLIM; a hang can't wedge it."""
    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        p = subprocess.run([sys.executable, "-m", "agenttrustsec.controlcenter", "probe"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout_s, cwd=ROOT)
        line = next((ln for ln in reversed(p.stdout.splitlines()) if ln.startswith("RESULT ")), None)
        probes = json.loads(line[7:]) if line else {
            pid: {"ok": False, "detail": f"probe process gave no result (exit {p.returncode})", "ms": 0}
            for pid in PROBE_LABELS}
    except subprocess.TimeoutExpired:
        probes = {pid: {"ok": False, "detail": f"probes timed out after {timeout_s:g}s", "ms": 0} for pid in PROBE_LABELS}
    return {"ran_at": started, "probes": probes}


# --- view for the page -------------------------------------------------------------------------

def view(data: dict[str, Any] | None, last: dict[str, Any] | None) -> dict[str, Any]:
    layers = layers_view(data, (last or {}).get("probes"))
    counts = {s: sum(1 for x in layers if x["status"] == s) for s in ("verified", "failing", "not verified")}
    return {"layers": layers, "health": health(data), "counts": counts, "total": len(layers),
            "probes_ran_at": (last or {}).get("ran_at"), "run": (data or {}).get("run"),
            "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["probe"]:
        print("RESULT " + json.dumps(run_probes()), flush=True)
        return 0
    if argv[:1] == ["status"]:
        from agenttrustsec import dashboard
        run_dir = Path(argv[1]) if len(argv) > 1 else dashboard.latest_run()
        v = view(dashboard.collect(run_dir) if run_dir.exists() else None, probe_in_child())
        for x in v["layers"]:
            print(f"{x['n']:>2}  {x['status']:<13} {x['name']}")
            for i in x["items"]:
                mark = {True: "✓", False: "✕", None: "·"}[i["ok"]]
                print(f"      {mark} {i['label']}: {i['detail'][:110]}")
        for h in v["health"]:
            print(f"health {h['status']:<4} {h['name']}: {h['detail']}")
        print(f"RESULT {v['counts']['verified']}/{v['total']} verified, {v['counts']['failing']} failing")
        return 1 if v["counts"]["failing"] else 0
    raise SystemExit("usage: python -m agenttrustsec.controlcenter status [run dir] | probe")


# --- page --------------------------------------------------------------------------------------

def render_page(v: dict[str, Any], token: str) -> str:
    """The Control Center page. Same design tokens as the decisions dashboard (its stylesheet is
    reused); data and the per-launch POST token are embedded as JSON, rendered as text only."""
    from agenttrustsec import dashboard
    css = dashboard.PAGE.split("<style>", 1)[1].split("</style>", 1)[0]
    payload = json.dumps({"view": v, "token": token}).replace("<", "\\u003c")
    return PAGE.replace("/*CSS*/", css).replace("/*DATA*/", payload)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentTrustSec Control Center</title>
<style>
/*CSS*/
.warnc { color: var(--warn-text); } .warnc .dot { background: var(--warn); }
.layers { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(360px, 100%), 1fr)); gap: 14px; }
.layer { display: flex; flex-direction: column; gap: 10px; border-top: 2px solid var(--muted); }
.layer.verified { border-top-color: var(--good); } .layer.failing { border-top-color: var(--critical); }
.layer.not-verified { border-top-color: var(--muted); }
.section-h { display: flex; align-items: baseline; gap: 10px; margin: 26px 0 12px; }
.section-h h2 { margin: 0; font-size: 20px; font-weight: 400; letter-spacing: -.01em; }
.lhead { display: flex; align-items: baseline; gap: 8px; }
.lnum { color: var(--muted); font-variant-numeric: tabular-nums; font-size: 12px; min-width: 18px; }
.lname { font-weight: 600; font-size: 16px; letter-spacing: -.01em; flex: 1; }
.ana { color: var(--ink-2); font-size: 12px; } .stops { font-size: 13px; }
.where { display: flex; flex-wrap: wrap; gap: 4px; }
.where span { background: var(--wash); color: var(--accent-text); border-radius: 999px; padding: 2px 9px; }
.items { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.items li { display: grid; grid-template-columns: 18px 1fr; gap: 6px; font-size: 13px; }
.items .ic { font-weight: 700; } .items .ic.t { color: var(--good-text); } .items .ic.f { color: var(--critical-text); }
.items .ic.n { color: var(--muted); }
.items .det { color: var(--ink-2); font-size: 12px; overflow-wrap: anywhere; }
.kind { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; margin-right: 4px; }
details summary { cursor: pointer; color: var(--ink-2); font-size: 12px; }
details ul { margin: 6px 0 0; padding-left: 18px; }
.health { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(300px, 100%), 1fr)); gap: 8px 16px; }
.health div { display: grid; grid-template-columns: auto 1fr; gap: 2px 8px; align-items: baseline; }
.health .hd { grid-column: 2; color: var(--ink-2); font-size: 12px; overflow-wrap: anywhere; }
.runbar { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 22px; }
.runbar .sub { color: #C2CCDA; } .runbar .note { color: #94A3B8; }
.runbar .mono { color: #C2CCDA; }
button[disabled] { opacity: .6; cursor: progress; }
.note { color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<div class="topbar"><div class="wrap">
  <span class="brand"><svg class="mark" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><defs><linearGradient id="mk" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3A8DFF"/><stop offset="1" stop-color="#0A60FF"/></linearGradient></defs><path d="M12 2.5 4 5.6v6.1c0 4.6 3.3 8.6 8 9.8 4.7-1.2 8-5.2 8-9.8V5.6L12 2.5Z" fill="url(#mk)"/><path d="m8.4 12.2 2.6 2.6 4.8-5.1" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>AgentTrustSec</span>
  <span class="tagline">Zero-trust for AI agents · lab</span>
  <span class="grow"></span>
  <nav class="tabs" aria-label="Views"><a href="./">Decisions</a><a href="control" aria-current="page">Control Center</a></nav>
  <button id="theme" type="button" aria-label="Toggle light or dark theme">Theme</button>
</div></div>
<section class="hero"><div class="wrap">
  <div class="eyebrow">Control Center</div>
  <h1>Is every security control working right now?</h1>
  <div class="sub" id="meta"></div>
  <section class="tiles" id="tiles"></section>
  <div class="runbar">
    <button class="primary" id="run" type="button">Run checks</button>
    <span class="sub" id="runmsg" role="status"></span>
    <span class="note">Read-only probes against the lab (~10 s). They change nothing; the full attack demo stays
      <span class="mono">python -m agenttrustsec.demo_live</span>.</span>
  </div>
</div></section>
<main>
  <section class="card"><h2>Health</h2><div class="health" id="health"></div></section>
  <div class="section-h"><h2>Defence in depth</h2><span class="sub">11 layers + audit, in the order a request meets them</span></div>
  <section class="layers" id="layers"></section>
  <p class="legend">A layer is <b>Verified</b> only when every piece of its evidence is present and good: audit records
    from the latest live demo, that demo's expected-vs-actual result, and the read-only probes. Missing evidence is
    <b>Not verified</b>, never green. Times are UTC.</p>
</main>
<script type="application/json" id="data">/*DATA*/</script>
<script>
(function () {
  "use strict";
  const BOOT = JSON.parse(document.getElementById("data").textContent);
  const TOKEN = BOOT.token;
  let V = BOOT.view;
  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v);
    }
    for (const k of kids) if (k != null) n.append(k);
    return n;
  }
  const STATUS = {"verified": ["allow", "✓", "Verified"], "failing": ["block", "✕", "Failing"],
                  "not verified": ["other", "–", "Not verified"]};
  const HEALTH = {"ok": ["allow", "✓", "OK"], "warn": ["warnc", "!", "Warning"], "fail": ["block", "✕", "Failing"]};
  function pill(map, s) {
    const m = map[s] || ["other", "•", s];
    return el("span", {class: "pill " + m[0]}, el("span", {class: "dot", "aria-hidden": "true"}), el("span", {text: m[1] + " " + m[2]}));
  }
  function when(ts) { return ts ? ts.replace("T", " ").replace("+00:00", "").replace(/\.\d+$/, "") : "never"; }
  function base(p) { return p ? p.split("/").pop().split("\\").pop() : "none"; }
  function tile(k, v, d) {
    return el("div", {class: "card tile"}, el("div", {class: "k", text: k}), el("div", {class: "v", text: v}), el("div", {class: "d", text: d}));
  }
  function layerCard(L) {
    const items = el("ul", {class: "items"}, ...L.items.map((i) => {
      const m = i.ok === true ? ["t", "✓"] : i.ok === false ? ["f", "✕"] : ["n", "·"];
      return el("li", {}, el("span", {class: "ic " + m[0], "aria-hidden": "true", text: m[1]}),
        el("div", {}, el("span", {class: "kind", text: i.kind}), el("span", {text: i.label}),
           el("div", {class: "det", text: (i.ts ? when(i.ts) + " · " : "") + (i.detail || "")})));
    }));
    return el("article", {class: "card layer " + L.status.replace(" ", "-"), "aria-label": "Layer " + L.n + " " + L.name},
      el("div", {class: "lhead"}, el("span", {class: "lnum", text: L.n}), el("span", {class: "lname", text: L.name}), pill(STATUS, L.status)),
      el("div", {class: "ana", text: "TrustSec: " + L.analogy}),
      el("div", {class: "stops", text: "Stops " + L.stops + "."}),
      el("div", {class: "where"}, ...L.where.map((w) => el("span", {class: "mono", text: w}))),
      items,
      el("details", {}, el("summary", {text: "Covered by " + L.tests.length + " test(s)"}),
         el("ul", {}, ...L.tests.map((t) => el("li", {class: "mono", text: t})))));
  }
  function render() {
    $("meta").textContent = "run " + base(V.run) + " · probes " + when(V.probes_ran_at) + " · built " + when(V.generated);
    const c = V.counts;
    $("tiles").replaceChildren(
      tile("Layers verified", c["verified"] + " / " + V.total, "every piece of evidence good"),
      tile("Failing", String(c["failing"]), c["failing"] ? "evidence contradicts the control" : "none"),
      tile("Not verified", String(c["not verified"]), "evidence missing: run checks / the demo"),
      tile("Probes", V.probes_ran_at ? "ran" : "not run", when(V.probes_ran_at)));
    $("health").replaceChildren(...V.health.map((h) => el("div", {},
      pill(HEALTH, h.status), el("span", {text: h.name}), el("span", {class: "hd", text: h.detail}))));
    $("layers").replaceChildren(...V.layers.map(layerCard));
  }
  async function refresh() {
    try {
      const r = await fetch("control.json", {cache: "no-store"});
      if (r.ok) { V = await r.json(); render(); }
    } catch (e) { /* server stopped: keep the last view */ }
  }
  $("run").addEventListener("click", async () => {
    const b = $("run"); b.disabled = true; $("runmsg").textContent = "Running read-only probes…";
    try {
      const r = await fetch("control/run", {method: "POST", headers: {"X-AgentTrustSec-Token": TOKEN}, cache: "no-store"});
      if (r.ok) { V = await r.json(); render(); $("runmsg").textContent = "Probes finished " + when(V.probes_ran_at) + "."; }
      else $("runmsg").textContent = r.status === 409 ? "A probe run is already in progress." : "Refused (" + r.status + ").";
    } catch (e) { $("runmsg").textContent = "Server not reachable."; }
    b.disabled = false;
  });
  $("theme").addEventListener("click", () => {      // navy is the default; light is one click away
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("ats-theme", root.dataset.theme); } catch (e) { /* storage blocked: fine */ }
  });
  try { const t = localStorage.getItem("ats-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }
  render();
  setInterval(refresh, 5000);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
