# P3 design — agents and the MCP gateway on SLIM (DRAFT for owner sign-off)

Goal (CLAUDE.md P3): every agent ↔ gateway exchange rides SLIM; no agent or gateway opens
an inbound port; and the **bearer-badge replay gap** (ARCHITECTURE "Known gap") closes,
because presenting a badge will require proving possession of a key the badge binds.

TrustSec analogy: today a badge is like a certificate anyone can copy and present. P3
turns it into a real certificate: the issuer binds a **public key** to the identity, the
SLIM handshake proves the peer holds the **private key** (like the TLS CertificateVerify
inside EAP-TLS), and MLS encrypts the session end to end (MACsec), so the SLIM node is
a fabric that forwards ciphertext.

## 1. Verified facts (2026-10-20, node 3.4.5, slim-bindings 3.3.6, mcp 2.3.0)

Probe: `lab/slim/identity_probe.py`, two apps on the lab node, MLS on.

| Finding | Consequence |
|---|---|
| Receiver gets `MessageContext.identity` = the peer's **full signed token** (JWT in JWT mode) and `metadata['slim-peer-subject']` = its `sub` | The gate can see and re-verify who is on the other end of every message |
| JWT mode: a sender key **not** in the verifier's JWKS → `identity verification failed`, dropped | Trust anchor works |
| JWT mode: Bob signs with **his own valid key** but claims `sub=agntcy/ns/alice-admin` → **ACCEPTED**; routing `source_name` (`agntcy/ns/bob`) ≠ `sub` | **SLIM does not bind key↔name, nor routing name↔identity.** We must (like ISE checking cert CN vs endpoint) |
| JWT header `kid` = the subject, not our JWK `kid`; verifier tries the JWKS | Can't rely on `kid` for key selection |
| Token carries a `pubkey` claim (MLS key) | Session MLS keys are bound to the signed identity token |
| Shared-secret mode = group PSK: any name accepted with the secret | Not usable (P1 notes) |
| `agntcy/slim-mcp-python` 0.2.3 (and `main`) pins `mcp==1.26.0`, `slim-bindings~=1.4`, and sets `enable_mls=False` | **Can't depend on it.** Reuse its pattern only |
| `mcp` 2.x: `Client(...)` accepts any `Transport` (async CM → read/write streams); `MCPServer` wraps a lowlevel `Server.run(read, write, init_opts)` where our `GateMiddleware` lives | A ~150-line adapter in `transport/` fits without touching the gate |

## 2. Identity model — badge-bound keys (recommended)

Each agent (and the gateway) gets its **own RSA key pair**. The issuer signs the binding:

* **Agents:** the public key's RFC 7638 JWK thumbprint goes into the OASF record's
  `annotations` (`"agenttrustsec.key_thumbprint": "<b64url>"`) before `badge issue oasf`,
  so it lands inside the issuer-signed `AgentBadge`. Same metadata ids → `identities.yaml`
  unchanged; the old key-less badges are revoked with `revoke_badge.py`.
* **Gateway (MCPServerBadge):** the CLI builds that badge from MCP discovery (name, url,
  tools, resources) — we can't add fields. See decision **D2**.
* SLIM names: `agenttrustsec/lab/<metadata-id>` (lower-cased); token `sub` = that name.

**Gate check `peer` (new), all must hold, any error → BLOCK:**
*As built (PR3): it runs right AFTER `badge`, because steps 4–5 need the key the verified
badge binds. A failed `peer` voids the role (TBAC/intent SKIPPED, `verified_role` None).*
1. SLIM already verified the token against the trust JWKS (the registered keys).
2. Decode the token; `sub` == `slim-peer-subject` == routing `source_name`.
3. The presented badge passes today's checks (node signature, published + not revoked,
   type, subject == claimed agent id).
4. `sub` ↔ badge subject (metadata id) match.
5. **Re-verify the token signature ourselves with the key whose thumbprint is in the
   badge** (+ `exp`/`iss`/`aud`). This is the key↔name binding SLIM lacks — it defeats the
   spoof above and any copied badge: no private key, no valid token for that badge.

The client does the mirror check on the gateway (server-side mutual auth, closes T9 replay).

## 3. Transport adapter — `src/agenttrustsec/transport/slim.py` (our own)

* `SlimClientTransport(app, gateway_name)` → `mcp` `Transport`: opens a P2P session
  **with MLS**, one JSON-RPC message per `publish_async`, replies via `get_message_async`.
* `serve_slim(mcp_server, app)`: `listen_for_session_async` loop; per session it runs the
  lowlevel server on the session's streams and puts the session's verified peer identity
  in a contextvar that `GateMiddleware` reads for the `peer` check (audited like every check).
* Gateway and agents connect OUT to the SLIM node; nobody listens on a port.
* Vendor calls stay behind this module (CLAUDE.md rule 7); `slim-bindings==3.3.6` pinned in
  a new `[slim]` extra; node pinned to 3.4.5 (the core 3.3.6 is built on).

## 4. Threats

| Threat | After P3 |
|---|---|
| Copied agent badge replayed (T1/T2 variant) | BLOCK at `peer` step 5 — no private key |
| Copied gateway badge on an impostor (T9 replay) | Client rejects — no private key |
| Valid agent claims another agent's name over SLIM | BLOCK at `peer` steps 2/4/5 |
| Revoked agent | BLOCK at `badge` (published-status check, P2) |
| SLIM node / network reads tool args | MLS ciphertext only |
| **Remaining:** anyone can connect to the lab node (no node admission auth, plaintext hop) | Node can be flooded / sees metadata (names, sizes). Node mTLS/JWT admission = D5 |

## 4b. Found while building (PR2–PR3)

* **SLIM silently ignores trust JWKs without `alg`** — such an agent can never connect and
  nothing says why. `transport.slim.jwt_identity` now refuses them; `identity/keys.trust_jwk`
  always emits `alg/use/kid`.
* **Re-using a SLIM name inside one process after a session fails** (both the old and a new
  key are then rejected) — looks like stale routing to the old instance; not root-caused.
  Tests run such exchanges in fresh processes. Not a security bypass (it fails closed),
  but a gateway restart/re-registration path to watch in PR4.
* Name→key binding in SLIM is NOT key pinning: the order test (attacker first, then the
  real agent) showed no first-use pinning — both were rejected on reuse.

## 5. Work order (one PR each)

1. **Keys + re-issued badges:** `lab/identity/agent_keys.py` (generate per-agent keys under
   `~/.agenttrustsec/keys/`, print thumbprints), OASF records gain the thumbprint
   annotation, re-issue + publish, revoke old badges, live tests updated.
2. **Adapter:** `transport/slim.py` + live tests (echo MCP server over SLIM, MLS on,
   skipped if node down).
3. **`peer` check:** gate + verifier code for steps 2–5, fake-identity unit tests
   (spoofed sub, wrong key, missing thumbprint, routing-name mismatch, expired token).
4. **Gateway on SLIM:** `serve.py --transport slim`; agents' `TrustedClient` over
   `SlimClientTransport`; live attack tests (spoof, copied badge, rogue key, revoked).
5. **Group session** for the reviewer pool (P3b) — after your group-example notes.

## 6. Decisions for the owner

* **D1 Key binding:** thumbprint inside the issuer-signed badge (**recommended**: the issuer
  is the single binder, like a CA) vs a thumbprint column in `policies/identities.yaml`
  (simpler, but our YAML becomes a second trust root).
* **D2 Gateway key:** (a) thumbprint in `identities.yaml` `mcp_servers` (recommended for
  now — explicit, reviewable), or (b) expose it as an MCP resource so discovery signs it
  into the MCPServerBadge (issuer-bound, but bends the resource concept).
* **D3 Private keys:** PEM files in `~/.agenttrustsec/keys/` (lab; never in repo) now;
  SPIRE / HSM later.
* **D4 HTTP:** after P3 the gateway serves tool calls **only over SLIM**; HTTP stays only in
  badge-issuance mode (which already refuses every `tools/call`). Recommended.
* **D5 Node admission:** keep the lab node open (127.0.0.1 only) in P3; add node mTLS/JWT
  admission in P6. Recommended.

## 7. Running it (as built, PR4)

```bash
docker compose -f lab/identity/docker-compose.yml up -d    # or the upstream node
docker compose -f lab/slim/docker-compose.yml up -d
uv pip install -e ".[dev,agntcy,slim]"
python lab/identity/agent_keys.py reader-01 reviewer-01 executor-01 netops-mcp     --export-jwks policies/trust-jwks.json                   # public keys only
export AGENTTRUSTSEC_BROKER_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export IDENTITY_NODE_GRPC_SERVER_URL=localhost:4001 IDENTITY_NODE_USE_SSL=0
python -m agenttrustsec.mcpgate.serve --transport slim --server-id AGNTCY-2e3bc5c0-7bc2-4c5f-a055-ff6ae74d0add
pytest tests/test_gateway_slim_live.py tests/test_gateway_impostor_live.py -v
```

Startup refuses (exit 2) if the gateway's key isn't the one bound to its badge or isn't
in the trust JWKS; `--transport http --server-id` is refused (D4).

Live attack matrix (2026-10-20, all as designed):

| Case | Stopped by |
|---|---|
| genuine reader, `show_acl` | ALLOW (`badge, peer, tbac, intent` all PASS, peer audited) |
| executor's trusted key + reader's SLIM name + reader's badge | `peer`: not signed by the badge's key |
| reader's key presenting executor's badge | `peer`: not the badge holder |
| token `sub` spoofed (`executor-admin`) | `peer`: identity mismatch |
| key outside the trust JWKS | SLIM — session never forms, no audit record reaches the gate |
| revoked agent (revoke-test-01) | `badge`: revoked |
| genuine executor, `push_config` in a read session | `intent` (peer passes; layers still apply) |
| impostor gateway: copied MCPServerBadge, real SLIM name, executor's key | agent: ServerAuthError, not signed by the badge's key |
