# P1 — Learn by running

Fill this in as you run the upstream projects. Claude Code: ask the owner to paste
command output here rather than guessing results.

## SLIM (github.com/agntcy/slim)
- [x] Run a SLIM node locally (`lab/slim/`, image `ghcr.io/agntcy/slim:3.4.5`)
- [x] Run the Python bindings point-to-point example (plain + MLS + negative tests)
- [ ] Run a group-session example; note how MLS group membership is added/removed
- Observations (2026-10-20, node 3.4.5, `slim-bindings` 3.3.6):
  - Python bindings moved to **github.com/agntcy/slim-bindings** (PyPI `slim-bindings`,
    import `slim_bindings`; README still shows old `slim_uniffi_bindings` in places).
    Wheel ships the examples as console scripts (`slim-bindings-p2p`, `-group`, ...).
    Bindings 3.3.6 are built on core **3.4.5** -> node pinned to 3.4.5 (3.4.6 = today).
    Also exists: **github.com/agntcy/slim-mcp-python** (MCP over SLIM) — read for P3.
  - Names are `org/namespace/app` (`agntcy/ns/alice`) + a per-instance id. Node listens on
    `:46357`; apps dial OUT to it (`connect_async`), subscribe to their own name, and
    `set_route_async` to the remote — no app opens a port.
  - **Identity is verified by the receiving app, not the node.** The node forwards; Alice
    logs `dropping pre-session message: identity verification failed ... token invalid`
    for a wrong secret and the sender just times out (`message send retries exhausted`,
    ~25 s = 5 retries x 5 s). Like MACsec peers authenticating while the fabric forwards.
  - **Shared-secret mode is a group PSK, not per-agent identity:** with the right secret,
    an unregistered name (`agntcy/ns/mallory`) was accepted. Unusable for zero trust ->
    P3 must use JWT mode (each app signs its own token with its private key; peers
    verify against a JWKS = proof of possession) or SPIRE. This is where the bearer-badge
    replay gap (ARCHITECTURE known gap) can close.
  - MLS on a P2P session is one flag (`MlsSettings`); receiver needs no MLS flag.
    3 round trips ~3.8–4.1 s wall, dominated by the example's 1 s sleeps — measure
    latency properly in P6, not from these.

### Runbook (Git Bash, repo root) — SLIM node + bindings examples

Examples run isolated via `uvx` (nothing added to the project venv until P3). Use a
throwaway secret per run; `SECRET` below is never written to the repo.

**1. Node**
```bash
docker compose -f lab/slim/docker-compose.yml up -d
docker compose -f lab/slim/docker-compose.yml logs slim | grep -E 'Version|server started'
```
Output: `Version: 3.4.5`, `dataplane server started endpoint=0.0.0.0:46357` (host: 127.0.0.1 only)

**2. Point-to-point** (terminal 1 listens, terminal 2 sends)
```bash
SECRET=$(python -c "import secrets;print(secrets.token_hex(16))")
P2P='uvx --python 3.12 --from slim-bindings[examples]==3.3.6 slim-bindings-p2p'
$P2P --local agntcy/ns/alice --shared-secret "$SECRET"                       # terminal 1
$P2P --local agntcy/ns/bob --remote agntcy/ns/alice --message "hey there" \
     --iterations 3 --shared-secret "$SECRET" [--enable-mls]                   # terminal 2
```
Output (both plain and `--enable-mls`): `Sent message hey there - 1/3` ->
`received (from session 456378187): hey there from 253ac012-…` x3.
Negative: wrong secret (plain and MLS) -> sender `Error: ... failed to add participant to
session: message send retries exhausted`; Alice logs `identity verification failed`.
Right secret + made-up name `agntcy/ns/mallory` -> **accepted** (see observations).

**3. Group with MLS** — interactive (prompt_toolkit), run yourself in 3 terminals:
```bash
G='uvx --python 3.12 --from slim-bindings[examples]==3.3.6 slim-bindings-group'
$G --local agntcy/ns/client-1 --shared-secret "$SECRET"                      # terminal 1
$G --local agntcy/ns/client-2 --shared-secret "$SECRET"                      # terminal 2
$G --local agntcy/ns/moderator --remote agntcy/ns/chat --shared-secret "$SECRET" \
   --invites agntcy/ns/client-1 --invites agntcy/ns/client-2 --enable-mls     # terminal 3
```
In the moderator: type messages; `remove agntcy/ns/client-2`, then `invite agntcy/ns/client-2`.
Note: can a removed member still read new messages? Does a non-invited client see anything?
Output:

## Identity (github.com/agntcy/identity)
- [x] Node running (step 0)
- [x] Self-signed issuer registered; 3 agent badges issued + published (steps 1–4)
- [x] Verified with `identity verify` and with our `AgntcyBadgeVerifier` (steps 5–6)
- Observations (2026-10-20, CLI + node 0.0.26):
  - Badge = JOSE compact, `RS256`, `kid` = vault key id; VC `type: [AgentBadge]`,
    `issuer` = issuer common name, `credentialSubject.id` = metadata id,
    `credentialSubject.badge` = the OASF JSON as a string. **No `expirationDate`.**
  - The VC `id` (in the JWS) differs from the "badge ID" the CLI prints at issue time
    (CLI-local id, used only for `publish -b`). Our verifier uses the VC `id`.
  - CLI prompts on stdin for anything not given as a flag -> pass `-i`, `-b` etc.
    `badge issue oasf` takes `-o` (upstream README shows `-f`).
  - Revocation: tested via `lab/identity/revoke_badge.py` (step 8) — node Verify only
    checks the presented copy (gap; fixed in our verifier). Expiry: nothing to test (none set).

### Runbook (Git Bash, from the repo root) — paste output under each step

Facts from upstream v0.0.26 source (commit `8f7c1b5`): node HTTP `:4000` (CLI,
`.well-known`), gRPC `:4001` (Python SDK). Badge subject `content.id` = the
**metadata id** -> one `metadata generate` per agent; those ids key
`policies/identities.yaml`. No `revoke` CLI command (node `Revoke` RPC needs an
issuer-signed proof -> `lab/identity/revoke_badge.py`, step 8) and the CLI sets no expiry.
Don't clone upstream on Windows (`Filename too long`; `launch_node.sh` uses `ln -s`).

**0. Node.** Already running from upstream compose (`identity-node`, `:latest` = 0.0.26
by image label). For a fresh pinned start instead (stop the upstream one first —
both bind 4000/4001):
```bash
echo "IDENTITY_DB_PASSWORD=<pick one>" > lab/identity/.env   # git-ignored
docker compose -f lab/identity/docker-compose.yml up -d
```

**1. Issuer CLI v0.0.26** (matches the SDK), checksum-verified:
```bash
mkdir -p ~/bin && cd ~/bin
V=0.0.26; B=https://github.com/agntcy/identity/releases/download/v$V
curl -LO $B/identity_windows_amd64.exe && curl -LO $B/identity_${V}_checksums.txt
grep ' identity_windows_amd64.exe$' identity_${V}_checksums.txt | sha256sum -c -
mv identity_windows_amd64.exe identity.exe && cd - && identity -h
```
Output:

**2. Vault + key** (the vault file holds the issuer private key — keep it out of the repo):
```bash
identity vault connect file -f ~/.identity/vault.json -v "AgentTrustSec Lab"
identity vault key generate
```
Output:

**3. Issuer** — self-signed, no IdP (lab only; the node treats the name as unverified,
like a self-signed CA):
```bash
identity issuer register -o "AgentTrustSec Lab" -b netops -n agenttrustsec-lab -i http://localhost:4000
```
Output: `Successfully registered as an Issuer` — ID `64028070-490a-4651-91b7-05faf913984d`,
JWKS at `http://localhost:4000/v1alpha1/issuer/agenttrustsec-lab/.well-known/jwks.json`

**4. One metadata id + badge per agent.** `metadata generate` makes the new id current,
so `badge issue` right after binds to it. Record each printed metadata id.
```bash
for a in reader-01 reviewer-01 executor-01; do
  echo "== $a"
  identity metadata generate
  out=$(identity badge issue oasf -o lab/identity/oasf/$a.json) && echo "$out"
  identity badge publish -b "${out##*: }" -i http://localhost:4000
done
```
Output (metadata id = badge subject; CLI badge id):
- reader-01:   `AGNTCY-13cbc3cf-89ae-43d6-b5b4-b0681092b8fb` (badge `c649aeab-…`)
- reviewer-01: `AGNTCY-c55ca3ee-802d-4209-8352-343197d644ae` (badge `d38d2fbb-…`)
- executor-01: `AGNTCY-f3f8503b-43e7-4cd1-8822-2ff32a78db84` (badge `894d4d2b-…`)

**5. Verify with the CLI** (replace `<MID>` with reader-01's metadata id):
```bash
curl -s -o vcs.json http://localhost:4000/v1alpha1/vc/<MID>/.well-known/vcs.json
identity verify -f vcs.json -i http://localhost:4000
```
Output (reader-01): `Badge verified successfully!` — Badge ID `c8bbed52-c0dc-4fba-9666-bb5dece11bae`,
Type `[AgentBadge]`, Issuer `agenttrustsec-lab`, Issued `2026-10-20T17:15:02Z`.

**6. Verify with our verifier over gRPC** (needs `uv pip install -e ".[agntcy]"`):
```bash
IDENTITY_NODE_GRPC_SERVER_URL=localhost:4001 IDENTITY_NODE_USE_SSL=0 python - <<'EOF'
import json
from agenttrustsec.identity.agntcy import AgntcyBadgeVerifier
mid = "<MID>"
jose = json.load(open("vcs.json"))["vcs"][0]["value"]
print(AgntcyBadgeVerifier({mid: "reader"}).verify(jose, mid))
print(AgntcyBadgeVerifier({mid: "reader"}).verify(jose, "someone-else"))  # expect BadgeError
EOF
rm vcs.json
```
Output (reader-01, plus extra negative cases):
- genuine -> `VerifiedIdentity(agent_id='AGNTCY-13cb…', role='reader', badge_id='c8bbed52-…')`
- wrong caller id -> `BadgeError: subject mismatch`
- tampered signature -> `BadgeError: identity node rejected badge: Unable to verify the integrity of the data provided.`
- id not in role map -> `BadgeError: no role mapped for verified id`

**7. MCP server badge.** The CLI discovers the server over streamable HTTP at
`{url}/mcp` (`initialize`, `tools/list`, `resources/list`) and signs the tool
inventory into an `MCPServerBadge`. Start the gateway badge-less (issuance mode:
discoverable, every `tools/call` BLOCKED + audited), issue, publish, map the id in
`policies/identities.yaml` -> `mcp_servers`, then restart it with its badge:
```bash
python -m agenttrustsec.mcpgate.serve --port 9090 &        # issuance mode
identity metadata generate
out=$(identity badge issue mcp -u http://localhost:9090 -n netops-mcp) && echo "$out"
identity badge publish -b "${out##*: }" -i http://localhost:4000
kill %1
IDENTITY_NODE_GRPC_SERVER_URL=localhost:4001 IDENTITY_NODE_USE_SSL=0   python -m agenttrustsec.mcpgate.serve --port 9090 --server-id <MID>
```
Output (2026-10-20): metadata `AGNTCY-2e3bc5c0-7bc2-4c5f-a055-ff6ae74d0add`, CLI badge
`e195d433-…`, VC id `3abc3ccf-d9e0-4a3d-9a64-fd48532953df`, type `[MCPServerBadge]`, no
expiry; signed tools: `show_running_config, show_acl, show_bgp_neighbors, review_change,
push_config, lookup_threat_intel`; resources: none. Startup check refuses an agent's id
(`expected MCPServerBadge, got types ['AgentBadge']`).

**8. Revocation** (throwaway badge `revoke-test-01`, never mapped to a role). The v0.0.26
CLI has no revoke command; the node's `Revoke` RPC takes the SAME VC re-signed by the
issuer with a `credentialStatus` of purpose `CREDENTIAL_STATUS_PURPOSE_REVOCATION`, plus
a self-issued JWT proof (`iss agntcy:<cn>`, `sub`=`aud`= metadata id minus `AGNTCY-`).
`lab/identity/revoke_badge.py` does that; it reads the issuer key from
`~/.identity/vault.json` in memory only (dry run unless `--yes`; IRREVERSIBLE).
```bash
identity metadata generate
out=$(identity badge issue oasf -o lab/identity/oasf/revoke-test-01.json) && echo "$out"
identity badge publish -b "${out##*: }" -i http://localhost:4000
curl -s http://localhost:4000/v1alpha1/vc/<MID>/.well-known/vcs.json   # keep: original copy
python lab/identity/revoke_badge.py <MID>          # dry run
python lab/identity/revoke_badge.py <MID> --yes
```
Output (2026-10-20): metadata `AGNTCY-ad860353-453a-4d71-9190-e1f32ca0947a`, VC
`315020a4-330d-4816-8898-1c9dbfa0f47d` -> `revoked VC 315020a4-…`. Then:
- `.well-known` now serves 1 VC, same id, carrying the REVOCATION status
- node Verify, revoked copy  -> `status=False`, warning `The Verifiable Credential is revoked.`
- node Verify, **original copy -> `status=True`, no warnings** (the node never consults
  its stored copy — `vc.ValidateStatus()` runs on the presented JOSE only)
- our verifier BEFORE the fix: revoked copy BLOCK, **original copy ALLOWED** (gap)
- AFTER (published-copy status check): both copies -> `BadgeError: ... revoked`
  (`tests/test_agntcy_live.py`, fixture `tests/fixtures/revoke-test-01.original.jose`)

**9. Key-bound agent badges (P3 PR1, docs/P3-design.md §2).** Each agent gets its own
RSA key (`~/.agenttrustsec/keys/<name>.pem`, never in the repo); its RFC 7638
thumbprint goes into the OASF `annotations` so the issuer signs the key binding.
Re-issue under the SAME metadata id (`metadata load`), then revoke the old key-less VC.
```bash
python lab/identity/agent_keys.py reader-01 reviewer-01 executor-01 --write-oasf
python lab/identity/agent_keys.py netops-mcp          # gateway key; thumbprint -> identities.yaml (D2, PR3)
identity metadata load -m <MID>
out=$(identity badge issue oasf -o lab/identity/oasf/<agent>.json) && echo "$out"
identity badge publish -b "${out##*: }" -i http://localhost:4000
python lab/identity/revoke_badge.py <MID> --vc-id <OLD_VC_ID> --yes
```
Output (2026-10-20):

| agent | key thumbprint | new VC | old VC (revoked) |
|---|---|---|---|
| reader-01 | `jCYe9css2M5J8yN4MZBoUrcN4IiRJioRl1BUpc0mIj0` | `a47e4139-…` | `c8bbed52-…` |
| reviewer-01 | `ZLXRltf2VV3Hj3Jj3KkvyHLSI9qQOxqKBqh4PDM6R1Q` | `bbc410d9-…` | `35419070-…` |
| executor-01 | `20Xqm22VvT_Doop2rV3YNaaNRVSCOlRAT6xkJ5Cfblg` | `9a69bbc1-…` | `a8b27052-…` |
| netops-mcp | `5q9tysl6LGnq_Z5s9UNy9IWFqa5V9-4xYCRsLPkTgIc` | (MCPServerBadge unchanged) | — |
| intake-01 (2026-10-21, P3 PR5a) | `Gfx8mBk3LhV66yBZNi2zaNSoj3t44vgjxot-HpUUFRM` | `682ca691-…` (metadata `AGNTCY-7787aa23-dfa1-4600-b664-0c728b88fd27`) | — (new) |

Node `.well-known` lists the newest VC first, but order isn't guaranteed — consumers
must pick by content (unrevoked / VC id), never by position.

**10. Gateway badge re-issued (item C, 2026-10-23).** P5a changed `review_change`
(`change`: object, new description), so the signed inventory drifted; the gateway now refuses
to start on drift (`mcpgate/inventory.py`). Re-issue under the SAME metadata id, then revoke:
```bash
python -m agenttrustsec.mcpgate.serve --port 9090 --jti-db <tmp> &      # issuance mode
identity metadata load -m AGNTCY-2e3bc5c0-7bc2-4c5f-a055-ff6ae74d0add
out=$(identity badge issue mcp -u http://localhost:9090 -n netops-mcp) && echo "$out"
identity badge publish -b "${out##*: }" -i http://localhost:4000
kill %1
python lab/identity/revoke_badge.py AGNTCY-2e3bc5c0-… --vc-id 3abc3ccf-d9e0-4a3d-9a64-fd48532953df --yes
```
Output: CLI badge `223a8b6a-…`, new VC `49479d21-e220-4ed6-86e4-e7c9a2eacb94` (issued
2026-10-23T10:42:51Z, 6 tools, `review_change.change` = object); old VC `3abc3ccf-…` now
published with REVOCATION status. Before the re-issue the gateway refused:
`tool inventory drift (re-issue the badge): badge 3abc3ccf…: review_change changed
(description, parameters)`. Note: `metadata load` leaves the CLI context on the gateway's id.

## CASA (github.com/outshift-open/outshift-casa)
- [ ] `bash scripts/dev/local-setup-standalone.sh` on Minikube
- [ ] Run safe vs compromised demo agent; screenshot Explorer UI traces
- Observations (how deterministic vs semantic checks decide; token exchange flow):

## Decisions for P2–P4
- Badge verifier: `AgntcyBadgeVerifier` (identity/agntcy.py). Findings from SDK 0.0.26 +
  node source: badges carry NO role -> role from `policies/identities.yaml`; revoked
  badges return status=False WITH document + reason in `warnings` -> require
  status is True and no warnings; no expiry check found in node -> enforced locally.
  Confirmed against a real node (2026-10-20): genuine/tampered/subject/role paths.
  Revocation (step 8): node Verify checks only the presented copy -> verifier also
  requires the VC id in the node's published copies, not revoked. Expiry: CLI sets none.
- Run gate in-process vs CASA sidecar: ...
- Semantic checker approach: ...
