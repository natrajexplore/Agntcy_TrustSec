# P1 — Learn by running

Fill this in as you run the upstream projects. Claude Code: ask the owner to paste
command output here rather than guessing results.

## SLIM (github.com/agntcy/slim)
- [ ] Run a SLIM node locally (Docker image `ghcr.io/agntcy/slim`)
- [ ] Run the Python bindings point-to-point example
- [ ] Run a group-session example; note how MLS group membership is added/removed
- Observations (naming `<org>/<namespace>/<agent>`, ports, latency):

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
  - Revocation: still untested (no CLI command). Expiry: nothing to test (none set).

### Runbook (Git Bash, from the repo root) — paste output under each step

Facts from upstream v0.0.26 source (commit `8f7c1b5`): node HTTP `:4000` (CLI,
`.well-known`), gRPC `:4001` (Python SDK). Badge subject `content.id` = the
**metadata id** -> one `metadata generate` per agent; those ids key
`policies/identities.yaml`. No `revoke` CLI command (node `Revoke` RPC needs an
issuer-signed proof) and the CLI sets no expiry -> revoked/expired TODO stays open.
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
  TODO: revoked badge (needs a Revoke-RPC helper); expiry (CLI sets none).
- Run gate in-process vs CASA sidecar: ...
- Semantic checker approach: ...
