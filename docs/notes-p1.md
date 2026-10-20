# P1 — Learn by running

Fill this in as you run the upstream projects. Claude Code: ask the owner to paste
command output here rather than guessing results.

## SLIM (github.com/agntcy/slim)
- [ ] Run a SLIM node locally (Docker image `ghcr.io/agntcy/slim`)
- [ ] Run the Python bindings point-to-point example
- [ ] Run a group-session example; note how MLS group membership is added/removed
- Observations (naming `<org>/<namespace>/<agent>`, ports, latency):

## Identity (github.com/agntcy/identity)
- [ ] Node running (step 0)
- [ ] Self-signed issuer registered; 3 agent badges issued + published (steps 1–4)
- [ ] Verified with `identity verify` and with our `AgntcyBadgeVerifier` (steps 5–6)
- Observations (badge structure, revocation, TBAC policy model):

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
identity issuer register -o "AgentTrustSec Lab" -n agenttrustsec-lab
```
Output:

**4. One metadata id + badge per agent.** `metadata generate` makes the new id current,
so `badge issue` right after binds to it. Record each printed metadata id.
```bash
for a in reader-01 reviewer-01 executor-01; do
  echo "== $a"
  identity metadata generate
  identity badge issue oasf -f lab/identity/oasf/$a.json
  identity badge publish
done
```
Output (metadata id per agent):
- reader-01:
- reviewer-01:
- executor-01:

**5. Verify with the CLI** (replace `<MID>` with reader-01's metadata id):
```bash
curl -s -o vcs.json http://localhost:4000/v1alpha1/vc/<MID>/.well-known/vcs.json
identity verify -f vcs.json
```
Output:

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
Output:

## CASA (github.com/outshift-open/outshift-casa)
- [ ] `bash scripts/dev/local-setup-standalone.sh` on Minikube
- [ ] Run safe vs compromised demo agent; screenshot Explorer UI traces
- Observations (how deterministic vs semantic checks decide; token exchange flow):

## Decisions for P2–P4
- Badge verifier: `AgntcyBadgeVerifier` (identity/agntcy.py). Findings from SDK 0.0.26 +
  node source: badges carry NO role -> role from `policies/identities.yaml`; revoked
  badges return status=False WITH document + reason in `warnings` -> require
  status is True and no warnings; no expiry check found in node -> enforced locally.
  TODO when node is running: confirm these against a real revoked + expired badge.
- Run gate in-process vs CASA sidecar: ...
- Semantic checker approach: ...
