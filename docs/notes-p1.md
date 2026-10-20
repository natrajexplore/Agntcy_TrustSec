# P1 — Learn by running

Fill this in as you run the upstream projects. Claude Code: ask the owner to paste
command output here rather than guessing results.

## SLIM (github.com/agntcy/slim)
- [ ] Run a SLIM node locally (Docker image `ghcr.io/agntcy/slim`)
- [ ] Run the Python bindings point-to-point example
- [ ] Run a group-session example; note how MLS group membership is added/removed
- Observations (naming `<org>/<namespace>/<agent>`, ports, latency):

## Identity (github.com/agntcy/identity)
- [ ] Create an agentic service; issue a badge with `identity-cli badge create {URL}`
- [ ] Verify the badge with the Python SDK; save one sample badge (redact keys)
- Observations (badge structure, revocation, TBAC policy model):

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
