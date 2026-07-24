#!/usr/bin/env bash
#
# demo.sh — drives all seven Kessa scenarios end to end through the real
# binaries, then hands the audit export to the independent verifier. It is
# deterministic: fixed seeds, fixed timestamps (--now), fixed nonces. No network
# beyond localhost; nothing of ours is trusted as a service.
#
# The story it tells: an agent delegated down a chain attempts actions through an
# enforcement proxy; a second org's proxy (different vertical) trusts the same
# chain with no shared config; and finally an independent verifier re-derives
# every verdict from the export alone — catching a tampered entry.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="$ROOT/bin"
WORK="$(mktemp -d)"
A_PID="" ; B_PID=""
cleanup() {
  [ -n "$A_PID" ] && kill "$A_PID" 2>/dev/null || true
  [ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

hr()  { printf '\n\033[1m── %s\033[0m\n' "$1"; }
note(){ printf '   %s\n' "$1"; }

# ---------------------------------------------------------------------------
hr "Build"
make -s build
note "built kessa, kessa-issuer, kessa-proxy, kessa-agent"

# ---------------------------------------------------------------------------
hr "Issue + publish (Org A)"
# Mint the alice → acme → worker → helper chain and publish the public artifacts:
# did:web documents (incl. Org B's) + a signed status list. This directory is a
# plain static site; no Kessa service serves it.
"$BIN/kessa-issuer" publish \
  --spec scripts/demo/spec.json --keystore scripts/demo/keystore.json \
  --root "$WORK/public" --out "$WORK/chain.json" >/dev/null
note "published DID docs + signed status list under $WORK/public"
note "minted delegation chain (kept out of the public root)"

PUBLIC="$WORK/public"
CH="$WORK/chain.json"
KS="scripts/demo/keystore.json"
STATUS_FILE="$PUBLIC/localhost/orgs/acme/status.json"
ST="https://localhost/orgs/acme/status.json=$STATUS_FILE"
NOW="2026-07-09T12:00:00Z"
GATEKEEPER="did:web:localhost:proxies:gatekeeper"
BRAVO="did:web:localhost:orgs:bravo"
ALICE="did:web:localhost:people:alice"
ACME="did:web:localhost:orgs:acme"

# ---------------------------------------------------------------------------
hr "Start two enforcement proxies (no shared config)"
# Each proxy forwards its audit entries to the default local-file sink (JSON
# Lines), pointed at the temp workdir so the demo leaves no files behind.
"$BIN/kessa-proxy" serve --policy examples/policies/commerce-security.json \
  --dids "$PUBLIC" --enforcement-point "$GATEKEEPER" --keystore "$KS" \
  --status "$ST" --now "$NOW" --audit-log "$WORK/audit-A.jsonl" \
  --addr 127.0.0.1:8191 >"$WORK/proxyA.log" 2>&1 &
A_PID=$!
"$BIN/kessa-proxy" serve --policy examples/policies/legal-ediscovery.json \
  --dids "$PUBLIC" --enforcement-point "$BRAVO" --keystore "$KS" \
  --status "$ST" --now "$NOW" --audit-log "$WORK/audit-B.jsonl" \
  --addr 127.0.0.1:8192 >"$WORK/proxyB.log" 2>&1 &
B_PID=$!
disown "$A_PID" 2>/dev/null || true  # keep cleanup's kill quiet (no job-control notice)
disown "$B_PID" 2>/dev/null || true

A="http://127.0.0.1:8191"
B="http://127.0.0.1:8192"
wait_ready() {
  for _ in $(seq 1 50); do curl -sf "$1/export" >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "proxy at $1 did not become ready"; cat "$2"; exit 1
}
wait_ready "$A" "$WORK/proxyA.log"
wait_ready "$B" "$WORK/proxyB.log"
note "Org A proxy  (commerce policy, gatekeeper key)  $A"
note "Org B proxy  (legal policy,    bravo key)       $B"

# agent helpers. || true: a DENY exits non-zero and must not abort the script.
agentA() { "$BIN/kessa-agent" attempt --proxy "$A" --chain "$CH" --keystore "$KS" "$@" || true; }
agentB() { "$BIN/kessa-agent" attempt --proxy "$B" --chain "$CH" --keystore "$KS" "$@" || true; }
act() { echo --type payment.transfer --target acct/999; }

# ---------------------------------------------------------------------------
hr "Scenario 1 — happy path (below threshold)"
agentA $(act) --attr amount=10 --nonce s1 | sed 's/^/   /'

hr "Scenario 2 — scope violation (\$500 vs an attenuated \$100 ceiling)"
agentA $(act) --attr amount=500 --nonce s2 | sed 's/^/   /'

hr "Scenario 3 — consequential + human-in-the-loop"
note "without approval:"
agentA $(act) --attr amount=100 --nonce s3a | sed 's/^/   /'
note "with alice's approval:"
agentA $(act) --attr amount=100 --approver "$ALICE" --nonce s3b | sed 's/^/   /'

hr "Scenario 5 — token loan (a copied blob signed by the wrong key)"
agentA --as "$ACME" $(act) --attr amount=10 --nonce s5 | sed 's/^/   /'

hr "Scenario 6 — cross-org + cross-vertical (same \$100 action, two orgs)"
note "Org A (commerce): consequential → needs approval → without one:"
agentA $(act) --attr amount=100 --nonce s6a | sed 's/^/   /'
note "Org B (legal), NO shared config with A, trusts A's chain via public DID docs:"
agentB $(act) --attr amount=100 --nonce s6b | sed 's/^/   /'
note "→ same action, routine under the legal vertical: consequentiality is environment-defined."

# ---------------------------------------------------------------------------
hr "Independent verification — Org A's export"
curl -sf "$A/export" > "$WORK/export-A.json"
"$BIN/kessa" verify --export "$WORK/export-A.json" --dids "$PUBLIC" --status "$ST" \
  | grep -E '^  (entry|VERDICT)' | sed 's/^/ /'

hr "Independent verification — Org B's export (signed by bravo, re-derived from A's evidence)"
curl -sf "$B/export" > "$WORK/export-B.json"
"$BIN/kessa" verify --export "$WORK/export-B.json" --dids "$PUBLIC" --status "$ST" \
  | grep -E '^  VERDICT' | sed 's/^/ /'

# ---------------------------------------------------------------------------
hr "Scenario 4 — revocation propagation (live, one rewritten static file)"
"$BIN/kessa-issuer" revoke --spec scripts/demo/spec.json --keystore "$KS" \
  --root "$PUBLIC" --index 42 >/dev/null
note "issuer revoked the acme→worker credential (index 42)"
note "routine action after revocation (rides its cached decision):"
agentA $(act) --attr amount=10 --nonce s4r | sed 's/^/   /'
note "consequential action after revocation (forces a live check → blocked):"
agentA $(act) --attr amount=100 --approver "$ALICE" --nonce s4c | sed 's/^/   /'

# ---------------------------------------------------------------------------
hr "Scenario 7 — tamper (post-hoc edit of one audit entry)"
sed 's/acct\/999/acct\/evil/' "$WORK/export-A.json" > "$WORK/export-tampered.json"
note "flipped one action target in entry 0, then re-ran the verifier:"
"$BIN/kessa" verify --export "$WORK/export-tampered.json" --dids "$PUBLIC" --status "$ST" \
  | grep -E '^  (entry|VERDICT)' | sed 's/^/ /' || true

# ---------------------------------------------------------------------------
hr "Done"
note "Org A's clean export verified; Org B trusted A cross-org; the tampered"
note "export failed at exactly the altered entry. Every verdict was re-derived"
note "from files alone — no Kessa service was trusted at any point."
