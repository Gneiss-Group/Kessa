#!/usr/bin/env bash
#
# verify-scene.sh - produce a persistent, independently-verifiable audit export
# for the tamper-detection demo (docs/demo.tape). Unlike scripts/demo.sh, this
# leaves its artifacts on disk so a human (or the verifier) can inspect and
# tamper with them afterward. Deterministic: fixed seeds, timestamp, nonces.
#
# Usage:   scripts/verify-scene.sh <out-dir>
# Emits:   <out-dir>/export.json   the signed audit export
#          <out-dir>/public/       the published DID docs + signed status list
#          <out-dir>/verify-env.sh  sourceable DIDS= and STATUS= for `kessa verify`
#
# After running, verify offline with nothing of ours trusted as a service:
#   source <out-dir>/verify-env.sh
#   bin/kessa verify --export <out-dir>/export.json --dids "$DIDS" --status "$STATUS"

set -euo pipefail

OUT="${1:?usage: verify-scene.sh <out-dir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
BIN="$ROOT/bin"
KS="scripts/demo/keystore.json"
NOW="2026-07-09T12:00:00Z"
GATEKEEPER="did:web:localhost:proxies:gatekeeper"
ALICE="did:web:localhost:people:alice"

make -s build

# Issue + publish Org A's public artifacts (DID docs + signed status list) and
# mint the alice -> acme -> worker -> helper delegation chain.
"$BIN/kessa-issuer" publish \
  --spec scripts/demo/spec.json --keystore "$KS" \
  --root "$OUT/public" --out "$OUT/chain.json" >/dev/null

PUBLIC="$OUT/public"
CH="$OUT/chain.json"
STATUS_FILE="$PUBLIC/localhost/orgs/acme/status.json"
STATUS="https://localhost/orgs/acme/status.json=$STATUS_FILE"

# One enforcement proxy (Org A, commerce policy). Audit entries land in a
# persistent JSON-Lines log; the export is pulled over HTTP below.
"$BIN/kessa-proxy" serve --policy examples/policies/commerce-security.json \
  --dids "$PUBLIC" --enforcement-point "$GATEKEEPER" --keystore "$KS" \
  --status "$STATUS" --now "$NOW" --audit-log "$OUT/audit.jsonl" \
  --addr 127.0.0.1:8191 >"$OUT/proxy.log" 2>&1 &
PID=$!
disown "$PID" 2>/dev/null || true
trap 'kill "$PID" 2>/dev/null || true' EXIT

A="http://127.0.0.1:8191"
for _ in $(seq 1 50); do curl -sf "$A/export" >/dev/null 2>&1 && break; sleep 0.1; done

agent() { "$BIN/kessa-agent" attempt --proxy "$A" --chain "$CH" --keystore "$KS" "$@" >/dev/null 2>&1 || true; }
ACT="--type payment.transfer --target acct/999"

# Three authorized actions, so every verified entry is a short one line
# ("allow justified by evidence"). The demo is about integrity of the log, not
# policy denials, so we keep the entry lines uniform and legible.
agent $ACT --attr amount=10  --nonce s1                       # routine
agent $ACT --attr amount=50  --nonce s2                       # routine
agent $ACT --attr amount=100 --approver "$ALICE" --nonce s3   # consequential, approved

curl -sf "$A/export" > "$OUT/export.json"

cat > "$OUT/verify-env.sh" <<EOF
export DIDS="$PUBLIC"
export STATUS="$STATUS"
EOF

echo "scene ready: $OUT/export.json"
