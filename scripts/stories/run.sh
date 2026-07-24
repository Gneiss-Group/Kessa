#!/usr/bin/env bash
#
# run.sh: drives the reporting-agent user stories end to end through the real
# Kessa binaries and captures the actual ALLOW/DENY line for each. It is the
# single source of truth the story images are rendered from (docs/stories.md):
# no image may state an outcome this script did not produce.
#
# Deterministic: fixed seeds, fixed timestamp (--now), fixed nonces. No network
# beyond localhost; nothing of ours is trusted as a service.
#
# Cast: Dana (FP&A analyst) delegates to Acme Finance, which issues a narrowed
# credential to her "revenue-pack" agent. The agent may READ the finance revenue
# dataset and READ/WRITE the finance-reporting workbook, and nothing else.
#
# Usage:
#   scripts/stories/run.sh            # human-readable narration
#   scripts/stories/run.sh --capture  # also write scripts/stories/out/runs.tsv
#                                      # (id <TAB> verbatim agent line), for the
#                                      # image generator to consume.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CAPTURE=0
[ "${1:-}" = "--capture" ] && CAPTURE=1

BIN="$ROOT/bin"
WORK="$(mktemp -d)"
OUT="$ROOT/scripts/stories/out"
PX_PID=""
cleanup() {
  [ -n "$PX_PID" ] && kill "$PX_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

hr()   { printf '\n\033[1m-- %s\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

# ---------------------------------------------------------------------------
hr "Build"
make -s build
note "built kessa, kessa-issuer, kessa-proxy, kessa-agent"

# ---------------------------------------------------------------------------
hr "Issue + publish (Dana -> Acme Finance -> revenue-pack agent)"
"$BIN/kessa-issuer" publish \
  --spec scripts/stories/spec.json --keystore scripts/stories/keystore.json \
  --root "$WORK/public" --out "$WORK/chain.json" >/dev/null
note "published DID docs + signed status list under $WORK/public"
note "minted the delegation chain (kept out of the public root)"

PUBLIC="$WORK/public"
CH="$WORK/chain.json"
KS="scripts/stories/keystore.json"
STATUS_FILE="$PUBLIC/localhost/orgs/acme-finance/status.json"
ST="https://localhost/orgs/acme-finance/status.json=$STATUS_FILE"
NOW="2026-07-23T12:00:00Z"
DLP="did:web:localhost:proxies:acme-dlp"

# ---------------------------------------------------------------------------
hr "Start the enforcement proxy (Acme data-loss-prevention gateway)"
"$BIN/kessa-proxy" serve --policy examples/policies/data-governance.json \
  --dids "$PUBLIC" --enforcement-point "$DLP" --keystore "$KS" \
  --status "$ST" --now "$NOW" --audit-log "$WORK/audit.jsonl" \
  --addr 127.0.0.1:8195 >"$WORK/proxy.log" 2>&1 &
PX_PID=$!
disown "$PX_PID" 2>/dev/null || true

P="http://127.0.0.1:8195"
for _ in $(seq 1 50); do curl -sf "$P/export" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf "$P/export" >/dev/null 2>&1 || { echo "proxy did not become ready"; cat "$WORK/proxy.log"; exit 1; }
note "data-governance policy, acme-dlp key   $P"

# agent helper. || true: a DENY exits non-zero and must not abort the script.
declare -a IDS=() LINES=()
attempt() { # id, then agent args
  local id="$1"; shift
  local line
  line="$("$BIN/kessa-agent" attempt --proxy "$P" --chain "$CH" --keystore "$KS" "$@" || true)"
  printf '   %s\n' "$line"
  IDS+=("$id"); LINES+=("$line")
}

# ---------------------------------------------------------------------------
hr "Story A -- least authority on READ (the agent is scoped to its dataset)"
note "reads the finance revenue dataset it was granted:"
attempt A-allow --type data.read  --target datalake:finance/revenue --nonce a1
note "reaches for the HR payroll dataset it was never granted:"
attempt A-deny  --type data.read  --target datalake:hr/payroll      --nonce a2

hr "Story B -- least authority on WRITE (the agent is scoped to its workbook)"
note "writes the pack into its own finance-reporting workbook:"
attempt B-allow --type file.write --target o365:finance-reporting/weekly.xlsx --nonce b1
note "tries to write into the exec-board workspace it was never granted:"
attempt B-deny  --type file.write --target o365:exec-board/summary.xlsx       --nonce b2

# ---------------------------------------------------------------------------
hr "Independent verification of this run's export"
curl -sf "$P/export" > "$WORK/export.json"
"$BIN/kessa" verify --export "$WORK/export.json" --dids "$PUBLIC" --status "$ST" \
  | grep -E '^  VERDICT' | sed 's/^/ /'

# ---------------------------------------------------------------------------
if [ "$CAPTURE" -eq 1 ]; then
  mkdir -p "$OUT"
  : > "$OUT/runs.tsv"
  for i in "${!IDS[@]}"; do
    printf '%s\t%s\n' "${IDS[$i]}" "${LINES[$i]}" >> "$OUT/runs.tsv"
  done
  hr "Captured"
  note "wrote ${#IDS[@]} verbatim outcomes to scripts/stories/out/runs.tsv"
fi

hr "Done"
note "Every ALLOW and DENY above came from the real binaries. The images in"
note "docs/assets/stories/ are rendered from exactly these lines."
