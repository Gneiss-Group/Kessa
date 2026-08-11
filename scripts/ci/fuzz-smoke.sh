#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# fuzz-smoke.sh: run every native fuzz target briefly, by hand.
#
# NO LONGER IN THE PR GATE, and the reason it was removed is worth keeping here
# so it is not added back on the same reasoning that put it there.
#
# It was justified as a liveness check: keep the targets COMPILING and their seed
# corpora LOADING. Both are true and neither needed this script, because `go
# test` runs a fuzz target's seed corpus as ordinary subtests whenever -fuzz is
# absent. The gate's race-test step therefore already compiles every target and
# runs every seed, including every committed regression seed. What ten seconds of
# -fuzz per target added was random exploration, which is discovery on a budget
# too small to do it, at two thirds of the job's runtime.
#
# Real discovery now runs on a schedule (.github/workflows/fuzz.yml) at minutes
# per target. This script stays for the local inner loop, where a quick pass over
# everything before pushing is genuinely useful:
#
#   make fuzz-smoke              # ten seconds per target
#   make fuzz-smoke FUZZTIME=2m  # longer, still local
#
# The target list is DERIVED, never enumerated. `go test -list` reads the
# compiled test binary, so a fuzz target added tomorrow is picked up by having
# been written, not by also being remembered here. A hardcoded list is a second
# place to update, and the standing rule in docs/go-standards.md is that the
# second place is the one that goes stale without saying so.
#
# Usage:  scripts/ci/fuzz-smoke.sh [fuzztime]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

FUZZTIME="${1:-10s}"

found=0
fail=0

for pkg in $(go list ./...); do
  # A package with no fuzz targets prints only its "ok" line, which the grep
  # drops. `|| true` keeps a no-match from tripping set -e.
  targets="$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)"
  [ -n "$targets" ] || continue

  for t in $targets; do
    found=$((found + 1))
    printf '\n=== %s %s (%s) ===\n' "$pkg" "$t" "$FUZZTIME"
    # Anchored -run and -fuzz so FuzzParse does not also select FuzzParseFoo.
    if ! go test "$pkg" -run "^${t}\$" -fuzz "^${t}\$" -fuzztime "$FUZZTIME"; then
      fail=1
    fi
  done
done

# Zero targets is a failure, not a quiet success. If this script ever finds
# nothing (a build tag, a renamed file, a refactor that dropped the targets), it
# would otherwise report OK while fuzzing nothing at all.
if [ "$found" -eq 0 ]; then
  echo "fuzz-smoke: no fuzz targets found; this script is checking nothing."
  exit 1
fi

if [ "$fail" -eq 0 ]; then
  echo
  echo "fuzz-smoke: OK: $found target(s), $FUZZTIME each"
fi
exit "$fail"
