#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# gate.sh: the merge/release gate, in one place.
#
# The same six checks a contributor runs locally, CI runs on every PR, and both
# release phases run again before anything is tagged or published. Factoring them
# into one script is what lets "a release never trusts an earlier green run" be
# true without three drifting copies in YAML, and it means the Codeberg mirror's
# CI runs the identical gate by calling this file.
#
# Ordered cheapest-first so an obvious failure (formatting, a missing header) is
# reported in seconds rather than after the race-detector suite and the demo.
#
# Usage:  scripts/ci/gate.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

step() { printf '\n=== %s ===\n' "$1"; }

step "gofmt (formatting is not negotiable)"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "gofmt would change these files:"
  printf '  %s\n' $unformatted
  exit 1
fi
echo "OK"

step "SPDX headers on every source file (REUSE)"
missing=""
for f in $(git ls-files '*.go' 'scripts/release/*.sh' 'scripts/ci/*.sh' '.github/workflows/*.yml' 'docker/*.Dockerfile'); do
  grep -q 'SPDX-License-Identifier' "$f" || missing="$missing $f"
done
if [ -n "$missing" ]; then
  echo "files with no SPDX-License-Identifier header:"
  printf '  %s\n' $missing
  exit 1
fi
echo "OK"

step "no em dashes (house style, enforced not remembered)"
# House style: em dashes are not used anywhere in this repository. This check
# exists because the rule was stated repeatedly and kept being broken: a
# preference that lives only in someone's memory is a preference that decays.
# Encoding it here makes it survive a new contributor, a new session, and a
# tired afternoon.
#
# LICENSE and LICENSES/ are third-party legal text and are never edited.
# The character is built from its code point rather than written literally, so
# this file does not trip its own check.
em="$(printf '\342\200\224')"
emdash="$(git ls-files | grep -vE '^(LICENSE$|LICENSES/)' | xargs grep -lF "$em" 2>/dev/null || true)"
if [ -n "$emdash" ]; then
  echo "em dashes (U+2014) found in:"
  printf '  %s\n' $emdash
  echo
  echo "Use a comma, a colon, a semicolon, or parentheses. Never an em dash."
  exit 1
fi
echo "OK"

step "go vet"
make vet

step "licence boundary (no Apache-tier package imports an AGPL-tier one)"
make license-check

step "tests (race detector: the merge gate, not an optional run)"
make test

step "end-to-end demo (seven scenarios, then the independent verifier)"
make demo

echo
echo "gate: OK"
