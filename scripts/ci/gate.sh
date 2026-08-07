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

step "licence on every tracked file, and only one per file"
# This step used to walk a glob of source extensions and check each file had an
# inline SPDX header. That shape was wrong and was recorded as known debt in
# docs/go-standards.md: it enumerated its inclusions, so any file type nobody
# thought of went unchecked (docker/demo/requests.json did, and nothing said so),
# and it could not be widened, because a dozen files carry no inline header by
# design and are licensed through REUSE.toml annotations instead. The fix that
# note called for was "a checker that accepts a header OR an annotation", and
# scripts/reusecheck is it.
#
# It starts from the complete tracked set, so no file type can fall outside it,
# and it is stricter than the FSFE's `reuse lint` in the place that matters: it
# fails when the repository states TWO licences for one file. REUSE resolves that
# case silently by precedence, which is how docs/enrollment.md carried an
# AGPL-3.0-only header under a glob claiming Apache-2.0 without any tool objecting.
#
# It is written in Go rather than installed, because scripts/ci/secret-scan.sh
# next door already answered this question for third-party tooling: pinned and
# built from source, never fetched as an opaque artifact. A pip install here would
# contradict the script beside it. See scripts/reusecheck/main.go.
go run ./scripts/reusecheck
echo "OK"

step "no em dashes (house style, enforced not remembered)"
# The check itself lives in scripts/ci/prose-check.sh because release.yml calls
# it a second time, after it generates CHANGELOG.md and before it pushes the
# release branch. The gate runs at the START of a release, so it cannot speak for
# a file the release has not written yet. One implementation, two moments.
bash scripts/ci/prose-check.sh

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
