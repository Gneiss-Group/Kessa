#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# fuzz-targets.sh: print every native fuzz target as a JSON array, one object per
# target, for use as a GitHub Actions matrix.
#
# The list is DERIVED from the compiled test binaries, never enumerated, for the
# same reason fuzz-smoke.sh derives it: a target added tomorrow should be picked
# up by having been written, not by also being remembered in a second place.
#
# ZERO TARGETS IS AN ERROR, and that guard is the whole reason this is a script
# rather than two lines of inline shell. An empty matrix does not fail a
# workflow: Actions skips the fanned-out job, a skipped job is not a failed one,
# and the run goes green having fuzzed nothing. That is precisely the
# passes-by-not-running shape this repository keeps finding, and a scheduled job
# is where it would survive longest, because nobody is watching a green cron.
#
# Usage:  scripts/ci/fuzz-targets.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

first=1
printf '['
for pkg in $(go list ./...); do
  targets="$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)"
  [ -n "$targets" ] || continue
  for t in $targets; do
    [ "$first" -eq 1 ] || printf ','
    first=0
    # `name` is what shows in the Actions UI and must be UNIQUE: FuzzParse
    # exists in both internal/export and internal/policy, so the target name
    # alone would label two different jobs identically and make a failure
    # ambiguous at exactly the moment it matters.
    printf '{"pkg":"%s","target":"%s","name":"%s/%s"}' "$pkg" "$t" "${pkg##*/}" "$t"
  done
done
printf ']\n'

if [ "$first" -eq 1 ]; then
  echo "fuzz-targets: no fuzz targets found; the campaign would fuzz nothing." >&2
  exit 1
fi
