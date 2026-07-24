#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# fixture-guard.sh — refuse to release on a golden fixture that moved without
# anyone saying so.
#
# The goldens in testdata/ are not test data in the ordinary sense. They freeze
# the audit export format, and the project's central claim is made about that
# format: an export carries the evidence a verifier re-derives every verdict
# from, and a v1 export carries none and must never read as a clean pass. A
# golden that changes quietly is the one change that can invalidate that claim
# while every test still goes green — because the goldens are what the tests
# compare against.
#
# So a release asks four questions:
#
#   1. Are the goldens reproducible from the code? `make fixtures` must be a
#      no-op in git. If regenerating them changes a byte, the committed fixture
#      is not what this source produces, and a hand-edited golden is exactly the
#      shape a tampered fixture would take.
#   2. Does the evidence-carrying golden still verify clean? A v2 export must
#      PASS with its evidence intact.
#   3. Does the evidence-free golden still refuse to pass? A v1 export must come
#      back DOWNGRADED with a non-zero exit. "Integrity-only reads as a pass" is
#      the failure this fixture exists to catch.
#   4. If a golden did move since the last release, was the format history
#      updated to say what changed and why (the discipline the `fixtures` target
#      in the Makefile states), and did a human acknowledge it?
#
# Usage:  scripts/release/fixture-guard.sh
#
# Env:
#   KESSA_FIXTURE_ACK=true   the release operator has reviewed a golden change
#   GITHUB_OUTPUT            if set, `fixtures_changed=<bool>` is written to it
#
# Exit: 0 = safe to release, 1 = a question above was answered wrong.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

V2_GOLDEN="testdata/audit_export_v2.golden.json"
V1_GOLDEN="testdata/audit_export.golden.json"
DIDS="testdata/dids"
STATUS_URL="https://localhost/orgs/acme/status.json"
STATUS_FILE="testdata/status/acme_status.json"
# Where a change to the frozen export format must be recorded. This was the
# round-2 fixes doc; that file was removed pending a consolidated security-review
# document. CHANGELOG.md is the interim home — a format change is release-notable
# by definition. Repoint this to the consolidated security doc once it lands, if
# that is where the format history should live.
FORMAT_HISTORY="CHANGELOG.md"

fail=0
note() { printf '  %s\n' "$1"; }
bad()  { printf 'FIXTURE GUARD: %s\n' "$1" >&2; fail=1; }

# ---- 1. the goldens must be reproducible from the source --------------------

echo "== fixtures are reproducible from source =="
# Scoped to testdata/, which is everything `make fixtures` writes: an unrelated
# edit elsewhere in the tree says nothing about whether a golden reproduces.
if [ -n "$(git status --porcelain -- testdata/)" ]; then
  bad "testdata/ is dirty before regeneration; cannot tell reproduction from local edits"
  git status --porcelain -- testdata/ >&2
else
  make -s fixtures >/dev/null
  drift="$(git status --porcelain -- testdata/)"
  if [ -n "$drift" ]; then
    bad "regenerating the fixtures changed the tree — the committed goldens are not what this source produces"
    printf '%s\n' "$drift" >&2
    git --no-pager diff --stat -- testdata/ >&2
  else
    note "OK — make fixtures is a no-op in git"
  fi
fi

# ---- 2 & 3. the goldens must still mean what they mean -----------------------

echo "== the goldens still hold the invariants they exist to freeze =="
make -s verify >/dev/null

set +e
v2_out="$(bin/kessa verify --export "$V2_GOLDEN" --dids "$DIDS" --status "$STATUS_URL=$STATUS_FILE" --quiet --color=never 2>&1)"
v2_code=$?
v1_out="$(bin/kessa verify --export "$V1_GOLDEN" --dids "$DIDS" --quiet --color=never 2>&1)"
v1_code=$?
set -e

if [ "$v2_code" -ne 0 ] || ! printf '%s' "$v2_out" | grep -q 'VERDICT: PASS'; then
  bad "the v2 golden no longer verifies clean (exit $v2_code) — evidence-backed verification is broken or the fixture moved"
  printf '%s\n' "$v2_out" >&2
else
  note "OK — v2 golden: PASS, evidence re-derived"
fi

if [ "$v1_code" -eq 0 ] || ! printf '%s' "$v1_out" | grep -q 'VERDICT: DOWNGRADED'; then
  bad "the v1 golden did not come back DOWNGRADED with a non-zero exit (exit $v1_code) — an evidence-free export must never read as a clean pass"
  printf '%s\n' "$v1_out" >&2
else
  note "OK — v1 golden: DOWNGRADED, exit $v1_code, not a clean pass"
fi

# ---- 4. a golden that moved needs a stated reason and an acknowledgement -----

echo "== golden drift since the last release =="
last_tag="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)"
fixtures_changed=false

if [ -z "$last_tag" ]; then
  note "no previous release tag — nothing to diff against (first release)"
else
  changed="$(git diff --name-only "$last_tag..HEAD" -- testdata/ || true)"
  goldens="$(printf '%s\n' "$changed" | grep -E 'golden\.json$' || true)"
  if [ -z "$goldens" ]; then
    note "OK — no golden fixture changed since $last_tag"
  else
    fixtures_changed=true
    echo "  golden fixtures changed since $last_tag:" >&2
    printf '%s\n' "$goldens" | sed 's/^/    /' >&2

    if git diff --quiet "$last_tag..HEAD" -- "$FORMAT_HISTORY"; then
      bad "a golden moved but $FORMAT_HISTORY did not. Regenerating a golden means the frozen export format changed; it needs an entry in $FORMAT_HISTORY saying what changed and why (see the 'fixtures' target in the Makefile)."
    else
      note "OK — $FORMAT_HISTORY was updated in the same range"
    fi

    if [ "${KESSA_FIXTURE_ACK:-false}" != "true" ]; then
      bad "a golden moved and the release was not run with the fixture change acknowledged. Re-run the release workflow with 'fixtures_reviewed' checked once you have read the diff above."
    else
      note "OK — the release operator acknowledged the golden change"
    fi
  fi
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "fixtures_changed=$fixtures_changed" >>"$GITHUB_OUTPUT"
fi

if [ "$fail" -eq 0 ]; then
  echo "fixture-guard: OK"
else
  echo "fixture-guard: FAILED — see above" >&2
fi
exit "$fail"
