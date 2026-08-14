#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# gate-full.sh: the core gate, plus everything that lives in a nested module.
#
# WHY THERE ARE TWO GATES
#
# scripts/ci/gate.sh is deliberately offline-hermetic. The core module has no
# third-party dependencies, so that gate needs no network at all, and it now
# asserts that property rather than merely benefiting from it. That is worth
# protecting: an air-gapped build and demo is a real property of the product, and
# a gate a contributor can run on a plane is a real property of the project.
#
# experimental/policy-opa is a nested module that depends on OPA, which arrives
# with roughly a hundred transitive modules. Checking it means resolving those,
# which means a network fetch on a cold cache. Folding that into gate.sh would
# have quietly cost the offline property to pay for an experiment that is not
# even shipped.
#
# WHY THIS IS COMPOSITION AND NOT A SECOND COPY
#
# This script CALLS gate.sh rather than reimplementing it, so it is a superset by
# construction. gate.sh's own header makes the point that one script is what stops
# CI and the release from checking different things; two parallel gates that each
# grew their own steps would reintroduce exactly that drift, one commit at a time.
# Nothing is checked here that is not checked there, only more.
#
# WHERE EACH ONE RUNS, WHICH IS THE PART THAT MATTERS
#
#   contributors, offline work, the demo box   ->  gate.sh
#   CI, on every PR                            ->  gate-full.sh  (this file)
#   release phases                             ->  gate.sh
#
# CI must run THIS one. If both CI and contributors ran the offline gate, the
# nested module would be covered by a check that exists and never executes, which
# is the failure this project has now hit often enough to name. The release runs
# the offline gate because experimental/ is not in the release artifact; a release
# is not the place to discover that an unshipped experiment stopped compiling.
#
# Usage:  scripts/ci/gate-full.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Every nested module: one place, so adding a second one does not mean
# remembering the three separate spots below.
NESTED_MODULES="experimental/policy-opa"

step() { printf '\n=== %s ===\n' "$1"; }

step "core gate (scripts/ci/gate.sh, unchanged and offline)"
bash scripts/ci/gate.sh

# The licence walk is re-run rather than skipped in gate.sh and done only here.
# It repeats the root module's walk, which costs a few seconds and buys the
# property that neither gate depends on the other having run a partial version of
# a check. `--also` is what makes the nested module visible at all: it has its own
# go.mod, so `go list ./...` at the root cannot enumerate it, and every check in
# license-check.sh would otherwise pass while classifying nothing in it.
step "licence boundary, including nested modules"
also_args=""
for m in $NESTED_MODULES; do
  also_args="$also_args --also $m"
done
# shellcheck disable=SC2086
bash scripts/license-check.sh $also_args

for m in $NESTED_MODULES; do
  step "$m: vet"
  ( cd "$m" && go vet ./... )

  # -race for the same reason the core suite uses it: a policy evaluator is held
  # by the enforcement proxy and called from many request goroutines at once, so
  # "safe to share" is part of what an Evaluator implementation has to be, not an
  # optional extra.
  step "$m: tests (race detector)"
  ( cd "$m" && go test -race ./... )

  # A nested module's go.mod can drift out of tidy without anything noticing,
  # since no root-level command reads it. Checked by tidying a COPY and diffing:
  # running `go mod tidy` in place would make the gate fix the problem it is
  # supposed to report, and a gate that repairs its own failures reports nothing.
  step "$m: go.mod is tidy"
  tidy_check="$(mktemp -d)"
  cp "$m/go.mod" "$m/go.sum" "$tidy_check/"
  ( cd "$m" && go mod tidy )
  if ! diff -q "$tidy_check/go.mod" "$m/go.mod" >/dev/null || ! diff -q "$tidy_check/go.sum" "$m/go.sum" >/dev/null; then
    cp "$tidy_check/go.mod" "$tidy_check/go.sum" "$m/"
    rm -rf "$tidy_check"
    echo "$m/go.mod or go.sum is not tidy. Run 'cd $m && go mod tidy' and commit the result."
    exit 1
  fi
  rm -rf "$tidy_check"
  echo "OK"
done

echo
echo "gate-full: OK"
