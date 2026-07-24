#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# next-version.sh — decide the version of the next release.
#
# The input is the commit history since the last release tag, read as
# Conventional Commits (docs/branching.md). The output, on stdout, is a bare
# semantic version; the reasoning goes to stderr so a human reading the workflow
# log can see WHY the number moved.
#
# Usage:
#   scripts/release/next-version.sh [auto|patch|minor|major]
#
# "auto" (the default) derives the bump from the commits:
#
#   BREAKING CHANGE / type!:   breaking change
#   feat:                      new capability
#   anything else              fix, docs, chore, refactor, test, perf, ci, build
#
# and maps it to a bump according to where the current version sits:
#
#   >= 1.0.0    breaking -> MAJOR   feat -> MINOR   other -> PATCH
#   <  1.0.0    breaking -> MINOR   feat -> MINOR   other -> PATCH
#
# The pre-1.0 row is the semver rule for 0.x: the public API is not yet declared
# stable, so a breaking change cannot consume the major. It is called out in the
# release notes instead, which is where a 0.x consumer has to read it anyway.
#
# The first release is special: with no tag to diff against there is no history
# to derive a bump from, so it ships the version the source already carries.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BUMP="${1:-auto}"
case "$BUMP" in
  auto|patch|minor|major) ;;
  *) echo "next-version.sh: unknown bump '$BUMP' (want auto|patch|minor|major)" >&2; exit 2 ;;
esac

CURRENT="$(scripts/release/version.sh)"
LAST_TAG="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)"

if [ -z "$LAST_TAG" ]; then
  echo "next-version.sh: no release tag exists yet — this is the first release." >&2
  echo "                 shipping the version the source carries: $CURRENT" >&2
  printf '%s\n' "$CURRENT"
  exit 0
fi

echo "next-version.sh: last release $LAST_TAG, current source version $CURRENT" >&2

if [ "$LAST_TAG" != "v$CURRENT" ]; then
  echo "next-version.sh: the source says $CURRENT but the newest tag is $LAST_TAG." >&2
  echo "                 These must agree before a release: the tag is cut from the" >&2
  echo "                 commit that sets the constant. Reconcile them first." >&2
  exit 1
fi

RANGE="$LAST_TAG..HEAD"
COUNT="$(git rev-list --count "$RANGE")"
if [ "$COUNT" -eq 0 ]; then
  echo "next-version.sh: no commits since $LAST_TAG — there is nothing to release." >&2
  exit 1
fi
echo "next-version.sh: $COUNT commit(s) in $RANGE" >&2

if [ "$BUMP" = "auto" ]; then
  BREAKING=0
  FEAT=0

  # Subjects decide type; the "!" marker and a BREAKING CHANGE footer both mean
  # breaking. Read subjects and bodies separately so a "feat:" quoted inside a
  # body cannot promote a release on its own.
  while IFS= read -r subject; do
    [ -z "$subject" ] && continue
    if printf '%s' "$subject" | grep -Eq '^[a-z]+(\([^)]*\))?!:'; then
      BREAKING=1
      echo "  breaking: $subject" >&2
    elif printf '%s' "$subject" | grep -Eq '^feat(\([^)]*\))?:'; then
      FEAT=1
      echo "  feature:  $subject" >&2
    fi
  done < <(git log --format='%s' "$RANGE")

  if git log --format='%b' "$RANGE" | grep -Eq '^BREAKING[ -]CHANGE:'; then
    BREAKING=1
    echo "  breaking: a BREAKING CHANGE footer is present" >&2
  fi

  MAJOR_CUR="${CURRENT%%.*}"
  if [ "$BREAKING" -eq 1 ]; then
    if [ "$MAJOR_CUR" = "0" ]; then BUMP=minor; else BUMP=major; fi
  elif [ "$FEAT" -eq 1 ]; then
    BUMP=minor
  else
    BUMP=patch
  fi
  echo "next-version.sh: derived bump = $BUMP" >&2
else
  echo "next-version.sh: bump forced to $BUMP by the release operator" >&2
fi

# Split on dots, dropping any pre-release/build metadata: a release is always cut
# to a clean MAJOR.MINOR.PATCH.
BASE="${CURRENT%%-*}"; BASE="${BASE%%+*}"
IFS='.' read -r MA MI PA <<<"$BASE"

case "$BUMP" in
  major) MA=$((MA + 1)); MI=0; PA=0 ;;
  minor) MI=$((MI + 1)); PA=0 ;;
  patch) PA=$((PA + 1)) ;;
esac

NEXT="$MA.$MI.$PA"
echo "next-version.sh: $CURRENT -> $NEXT" >&2
printf '%s\n' "$NEXT"
