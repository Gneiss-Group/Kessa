#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# version.sh: read or set the single source of truth for Kessa's version.
#
# That source is the `Version` constant in internal/version/version.go, and it is
# a constant on purpose (see the package doc): the version a binary prints is the
# version its source said, so anyone can rebuild a release from its tag and get a
# binary that identifies itself identically. Nothing is injected at link time.
#
# Usage:
#   scripts/release/version.sh            print the current version
#   scripts/release/version.sh 0.2.0      rewrite the constant to 0.2.0
#
# Reading and writing live in one script so the two can never disagree about
# where the number lives or what shape it has.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FILE="$ROOT/internal/version/version.go"

# SEMVER is semantic versioning 2.0.0 without the leading "v" (the git tag adds
# that). Anchored: "1.2" and "v1.2.3" are rejected, not silently accepted.
SEMVER='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'

read_version() {
  local v
  v="$(sed -n 's/^const Version = "\(.*\)"$/\1/p' "$FILE")"
  if [ -z "$v" ]; then
    echo "version.sh: no 'const Version = \"...\"' line in $FILE" >&2
    return 1
  fi
  if [ "$(printf '%s\n' "$v" | wc -l | tr -d ' ')" != "1" ]; then
    echo "version.sh: more than one Version constant in $FILE" >&2
    return 1
  fi
  printf '%s\n' "$v"
}

write_version() {
  local new="$1"
  if ! printf '%s' "$new" | grep -Eq "$SEMVER"; then
    echo "version.sh: '$new' is not semantic versioning (MAJOR.MINOR.PATCH, no leading v)" >&2
    return 1
  fi
  # Rewrite via a temp file so a failed sed cannot leave a half-written source
  # file behind, and read the value back so the commit that follows is provably
  # the version we intended.
  local tmp
  tmp="$(mktemp)"
  sed "s/^const Version = \".*\"$/const Version = \"$new\"/" "$FILE" >"$tmp"
  mv "$tmp" "$FILE"
  local got
  got="$(read_version)"
  if [ "$got" != "$new" ]; then
    echo "version.sh: wrote '$new' but $FILE now reads '$got'" >&2
    return 1
  fi
  printf '%s\n' "$new"
}

if [ $# -eq 0 ]; then
  read_version
else
  write_version "$1"
fi
