#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# changelog.sh — insert a release's notes into CHANGELOG.md, newest first.
#
# Insertion is anchored to a marker line rather than a line count, so editing the
# preamble cannot silently start writing releases into the middle of a sentence.
#
# Usage:  scripts/release/changelog.sh <notes-file>

set -euo pipefail

NOTES="${1:?usage: changelog.sh <notes-file>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

FILE="CHANGELOG.md"
MARKER="<!-- releases below; newest first -->"

if [ ! -f "$FILE" ]; then
  echo "changelog.sh: $FILE does not exist" >&2
  exit 1
fi
if ! grep -qF "$MARKER" "$FILE"; then
  echo "changelog.sh: $FILE has no insertion marker ($MARKER)" >&2
  exit 1
fi

tmp="$(mktemp)"
inserted=0
while IFS= read -r line; do
  printf '%s\n' "$line"
  if [ "$inserted" -eq 0 ] && [ "$line" = "$MARKER" ]; then
    printf '\n'
    cat "$NOTES"
    inserted=1
  fi
done <"$FILE" >"$tmp"

mv "$tmp" "$FILE"
echo "changelog.sh: inserted $(head -n1 "$NOTES") into $FILE"
