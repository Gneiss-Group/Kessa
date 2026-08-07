#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# prose-check.sh: house style, enforced not remembered.
#
# Em dashes are not used anywhere in this repository. The rule and the
# replacement marks are in docs/go-standards.md under "Prose style"; this is the
# enforcement half. It exists because the rule was stated repeatedly and kept
# being broken: a convention that lives only in someone's memory is a convention
# that decays.
#
# This lives in its own file, rather than inline in gate.sh, because it has TWO
# callers that need it at different moments:
#
#   1. gate.sh, as one of the merge/release gate's checks.
#   2. release.yml, AFTER it generates CHANGELOG.md and BEFORE it pushes the
#      release branch.
#
# The second caller is the reason this was split out. The gate runs at the start
# of a release, before the changelog exists, so it can say nothing about the file
# the release is about to create. A generated changelog that violates house style
# therefore used to reach the release PR, where the gate IS a required check, and
# deadlock the release: unmergeable, and unfixable without hand-editing generated
# output. Checking after the write, before the push, is the repository's standing
# rule (validate before the side effect) applied to the side effect that matters
# here, which is the push and not the generation.
#
# It reads the WORKING TREE, not the index, so it sees generated changes that
# have not been committed yet. That is what makes the second caller work.
#
# LICENSE and LICENSES/ are third-party legal text and are never edited.
#
# Usage:  scripts/ci/prose-check.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# The characters are built from their code points rather than written literally,
# so this file does not trip its own check.
em="$(printf '\342\200\224')"  # U+2014 em dash

found="$(git ls-files | grep -vE '^(LICENSE$|LICENSES/)' | xargs grep -lF "$em" 2>/dev/null || true)"
if [ -n "$found" ]; then
  echo "em dashes (U+2014) found in:"
  printf '  %s\n' $found
  echo
  echo "Use a comma, a colon, a semicolon, or parentheses. Never an em dash."
  exit 1
fi
echo "OK"
