#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# notes.sh: render the release notes for a version from the commit history.
#
# Commits are read as Conventional Commits (docs/branching.md) and grouped by
# what they mean to someone downstream, breaking changes first. A commit that
# does not follow the convention is not dropped: it lands under "Other changes",
# because a release note that quietly omits a change is worse than an untidy one.
#
# Usage:  scripts/release/notes.sh <version> [previous-tag]
#
# Writes markdown to stdout. Used both as the GitHub release body and as the new
# section prepended to CHANGELOG.md.

set -euo pipefail

VERSION="${1:?usage: notes.sh <version> [previous-tag]}"
PREV="${2:-}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [ -z "$PREV" ]; then
  PREV="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)"
fi

if [ -n "$PREV" ]; then
  RANGE="$PREV..HEAD"
else
  RANGE="HEAD"
fi

DATE="$(date -u +%Y-%m-%d)"

# house_style: apply the repository's prose rules to text taken from commit
# messages.
#
# The no-em-dash rule (docs/go-standards.md) is enforced by scripts/ci/gate.sh
# against tracked FILES. Nothing checks commit messages, so a subject written
# with an em dash is legitimate history. This script transcribes subjects into
# CHANGELOG.md, which IS tracked, so without this filter the generator converts
# text the gate never checked into a violation of a rule it does check.
#
# That failure lands at the worst possible moment, which is why it is filtered
# here rather than left to be noticed: phase 1 runs the gate BEFORE writing the
# changelog, so the release branch pushes clean and the gate fails on the release
# PR, where it is a required status check. The release then cannot merge without
# hand-editing generated output, and hand-edited generated output is the thing
# this whole pipeline exists to avoid.
#
# A comma rather than a colon: a conventional subject already carries a colon
# after the type, and a second one reads as a nested clause. The dash is almost
# always introducing an appositive, which a comma renders correctly.
#
# The characters are built from their code points, the same way gate.sh does it,
# so this file does not contain the thing it removes.
house_style() {
  local em en
  em="$(printf '\342\200\224')"  # U+2014 em dash
  en="$(printf '\342\200\223')"  # U+2013 en dash
  sed -E "s/ *${em} */, /g; s/ *${en} */, /g"
}

# section <heading> <subject-pattern>: print the matching subjects as bullets,
# with the conventional prefix stripped so the line reads as prose.
section() {
  local heading="$1" pattern="$2"
  local body
  body="$(git log --no-merges --format='%s' "$RANGE" \
    | grep -E "$pattern" \
    | sed -E 's/^[a-z]+(\([^)]*\))?!?: */- /' \
    | house_style || true)"
  if [ -n "$body" ]; then
    printf '### %s\n\n%s\n\n' "$heading" "$body"
  fi
}

printf '## v%s: %s\n\n' "$VERSION" "$DATE"

if [ -n "$PREV" ]; then
  printf '_Changes since %s._\n\n' "$PREV"
else
  printf '_First tagged release._\n\n'
fi

# Breaking first, and stated as breaking: pre-1.0 the version number cannot carry
# that signal (a 0.x breaking change bumps the minor), so this section is the
# only place a consumer learns it.
breaking="$(git log --no-merges --format='%s' "$RANGE" | grep -E '^[a-z]+(\([^)]*\))?!:' | sed -E 's/^[a-z]+(\([^)]*\))?!: */- /' | house_style || true)"
footers="$(git log --no-merges --format='%B' "$RANGE" | grep -E '^BREAKING[ -]CHANGE: ' | sed -E 's/^BREAKING[ -]CHANGE: */- /' | house_style || true)"
if [ -n "$breaking$footers" ]; then
  printf '### Breaking changes\n\n'
  [ -n "$breaking" ] && printf '%s\n' "$breaking"
  [ -n "$footers" ] && printf '%s\n' "$footers"
  printf '\n'
fi

section 'Features'      '^feat(\([^)]*\))?!?: '
section 'Fixes'         '^fix(\([^)]*\))?!?: '
section 'Security'      '^sec(\([^)]*\))?!?: '
section 'Performance'   '^perf(\([^)]*\))?!?: '
section 'Documentation' '^docs(\([^)]*\))?!?: '

# Unconventional subjects have no prefix to strip, so the bullet is added in a
# second pass: matching the convention decides the GROUPING, never whether a
# change is listed at all.
other="$(git log --no-merges --format='%s' "$RANGE" \
  | grep -Ev '^(feat|fix|sec|perf|docs)(\([^)]*\))?!?: ' \
  | sed -E 's/^[a-z]+(\([^)]*\))?!?: *//' \
  | sed -E 's/^/- /' \
  | house_style || true)"
if [ -n "$other" ]; then
  printf '### Other changes\n\n%s\n\n' "$other"
fi

cat <<'EOF'
### Verifying what you downloaded

Each archive is listed in `SHA256SUMS`, every binary answers `--version`
without running anything, and every artifact carries signed build provenance
binding it to this repository's release pipeline:

```sh
sha256sum -c SHA256SUMS
gh attest verify kessa_*_linux_amd64.tar.gz --repo Gneiss-Group/Kessa
./kessa --version
```

The verifier bundle (`kessa_*`) is Apache-2.0; the server bundle
(`kessa-server_*`) is AGPL-3.0-only. See `LICENSING.md`.

### Container images

Multi-arch (linux/amd64 + arm64), distroless, signed with build provenance:

```sh
docker pull ghcr.io/gneiss-group/kessa:VERSION          # verifier (Apache-2.0)
docker pull ghcr.io/gneiss-group/kessa-proxy:VERSION    # enforcement proxy (AGPL-3.0-only)
gh attest verify oci://ghcr.io/gneiss-group/kessa:VERSION --repo Gneiss-Group/Kessa
```
EOF
