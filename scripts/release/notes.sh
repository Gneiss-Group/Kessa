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

# FOOTER_EOC marks where one commit message ends, so a footer running to the end
# of its message cannot absorb the start of the next one. It is emitted by the
# --format string, never by a commit.
FOOTER_EOC='@@end-of-commit@@'

# footer_bullets: turn BREAKING CHANGE footers on stdin into markdown bullets,
# INCLUDING their continuation lines.
#
# A footer is a paragraph, not a line. The previous implementation was a single
# `grep -E '^BREAKING[ -]CHANGE: '`, which is line-oriented, so a footer that
# wrapped contributed only its first line and the bullet stopped mid-sentence.
# That is not hypothetical: v0.0.1 shipped "Signer.Public() and did.ResolveKey now
# return crypto.PublicKey;" into CHANGELOG.md and into the GitHub release body,
# ending on a semicolon with the rest discarded. It survived review because a
# truncated footer still reads like a terse note. The v0.1.0 range does it twice,
# and one of those drops the sentence telling operators their scripts will fail,
# which is the only part of the note that asks anyone to do anything.
#
# A footer therefore ends at the first of: a blank line, another footer token, or
# the end of its commit message. The middle terminator is what keeps a trailing
# `Co-Authored-By:` out of the release notes; v0.0.1's second footer has one, so
# reading to end-of-message is not an option.
#
# The footer-token terminator can in principle cut a wrapped line that happens to
# begin `Word: `. That is the safe direction (it truncates rather than swallowing
# an unrelated trailer) and it is what the git trailer convention means by a
# footer, but it is a choice rather than a certainty, so it is stated here.
#
# Line-oriented with an explicit delimiter rather than a NUL record separator:
# awk's RS is not portably assignable to NUL, and this script runs on whatever
# awk the runner has.
footer_bullets() {
  awk -v eoc="$FOOTER_EOC" '
    function flush() {
      if (collecting && acc != "") print "- " acc
      collecting = 0
      acc = ""
    }
    $0 == eoc { flush(); next }
    /^BREAKING[ -]CHANGE: / {
      flush()
      acc = $0
      sub(/^BREAKING[ -]CHANGE: /, "", acc)
      collecting = 1
      next
    }
    {
      if (!collecting) next
      if ($0 ~ /^[[:space:]]*$/) { flush(); next }
      if ($0 ~ /^[A-Za-z][A-Za-z-]*: /) { flush(); next }
      acc = acc " " $0
    }
    END { flush() }
  '
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
footers="$(git log --no-merges --format="%B%n${FOOTER_EOC}" "$RANGE" | footer_bullets | house_style || true)"
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

# The heredoc stays QUOTED so nothing in these shell examples is expanded by the
# shell generating them, which is what keeps a future `$HOME` or `$(...)` in an
# example from being evaluated here. The consequence is that $VERSION does not
# expand either, so the one place that needs it uses a placeholder token and an
# explicit substitution below. The previous spelling was a bare "VERSION", which
# read like an intentional fill-in-the-blank and shipped in v0.0.1 as a docker
# pull nobody could copy.
cat <<'EOF' | sed "s/@@VERSION@@/$VERSION/g"
### Verifying what you downloaded

Each archive is listed in `SHA256SUMS`, every binary answers `--version`
without running anything, and every artifact carries signed build provenance
binding it to this repository's release pipeline:

```sh
sha256sum -c SHA256SUMS
gh attestation verify kessa_*_linux_amd64.tar.gz --repo Gneiss-Group/Kessa
./kessa --version
```

The verifier bundle (`kessa_*`) is Apache-2.0; the server bundle
(`kessa-server_*`) is AGPL-3.0-only. See `LICENSING.md`.

### Container images

Multi-arch (linux/amd64 + arm64), distroless, signed with build provenance:

```sh
docker pull ghcr.io/gneiss-group/kessa:@@VERSION@@          # verifier (Apache-2.0)
docker pull ghcr.io/gneiss-group/kessa-proxy:@@VERSION@@    # enforcement proxy (AGPL-3.0-only)
gh attestation verify oci://ghcr.io/gneiss-group/kessa:@@VERSION@@ --repo Gneiss-Group/Kessa
```
EOF
