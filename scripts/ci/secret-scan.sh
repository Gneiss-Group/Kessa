#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# secret-scan.sh — scan the tree for committed credentials.
#
# This is the portable half of Kessa's secret-scanning posture. It depends only
# on the Go toolchain (already required to build Kessa) and the version-controlled
# .gitleaks.toml, so it runs identically in GitHub Actions and in the Codeberg
# mirror's CI — neither of which can rely on the other forge's built-in scanner.
# The forge-native scanners (GitHub secret scanning, configured in
# .github/secret_scanning.yml) are a second layer on top of this one, not a
# substitute for it.
#
# gitleaks is pinned and built from source rather than pulled as a prebuilt
# binary: for a project whose whole thesis is "don't trust an artifact you did
# not build," fetching an opaque scanner binary would be the wrong pattern.
#
# Usage:  scripts/ci/secret-scan.sh
#
# Exit: 0 = clean, 1 = a non-allowlisted secret was found, 2 = setup error.

set -euo pipefail

# The canonical module path is zricethezav/... even though the project now lives
# at gitleaks/gitleaks; the module never renamed itself. Pinned for reproducible
# scans: an unpinned scanner can change findings out from under a green history.
GITLEAKS_MODULE="github.com/zricethezav/gitleaks/v8"
GITLEAKS_VERSION="v8.30.1"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Resolve a gitleaks binary: one already on PATH wins (a developer's local
# install, or a CI cache); otherwise build the pinned version with the Go
# toolchain that is already present because this is a Go project.
if command -v gitleaks >/dev/null 2>&1; then
  GL="$(command -v gitleaks)"
else
  echo "secret-scan: gitleaks not on PATH; building $GITLEAKS_VERSION from source"
  GOBIN="$(go env GOPATH)/bin"
  GOFLAGS='' go install "${GITLEAKS_MODULE}@${GITLEAKS_VERSION}" || {
    echo "secret-scan: failed to install gitleaks" >&2
    exit 2
  }
  GL="$GOBIN/gitleaks"
fi

if [ ! -x "$GL" ]; then
  echo "secret-scan: no usable gitleaks binary at '$GL'" >&2
  exit 2
fi

report="$(mktemp -t gitleaks-report.XXXXXX.json)"
trap 'rm -f "$report"' EXIT

echo "secret-scan: scanning the working tree with .gitleaks.toml"
# --redact keeps any hit out of the CI log (these are demo values, but printing a
# matched "secret" into a public build log is a habit worth never forming).
# `dir` scans the tree as it stands — the state a merge would produce — rather
# than walking history, which keeps the gate deterministic and clone-depth
# independent. A one-time full-history sweep (`gitleaks git`) is worth running
# before the repository is first made public.
if "$GL" dir . \
  --config .gitleaks.toml \
  --redact \
  --no-banner \
  --report-format json \
  --report-path "$report"; then
  echo "secret-scan: OK — no non-allowlisted secrets"
  exit 0
fi

count="$(grep -c '"RuleID"' "$report" 2>/dev/null || echo '?')"
echo "::error::secret-scan found $count potential credential(s) not covered by the .gitleaks.toml allowlist."
echo "secret-scan: if a finding is a deliberate demo/fixture value, add it to the"
echo "             allowlist in .gitleaks.toml AND record it in SECURITY.md; do not"
echo "             suppress a real one. Findings (redacted):"
# Surface file:line and rule without the secret value.
grep -E '"(RuleID|File|StartLine)"' "$report" | sed 's/^/    /' || true
exit 1
