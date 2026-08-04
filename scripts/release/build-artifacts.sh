#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# build-artifacts.sh: cross-compile the release bundles and checksum them.
#
# Two bundles per platform, split along the license boundary rather than by
# convenience (LICENSING.md):
#
#   kessa_<version>_<os>_<arch>         the independent verifier and the passive
#                                       shadow tool. Apache-2.0. This is the
#                                       artifact a skeptical evaluator downloads:
#                                       it must be obtainable and runnable
#                                       without accepting a copyleft licence.
#   kessa-server_<version>_<os>_<arch>   the issuer, proxy, and agent. AGPL-3.0.
#
# Shipping them together in one archive would hand the AGPL to someone who only
# wanted the verifier, which is the whole thing the two-tier model avoids.
#
# The builds are CGO-free and stdlib-only, so every platform cross-compiles from
# one runner. No -ldflags: the version is a constant in the source (see
# internal/version), and the commit is stamped by the toolchain's own VCS
# recording, so `go build` from the release tag reproduces the released binary's
# self-identification exactly.
#
# Usage:  scripts/release/build-artifacts.sh <version> <out-dir>

set -euo pipefail

VERSION="${1:?usage: build-artifacts.sh <version> <out-dir>}"
OUT="${2:?usage: build-artifacts.sh <version> <out-dir>}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PLATFORMS=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

# bundle <name> <staging-dir> <os>: archive a staged directory, tar.gz
# everywhere except Windows, which gets a zip.
bundle() {
  local name="$1" dir="$2" os="$3"
  if [ "$os" = "windows" ]; then
    (cd "$(dirname "$dir")" && zip -qr "$OUT/$name.zip" "$(basename "$dir")")
    echo "  $name.zip"
  else
    tar -czf "$OUT/$name.tar.gz" -C "$(dirname "$dir")" "$(basename "$dir")"
    echo "  $name.tar.gz"
  fi
}

for p in "${PLATFORMS[@]}"; do
  os="${p%/*}"; arch="${p#*/}"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"
  echo "building $os/$arch"

  verifier="$WORK/kessa_${VERSION}_${os}_${arch}"
  server="$WORK/kessa-server_${VERSION}_${os}_${arch}"
  mkdir -p "$verifier" "$server"

  # Apache-2.0 tier: the verifier (built from cmd/verify as `kessa`) and shadow.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$verifier/kessa$ext" ./cmd/verify
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$verifier/kessa-shadow$ext" ./cmd/shadow
  cp LICENSES/Apache-2.0.txt "$verifier/LICENSE.txt"
  cp README.md "$verifier/README.md"
  cp LICENSING.md "$verifier/LICENSING.md"

  # AGPL-3.0-only tier: everything that issues authority or decides whether a
  # real action may proceed.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$server/kessa-issuer$ext" ./cmd/issuer
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$server/kessa-proxy$ext" ./cmd/proxy
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$server/kessa-agent$ext" ./cmd/agent
  cp LICENSES/AGPL-3.0-only.txt "$server/LICENSE.txt"
  cp README.md "$server/README.md"
  cp LICENSING.md "$server/LICENSING.md"

  bundle "$(basename "$verifier")" "$verifier" "$os"
  bundle "$(basename "$server")" "$server" "$os"
done

# One checksum file over every archive. Verifying a download is then a single
# command against a single file, which is the only form of that instruction
# anybody actually follows.
(
  cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz ./*.zip >SHA256SUMS
  else
    shasum -a 256 ./*.tar.gz ./*.zip >SHA256SUMS
  fi
)

echo
echo "artifacts in $OUT:"
ls -1 "$OUT"
