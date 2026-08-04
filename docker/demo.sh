#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# demo.sh: the containerized end-to-end story. It builds the three tier-split
# images from source and composes them over one shared volume:
#
#   issuer (AGPL)   mints a delegation chain, publishes did:web docs + a signed
#                   status list into /pub
#   proxy  (AGPL)   enforces a batch of action requests against /pub, writing a
#                   signed audit export
#   kessa  (Apache) the INDEPENDENT verifier: re-derives every verdict from the
#                   files in /pub alone, trusting no running service
#
# The point mirrors `make demo`, but as containers: the Apache verifier, in its
# own licence-pure image, checks the AGPL side's output offline. This is the
# software/keystore path: the daemon's hardware backing is a host concern, not a
# container one (see docker/issuer.Dockerfile).
#
# Requires a running Docker daemon. Deterministic (fixed seeds/timestamps), same
# inputs as scripts/demo.sh.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NOW="2026-07-09T12:00:00Z"
ST="https://localhost/orgs/acme/status.json=/pub/localhost/orgs/acme/status.json"
GATEKEEPER="did:web:localhost:proxies:gatekeeper"

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hr "Build the three images from source (provably this repo)"
docker build -q -f docker/issuer.Dockerfile   -t kessa-issuer:demo .
docker build -q -f docker/proxy.Dockerfile    -t kessa-proxy:demo .
docker build -q -f docker/verifier.Dockerfile -t kessa:demo .

# A shared volume is the publication root + artifact drop; the demo inputs (spec,
# keystore, policy, requests) mount read-only.
docker volume rm kessa_demo_pub >/dev/null 2>&1 || true
docker volume create kessa_demo_pub >/dev/null
trap 'docker volume rm kessa_demo_pub >/dev/null 2>&1 || true' EXIT

# Run the demo containers as root so the shared volume is freely writable. This is
# a DEMO convenience only: the published images default to nonroot (uid 65532).
MOUNTS=(--user 0:0
  -v kessa_demo_pub:/pub
  -v "$ROOT/scripts/demo:/in:ro"
  -v "$ROOT/examples/policies:/policies:ro"
  -v "$ROOT/docker/demo:/demo:ro")
run() { docker run --rm "${MOUNTS[@]}" "$@"; }

hr "1. issuer: mint chain + publish did:web docs and a signed status list"
run kessa-issuer:demo publish \
  --spec /in/spec.json --keystore /in/keystore.json \
  --root /pub --out /pub/chain.json

hr "2. proxy: enforce a batch of actions, write a signed export"
run kessa-proxy:demo run \
  --requests /demo/requests.json --policy /policies/commerce-security.json \
  --dids /pub --enforcement-point "$GATEKEEPER" --keystore /in/keystore.json \
  --status "$ST" --now "$NOW" --out /pub/export.json --audit-log ""

hr "3. verifier: re-derive every verdict from files alone (nothing running)"
run kessa:demo verify --export /pub/export.json --dids /pub --status "$ST"

hr "Done"
printf '   Two allows verified, two denies with intact evidence, all re-derived by\n'
printf '   the Apache verifier from the shared directory: no Kessa service trusted.\n'
