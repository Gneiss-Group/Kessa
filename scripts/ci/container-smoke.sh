#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# container-smoke.sh: start the proxy image the way its own Dockerfile says to,
# and prove both listeners actually answer.
#
# WHY THIS EXISTS. `docker/proxy.Dockerfile`'s CMD shipped for months in a state
# where it could not start: it binds 0.0.0.0, the binary refuses a non-loopback
# bind without `--allow-unauthenticated-remote`, and the flag was not there, so
# every container built from that image exited 2 before binding anything. Nothing
# caught it because nothing ran it. `docker/demo.sh` builds the same image and
# then exercises `run` (batch mode), which never reaches the listener path at all,
# and the Go tests exercise the handlers without going near the container.
#
# That is the same class as the CLA bot and the release-owner guard: a gate that
# always fails looks exactly like a gate that never had to fire. The correction is
# not a sharper reading of the Dockerfile, it is running the thing.
#
# HOW IT AVOIDS BEING THE SAME KIND OF TEST. Two properties do the work:
#
#   1. The run arguments are READ OUT OF THE BUILT IMAGE (`docker inspect`), not
#      restated here. Deleting `--allow-unauthenticated-remote` from the CMD makes
#      this script fail, which a hand-written `docker run serve --http-addr ...`
#      would not: that would test a command line this file made up, and would have
#      passed happily against the broken image.
#   2. The probes reach a LISTENER and read the response body. "The container is
#      still running" is not evidence: the bug being guarded against was an
#      immediate exit, but the next one might not be, and a liveness check that a
#      dead listener can pass is the shape this whole file exists to reject.
#
# Deliberately NOT in scripts/ci/gate.sh. The gate has no non-Go dependencies (see
# scripts/reusecheck and scripts/ci/secret-scan.sh, both of which exist to keep it
# that way), and Docker is the largest non-Go dependency there is. This runs as its
# own CI job instead, in parallel, so it costs no gate wall-clock.
#
# Requires a running Docker daemon.
#
# Usage:  scripts/ci/container-smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROXY_IMAGE="kessa-proxy:smoke"
ISSUER_IMAGE="kessa-issuer:smoke"
VOLUME="kessa_smoke_pub"
CONTAINER="kessa-smoke-proxy"

# Host ports deliberately offset from the container's 8181/8182 so a developer
# running this locally does not collide with a proxy they already have up, and so
# a passing probe cannot possibly be talking to one.
HTTP_PORT=18181
MCP_PORT=18182

GATEKEEPER="did:web:localhost:proxies:gatekeeper"
STATUS="https://localhost/orgs/acme/status.json=/pub/localhost/orgs/acme/status.json"

# The MCP revision the listener speaks (internal/enforce/mcp.go, mcpProtocolVersion).
# Restated here because the probe is an external client and has to send it like
# one. If the listener's revision moves, this fails loudly, which is correct: a
# revision bump that no client noticed is not a bump anyone has verified.
MCP_VERSION="2026-07-28"

step() { printf '\n=== %s ===\n' "$1"; }
fail() {
  printf '\ncontainer-smoke: FAIL: %s\n' "$1" >&2
  if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
    printf '\n--- container logs ---\n' >&2
    docker logs "$CONTAINER" >&2 2>&1 || true
    printf '\n--- container state ---\n' >&2
    docker container inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "$CONTAINER" >&2 || true
  fi
  exit 1
}

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "build the issuer and proxy images from source"
docker build -q -f docker/issuer.Dockerfile -t "$ISSUER_IMAGE" .
docker build -q -f docker/proxy.Dockerfile -t "$PROXY_IMAGE" .
echo "OK"

step "publish did:web documents and a signed status list into a shared volume"
# The proxy resolves DIDs only from a local directory (did.FileResolver, no network
# path), so it cannot start against an empty root: --dids is its trust root and a
# missing enforcement-point document is a startup failure, not a runtime one. The
# publish step therefore has to precede serving, exactly as any real deployment's
# does. Root here only so the shared volume is writable, matching docker/demo.sh.
docker volume rm "$VOLUME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null
docker run --rm --user 0:0 \
  -v "$VOLUME:/pub" -v "$ROOT/scripts/demo:/in:ro" \
  "$ISSUER_IMAGE" publish \
  --spec /in/spec.json --keystore /in/keystore.json \
  --root /pub --out /pub/chain.json >/dev/null
echo "OK"

step "read the image's own default command"
# The whole point: these arguments come out of the built image, so this script
# tests the CMD that ships rather than one it invented. Restating the flags here
# would have passed against the broken image.
CMD_ARGS=()
while IFS= read -r arg; do
  [ -n "$arg" ] && CMD_ARGS+=("$arg")
done < <(docker inspect --format '{{range .Config.Cmd}}{{println .}}{{end}}' "$PROXY_IMAGE")

if [ "${#CMD_ARGS[@]}" -eq 0 ]; then
  fail "$PROXY_IMAGE declares no CMD; there is nothing for this test to exercise"
fi
if [ "${CMD_ARGS[0]}" != "serve" ]; then
  fail "$PROXY_IMAGE's CMD starts with '${CMD_ARGS[0]}', not 'serve'; this test appends serving configuration and would be testing nothing"
fi
printf 'CMD: %s\n' "${CMD_ARGS[*]}"

step "start the proxy from that command, adding only deployment configuration"
# No --user: the image's own USER (nonroot, uid 65532) is part of what is under
# test. The appended flags are the four buildProxy requires plus the status list;
# none of them touch the bind posture, which is the CMD's business and stays the
# CMD's business.
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$HTTP_PORT:8181" \
  -p "127.0.0.1:$MCP_PORT:8182" \
  -v "$VOLUME:/pub" \
  -v "$ROOT/scripts/demo:/in:ro" \
  -v "$ROOT/examples/policies:/policies:ro" \
  "$PROXY_IMAGE" "${CMD_ARGS[@]}" \
  --policy /policies/commerce-security.json \
  --dids /pub \
  --enforcement-point "$GATEKEEPER" \
  --keystore /in/keystore.json \
  --status "$STATUS" >/dev/null

# Wait for the HTTP listener to answer, not for the container to merely exist. A
# container that exited 2 is caught here by the readiness loop failing, and the
# explicit running check turns that into a precise message rather than a timeout.
step "wait for the HTTP listener"
ready=""
for _ in $(seq 1 60); do
  if ! docker container inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    fail "the container exited before its listener came up (this is the shape of the CMD bug this test exists for)"
  fi
  if curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT/tip" 2>/dev/null; then
    ready=yes
    break
  fi
  sleep 0.5
done
[ -n "$ready" ] || fail "the HTTP listener never answered on 127.0.0.1:$HTTP_PORT"
echo "OK"

step "GET /tip returns the next entry's slot"
tip="$(curl -fsS "http://127.0.0.1:$HTTP_PORT/tip")" || fail "GET /tip failed"
printf '%s\n' "$tip"
# Assert on the payload, not the status code: a 200 with an unrelated body would
# mean this is talking to something that is not the enforcement engine.
case "$tip" in
  *'"seq"'*'"prevHash"'*) ;;
  *) fail "GET /tip returned a body that is not an enforce.Tip: $tip" ;;
esac
echo "OK"

step "the MCP-native listener answers a real tools/list call"
# A full, valid request rather than a cheap 405 probe: the metadata contract
# (matching Mcp-Method header, params._meta protocolVersion and an OBJECT
# clientCapabilities) is enforced before dispatch, so anything less would confirm
# the port is open without confirming the listener works.
mcp_body='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"'"$MCP_VERSION"'","io.modelcontextprotocol/clientCapabilities":{}}}}'
mcp="$(curl -fsS -X POST "http://127.0.0.1:$MCP_PORT/" \
  -H 'Content-Type: application/json' \
  -H "MCP-Protocol-Version: $MCP_VERSION" \
  -H 'Mcp-Method: tools/list' \
  -d "$mcp_body")" || fail "the MCP tools/list call failed"
printf '%s\n' "$mcp"
case "$mcp" in
  *'"error"'*) fail "the MCP listener answered tools/list with a JSON-RPC error: $mcp" ;;
esac
# Both tools, by name. "a result came back" would pass against a listener that
# had lost one of them.
case "$mcp" in
  *'kessa/tip'*'kessa/enforce'*) ;;
  *'kessa/enforce'*'kessa/tip'*) ;;
  *) fail "tools/list did not advertise both kessa/tip and kessa/enforce: $mcp" ;;
esac
echo "OK"

echo
echo "container-smoke: OK"
