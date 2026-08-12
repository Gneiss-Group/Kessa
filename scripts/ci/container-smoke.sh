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
# HOW IT AVOIDS BEING THE SAME KIND OF TEST. Three properties do the work:
#
#   1. The proxy is started with NO ARGUMENTS, so the shipped CMD runs verbatim.
#      A hand-written `docker run … serve --http-addr …` tests a command line this
#      file made up, and would have passed happily against the broken image.
#   2. The CMD is still READ OUT OF THE BUILT IMAGE (`docker inspect`) and
#      asserted on: it must name a --config file and must NOT carry bind
#      configuration. Configuration in the CMD is what forced every real
#      invocation to restate the bind posture, and is how the flag came to be
#      missing. Checking the shape means a regression NAMES itself rather than
#      reappearing later as an unreachable listener.
#   3. The probes reach a LISTENER and read the response body. "The container is
#      still running" is not evidence: the bug being guarded against was an
#      immediate exit, but the next one might not be, and a liveness check that a
#      dead listener can pass is the shape this whole file exists to reject.
#
# Configuration now arrives through a mounted file, which is the shape a real
# deployment uses, and the image validates it (--check-config) before the run that
# has to start from it.
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
STATUS_URL="https://localhost/orgs/acme/status.json"
STATUS_FILE="/pub/localhost/orgs/acme/status.json"

# Where the rendered config is written on the host. Set before the cleanup trap so
# a failure between here and the mkdir still tears down cleanly.
CFG_DIR=""

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
  [ -n "$CFG_DIR" ] && rm -rf "$CFG_DIR"
  return 0
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
# Read out of the BUILT IMAGE rather than restated here. Two things depend on it:
# the assertion below names a regression instead of letting it surface as a
# connection refused, and the --check-config run further down exercises the same
# command the real start uses.
CMD_ARGS=()
while IFS= read -r arg; do
  [ -n "$arg" ] && CMD_ARGS+=("$arg")
done < <(docker inspect --format '{{range .Config.Cmd}}{{println .}}{{end}}' "$PROXY_IMAGE")

if [ "${#CMD_ARGS[@]}" -eq 0 ]; then
  fail "$PROXY_IMAGE declares no CMD; there is nothing for this test to exercise"
fi
if [ "${CMD_ARGS[0]}" != "serve" ]; then
  fail "$PROXY_IMAGE's CMD starts with '${CMD_ARGS[0]}', not 'serve'; this test exercises the serving path and would be testing nothing"
fi
# The CMD must name a config file and must NOT carry configuration itself. It used
# to carry the bind flags, which is what forced every real invocation to restate
# them, and is how --allow-unauthenticated-remote came to be missing for months.
# Asserting the shape here means a regression to that says so, rather than
# reappearing as an unreachable listener.
case "${CMD_ARGS[*]}" in
  *--config*) ;;
  *) fail "the CMD does not name a --config file: ${CMD_ARGS[*]}" ;;
esac
case "${CMD_ARGS[*]}" in
  *--http-addr*|*--mcp-addr*|*--allow-unauthenticated-remote*)
    fail "the CMD carries bind configuration again (${CMD_ARGS[*]}); that belongs in the mounted config, or overriding the command silently drops it" ;;
esac
printf 'CMD: %s\n' "${CMD_ARGS[*]}"

# Where the CMD says the config lives, so the mount below follows the image
# rather than a path this script decided.
CFG_IN_CONTAINER=""
for i in "${!CMD_ARGS[@]}"; do
  if [ "${CMD_ARGS[$i]}" = "--config" ]; then
    CFG_IN_CONTAINER="${CMD_ARGS[$((i + 1))]}"
  fi
done
[ -n "$CFG_IN_CONTAINER" ] || fail "the CMD names --config with no path"
printf 'config path inside the image: %s\n' "$CFG_IN_CONTAINER"

step "render the deployment's config"
# Every path here is a path INSIDE the container. This is the shape a real
# deployment uses: configuration is mounted, not spliced into the command line.
CFG_DIR="$(mktemp -d)"
cat > "$CFG_DIR/proxy.json" <<JSON
{
  "comment": "Rendered by scripts/ci/container-smoke.sh. Binds 0.0.0.0 because a container's loopback is unreachable through -p, and says so via allow_unauthenticated_remote.",
  "policy": "/policies/commerce-security.json",
  "dids": "/pub",
  "enforcement_point": {
    "did": "$GATEKEEPER",
    "key": { "mock_keystore": "/in/keystore.json" }
  },
  "http_addr": "0.0.0.0:8181",
  "mcp_addr": "0.0.0.0:8182",
  "allow_unauthenticated_remote": true,
  "audit_log": "",
  "audit_wal": null,
  "status": { "$STATUS_URL": "$STATUS_FILE" }
}
JSON
echo "OK"

MOUNTS=(-v "$VOLUME:/pub"
  -v "$ROOT/scripts/demo:/in:ro"
  -v "$ROOT/examples/policies:/policies:ro"
  -v "$CFG_DIR/proxy.json:$CFG_IN_CONTAINER:ro")

step "the image validates that config before anything is bound"
# --check-config appended to the image's own command, so this exercises the same
# invocation the real start uses. It must succeed WITHOUT the port mappings below:
# a check that needed a bindable port would not be a check.
docker run --rm "${MOUNTS[@]}" "$PROXY_IMAGE" "${CMD_ARGS[@]}" --check-config \
  || fail "the image refused a config it then has to start from"

step "start the proxy from its default command, with NO arguments"
# No arguments at all: the CMD runs verbatim, which is the strongest form of "the
# shipped default works". No --user either, so the image's own nonroot USER is
# part of what is under test.
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$HTTP_PORT:8181" \
  -p "127.0.0.1:$MCP_PORT:8182" \
  "${MOUNTS[@]}" \
  "$PROXY_IMAGE" >/dev/null

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
