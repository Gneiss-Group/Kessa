# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Container image for the enforcement proxy (`kessa-proxy`), the AGPL-3.0 tier.
# This is the sidecar/service artifact: `kessa-proxy serve` is the localhost HTTP
# shell around the enforcement engine that an agent in a separate process (or pod)
# attempts actions through.
#
# Builds from source (provably this repository's binary), cross-compiled so one
# runner yields linux/amd64 and linux/arm64 without QEMU. Final base is
# distroless/static (nonroot), it carries CA certificates, which the proxy needs
# when it resolves did:web documents or status lists over HTTPS. No shell, no
# package manager. Bases pinned by digest, bumped by Dependabot.
#
# Licence-tier pure: contains ONLY the AGPL enforcement binary. Keep the Apache
# verifier out of this image (it has its own).
#
# NOTE: the `serve` transport is a documented mock (plain JSON over HTTP, no
# mTLS: see the README's "not production-hardened"). This image is for
# evaluation and development deployments (k8s, sidecars); it is not a
# production-hardened enforcement endpoint yet.

# --- build ---------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/kessa-proxy ./cmd/proxy

# --- run -----------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=build /out/kessa-proxy /usr/local/bin/kessa-proxy

USER nonroot:nonroot
# Both listeners are on by default: the generic HTTP listener (8181) and the
# MCP-native Streamable-HTTP listener (8182). Close either by passing an empty
# address (e.g. `serve --mcp-addr ""`).
EXPOSE 8181 8182
ENTRYPOINT ["/usr/local/bin/kessa-proxy"]
# Default to serving on all interfaces: the binary's own default is 127.0.0.1,
# which is unreachable from outside a container. 0.0.0.0 inside a container is
# scoped by the pod/host network, and this CMD is overridable (e.g.
# `docker run … run --requests …` for batch mode).
CMD ["serve", "--http-addr", "0.0.0.0:8181", "--mcp-addr", "0.0.0.0:8182"]
