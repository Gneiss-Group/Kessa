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
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:2005724102f45917a63e9d092fc0e4ea56ea575048ce147caad5f5f61502c365 AS build

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
# The conventional ports, declared for documentation. Which listeners actually
# bind, and on what addresses, is the mounted config's business now, not the
# image's: see `http_addr` and `mcp_addr` in docs/configuration.md.
EXPOSE 8181 8182
ENTRYPOINT ["/usr/local/bin/kessa-proxy"]
# Mount a config at /etc/kessa/proxy.json and run the image with NO arguments.
#
# This CMD used to carry the bind flags instead: `--http-addr 0.0.0.0:8181
# --mcp-addr 0.0.0.0:8182 --allow-unauthenticated-remote`. That was unavoidable
# while flags were the only way to configure the proxy, and it was the source of
# a genuine defect. `docker run` REPLACES the CMD rather than adding to it, so
# supplying --policy and --dids meant restating the bind posture too, and any
# invocation that forgot was refused. The flag itself went missing for months,
# leaving an image whose default command exited 2 before binding anything,
# because nothing ever ran it: docker/demo.sh builds this image and then
# exercises `run`, never `serve`.
#
# Configuration now arrives through a file, so it no longer has to displace the
# command. The bind posture, including whether this deployment accepts listeners
# with no caller authentication, is stated in the operator's config rather than
# presumed by the image. An image that hardcodes 0.0.0.0 is making that choice on
# their behalf, and it is not the image's to make.
#
# Overriding the CMD is still fine for a different command (`docker run …
# run --requests …` for batch mode). What changed is that configuring the proxy
# is no longer such an override.
CMD ["serve", "--config", "/etc/kessa/proxy.json"]
