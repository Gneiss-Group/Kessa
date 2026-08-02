# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Container image for the issuer (`kessa-issuer`), the AGPL-3.0 tier. This
# completes the image trio (verifier, proxy, issuer). It mints delegation chains
# and publishes the public artifacts a verifier needs (did:web documents + a
# signed bitstring status list), serves that publication root over HTTP for demos,
# and runs the on-device signing daemon that brokers key material over a local
# socket.
#
# Builds from source (provably this repository's binary), cross-compiled so one
# runner yields linux/amd64 and linux/arm64 without QEMU. Final base is
# distroless/static (nonroot) — it carries CA certificates, which `enroll
# --fetch-org-did` needs to resolve the org's did:web over HTTPS. No shell, no
# package manager. Bases pinned by digest, bumped by Dependabot.
#
# Licence-tier pure: contains ONLY the AGPL issuer binary. Keep the Apache
# verifier out of this image (it has its own).
#
# SCOPE: this is the software/keystore path — the pure-Go issuer that runs
# anywhere (CGO disabled, the Secure Enclave backend compiles to its no-op stub).
# Hardware-backed keys (macOS Secure Enclave) are a host concern, not a container
# one: a containerized daemon has no clean access to the platform secure element,
# so this image brokers software keys. That is the correct shape for demos, CI,
# and evaluation; real employee-device hardware backing runs on the host.

# --- build ---------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Full context (including .git) so the toolchain's VCS stamping records the commit
# in `--version`, exactly as the release tarballs do.
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/kessa-issuer ./cmd/issuer

# --- run -----------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=build /out/kessa-issuer /usr/local/bin/kessa-issuer

USER nonroot:nonroot
# `serve` (the static did:web host, demo only) listens here when used; publish,
# enroll, revoke, and daemon are one-shot / socket modes that ignore it.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kessa-issuer"]
