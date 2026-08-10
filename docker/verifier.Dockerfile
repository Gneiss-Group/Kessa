# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Container image for the independent verifier (`kessa`), the Apache-2.0 tier.
#
# Builds from source, so the binary in the image is provably this repository's:
# no "trust a prebuilt binary" step. The build stage cross-compiles (Go needs no
# emulation to target another arch), so a single amd64 runner produces both
# linux/amd64 and linux/arm64 with no QEMU. The final stage is distroless/static
# (nonroot): CA certificates, a nonroot user, and tzdata, and nothing else: no
# shell, no package manager. Bases are pinned by digest and bumped by Dependabot,
# the same discipline as the pinned Actions.
#
# This image is licence-tier pure on purpose: it contains ONLY the verifier and
# nothing from the AGPL tier, so an evaluator can run it without touching copyleft
# code. Do not add a server/enforcement binary here.

# --- build ---------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:2005724102f45917a63e9d092fc0e4ea56ea575048ce147caad5f5f61502c365 AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Full context (including .git) so the toolchain's VCS stamping records the commit
# in `--version`, exactly as the release tarballs do.
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/kessa ./cmd/verify

# --- run -----------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=build /out/kessa /usr/local/bin/kessa

# distroless/static:nonroot already defaults to uid 65532; state it explicitly.
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/kessa"]
