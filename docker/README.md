<!--
SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Container images

Three images, split along the licence boundary, each built `FROM` source into
`distroless/static` (nonroot, multi-arch, digest-pinned bases):

| Image | Binary | Tier | Dockerfile |
|-------|--------|------|------------|
| `kessa` | `kessa` (verifier) | Apache-2.0 | [`verifier.Dockerfile`](verifier.Dockerfile) |
| `kessa-proxy` | `kessa-proxy` (enforcement) | AGPL-3.0-only | [`proxy.Dockerfile`](proxy.Dockerfile) |
| `kessa-issuer` | `kessa-issuer` (issue/publish/enroll/daemon) | AGPL-3.0-only | [`issuer.Dockerfile`](issuer.Dockerfile) |

The verifier image is licence-tier pure on purpose — it contains **only** the
Apache verifier, so an evaluator can run it without touching copyleft code.

## Scope: this is the software path

These images run the **pure-Go** binaries (CGO disabled; the macOS Secure Enclave
backend compiles to its no-op stub). That is the correct shape for demos, CI, and
evaluation. **Hardware-backed keys are a host concern, not a container one:** a
containerized daemon has no clean access to a platform secure element, so the
container brokers software keys. Real employee-device hardware backing (Secure
Enclave; TPM is [upcoming](../UPCOMING.md)) runs on the host, not in a container.

## The end-to-end demo

[`demo.sh`](demo.sh) builds all three images and composes them over one shared
volume — the containerized version of `make demo`:

```sh
docker/demo.sh
```

1. **issuer** mints the `alice → acme → worker → helper` chain and publishes
   did:web documents + a signed status list into a shared `/pub` volume.
2. **proxy** enforces a batch of action requests ([`demo/requests.json`](demo/requests.json))
   against `/pub` and writes a signed audit export.
3. **verifier** (the Apache image, on its own) re-derives every verdict from the
   files in `/pub` alone — the whole point: trust nothing that is running.

Expect two allows verified and two denies with intact evidence. The demo runs its
containers as root for shared-volume writability; the **published images default
to nonroot** (uid 65532).

## Running an image directly

```sh
# Verifier (Apache) — offline, against mounted files.
docker run --rm -v "$PWD:/data:ro" kessa verify \
  --export /data/export.json --dids /data/public --status "URL=/data/status.json"

# Issuer (AGPL) — publish a chain's public artifacts into a mounted directory.
docker run --rm -v "$PWD/out:/pub" -v "$PWD/scripts/demo:/in:ro" kessa-issuer \
  publish --spec /in/spec.json --keystore /in/keystore.json --root /pub --out /pub/chain.json

# Proxy (AGPL) — the sidecar; two listeners by default (8181 HTTP, 8182 MCP).
docker run --rm -p 8181:8181 -p 8182:8182 kessa-proxy serve --help
```

> The `serve` transport is a documented mock (plain JSON over HTTP, no mTLS).
> These images are for **evaluation and development**, not production-hardened
> endpoints. See the repo README's "Known limits."
