# Kessa

[![CI](https://github.com/Gneiss-Group/Kessa/actions/workflows/ci.yml/badge.svg)](https://github.com/Gneiss-Group/Kessa/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Gneiss-Group/Kessa/actions/workflows/codeql.yml/badge.svg)](https://github.com/Gneiss-Group/Kessa/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Gneiss-Group/Kessa/badge)](https://scorecard.dev/viewer/?uri=github.com/Gneiss-Group/Kessa)

<!-- Badges resolve once the repository is public and each workflow has run at least once on the default branch. -->

Attestation and enforcement for delegated agent authority. A human delegates to
an org, the org to an agent, the agent to a sub-agent. Each hop **narrows**
authority and never broadens it, and every consequential action is logged to a
tamper-evident chain that an **independent, offline verifier** can re-check while
trusting nothing of ours beyond public DID documents.

![kessa verify run twice on an audit export: the first run re-derives every verdict and prints VERDICT PASS; after one character is flipped in the signed log the same command prints VERDICT FAIL and pinpoints the tampered entry, marking every entry after it UNVERIFIED.](docs/assets/demo.gif)

*Same command, one byte changed between runs. The verifier fails at exactly the tampered entry and re-derives every verdict from the files alone. [How the GIF is built and regenerated.](docs/demo.md)*

Jump to: [What this solves](#what-this-solves) · [Try it](#try-it) · [Status](#status) · [Standards](#standards) · [Known limits](#known-limits)

## What this solves

When a person hands work to an AI agent, and that agent hands part of it to
another, the authority travelling down that chain is normally invisible and
usually undiminished. Kessa makes the chain explicit, narrowing, and provable
after the fact.

- **Agents inherit far more authority than the task needs.** The common pattern
  is to hand the agent a copy of the user's token, so a summarization job holds
  the power to move money. Kessa issues each hop a *new, strictly narrower*
  credential, and a hop that tries to broaden its own authority is rejected when
  it is minted, not when it is used.
- **Nobody can say what an agent was allowed to do at the time it acted.**
  Reconstructing that after an incident usually means trusting application logs.
  Kessa records the delegation chain, the policy, and the approval as signed
  evidence carried with the action.
- **The system that made the decision also writes the record of it.** That is
  the party with the most reason to be wrong. Kessa's verifier re-derives every
  verdict from the evidence instead of reading the decision the enforcement
  point wrote down, so a proxy that cut a corner produces an export that fails.
- **Verifying usually means trusting the vendor.** `kessa verify` is a separate,
  permissively licensed binary that runs offline against files. It reads no
  service of ours, and its trust root is a directory of public keys you can
  obtain independently.
- **Revocation does not reach authority already delegated.** Kessa checks every
  hop against a signed status list at action time, so revoking a credential
  mid-chain stops the consequential actions that depend on it.
- **Tampering with the record is undetectable.** The audit log is hash-chained
  and signed, and the signature covers the log's length and tip, so entries
  cannot be edited, reordered, or quietly dropped after the fact.

Kessa governs *authority*, not content. It decides whether an action may
proceed; it does not judge what an agent says or inspect the data an approved
action touches.

## How it works

Three binaries produce evidence and one re-checks it, trusting none of the
three. The full walkthrough, with diagrams of the delegation, enforcement, and
verification stages, plus the precise statement of what a clean verdict proves,
is in **[How Kessa Works](docs/how-it-works.md)**.

## Status

Kessa is complete and works end to end: seven scenarios run start to finish
(`make demo`), and multiple adversarial security review rounds are closed with every
finding fixed. All rounds were **self-run AI red-team passes, not a third-party
audit**; no external audit has been commissioned yet. It is standard-library
only, with no third-party dependencies. The milestones that matter are provable
attenuation, provable auditability, the independent verifier, and the full
seven-scenario demo.

It is **not production-hardened yet.** Key handling runs behind a `Signer`
seam with two backends: a software keystore (the demo, CI, and
`--software-key` path, whose private key exists in plaintext in the file) and a
**macOS Secure Enclave** backend holding a non-extractable P-256 key. The Enclave
generate → persist → reload → sign → delete loop is **validated on real
hardware**, and the compiled Go daemon has not yet run under a profile, so
packaging is the remaining step. There is no Linux/TPM or Windows backend. What
each backend does and does not prove is stated bluntly in
[Signing backends](docs/signer.md); the other boundaries are under
[Known limits](#known-limits), and open questions are collected in
[`UPCOMING.md`](UPCOMING.md).

## Licensing

The core is `AGPL-3.0-only`: the enforcement engine, the proxy, the issuer, and
the agent. The independent verifier and its dependency closure are `Apache-2.0`,
because a verifier whose value is that anyone can run it and trust no one,
including us, cannot also be the part you need our permission to use.

Designated plugin interfaces are `Apache-2.0` as well, and an additional
permission under section 7 of the AGPL lets an independent implementation of one
be conveyed under its author's own terms even when linked into the same binary as
the core. That permission is conditional: it applies only to code that reaches the
core exclusively through a designated interface. Which interfaces those are is
stated in the source by a `//kessa:plugin-interface` marker and nowhere else.
`auditsink.AuditSink` is the only one today; the build fails if a marked package
reaches beyond the standard library, because the permission's condition depends on
it.

[`LICENSE`](LICENSE) carries the AGPL text and the exception. [`NOTICE.md`](NOTICE.md)
is the bundle to ship with a binary. [`LICENSING.md`](LICENSING.md) states the tier
test and the marker's meaning. The `AGPL-3.0-only` components are also available
under a separate commercial licence for organizations that cannot meet the AGPL's
terms: <sales@gneiss-group.com>.

## Standards

Kessa maps to four published frameworks. Every row in the detailed mapping cites a
test you can run.

| Framework | What Kessa contributes | Where it stops |
|---|---|---|
| **OWASP LLM06:2025** Excessive Agency | All four mitigations OWASP names: least-privilege delegation, authorization outside the model, complete mediation, human approval for high-impact actions | The other nine Top 10 items are model-layer, not authority |
| **NIST SP 800-207** Zero Trust | Tenets 3, 4, 6, 7: per-session credentials, dynamic policy, enforcement before access, signed evidence | Transport security and asset posture are yours |
| **EU AI Act** Art. 12 | A tamper-evident authorization record, which Art. 12 does not require and most logging does not provide | Logging the AI system's own operation stays with the provider |
| **DORA** Art. 9 | Authenticity and integrity of the authority record; access limited to approved activity | Availability and confidentiality are deployment properties |

[Full mapping, with citations and test names](docs/standards-alignment.md). Not a
certification; no external audit has been commissioned.

## Try it

**Prerequisites:** Go **1.26 or newer** (the version in [`go.mod`](go.mod); an
older toolchain will try to download 1.26 and fail if it cannot), plus `make` and
`bash`. There is nothing else to install: Kessa has no third-party Go
dependencies, so `make demo` builds and runs with the network off. The
[container images](#container-images) additionally need a running Docker daemon,
and the provenance check needs the [GitHub CLI](https://cli.github.com).

```sh
make demo     # the whole story: all seven scenarios, end to end, deterministic
```

Or drive the pieces yourself:

```sh
make build    # builds every binary into ./bin (the verifier is ./bin/kessa)

# 1. Issue a chain and publish the public artifacts.
./bin/kessa-issuer publish \
  --spec examples/issuer/spec.json --keystore examples/issuer/keystore.json \
  --root ./public --out ./private/chain.json

# 2. Verify an export against them, offline, nothing running.
./bin/kessa verify \
  --export testdata/audit_export_v2.golden.json \
  --dids   ./public \
  --status "https://localhost/orgs/acme/status.json=./public/localhost/orgs/acme/status.json"

# 3. Revoke a mid-chain credential; the same export stops verifying.
./bin/kessa-issuer revoke --spec examples/issuer/spec.json \
  --keystore examples/issuer/keystore.json --root ./public --index 42
```

Exit `0` = every entry verified against carried evidence, `1` = a FAIL or an
integrity-only v1 downgrade (never a clean pass), `2` = usage/IO error.
Nothing is started, nothing is dialled: the verifier's only inputs are files.
`--fetch-dids` enables HTTPS resolution of public did:web documents, the only
network access `kessa` can make, and it is off by default.

## Container images

Three images per release, split along the same licence boundary as the binaries,
published to GHCR. All are multi-arch (linux/amd64 + arm64), built `FROM`
distroless/static as a nonroot user, and signed with build provenance.

```sh
# The independent verifier (Apache-2.0): offline, runs against mounted files.
docker run --rm -v "$PWD:/data:ro" ghcr.io/gneiss-group/kessa:latest \
  verify --export /data/export.json --dids /data/public

# The enforcement proxy (AGPL-3.0-only): the sidecar. By default it serves two
# listeners into one enforcement engine: generic HTTP (8181) and MCP-native
# Streamable HTTP (8182). Close either with an empty address (e.g. --mcp-addr "").
docker run --rm -p 8181:8181 -p 8182:8182 ghcr.io/gneiss-group/kessa-proxy:latest serve --help

# Serving from a container binds a non-loopback address, which is refused unless you
# say so: the listeners have no caller authentication. The flag adds none, it
# records that you accepted its absence.
#   ... serve --http-addr 0.0.0.0:8181 --allow-unauthenticated-remote

# The issuer (AGPL-3.0-only): mint/publish/enroll/daemon. Publishes a chain's
# public artifacts into a mounted directory (software-key path; see docker/README).
docker run --rm -v "$PWD/out:/pub" -v "$PWD/scripts/demo:/in:ro" \
  ghcr.io/gneiss-group/kessa-issuer:latest \
  publish --spec /in/spec.json --keystore /in/keystore.json --root /pub --out /pub/chain.json
```

See the containers directory for the full three-image, end-to-end demo
([`docker/`](docker/README.md), `docker/demo.sh`): the issuer publishes, the proxy
enforces a batch, and the Apache verifier re-derives every verdict from the shared
files alone.

Verify an image's provenance before trusting it:

```sh
gh attest verify oci://ghcr.io/gneiss-group/kessa:latest --repo Gneiss-Group/Kessa
```

The proxy's `serve` transport is still a documented mock (plain JSON over HTTP,
no mTLS); the image is for **evaluation and development** deployments, not a
production-hardened enforcement endpoint. See [Known limits](#known-limits).

## Self-hostable, for real

The issuer's publication root is a directory of plain JSON files at exactly the
paths `did:web` resolution and the status URL imply. That one directory is
simultaneously:

- **a static website.** `./public/<host>` is a document root you can drop on
  Cloudflare Pages, nginx, S3, or `python3 -m http.server`. No application
  server, no Kessa code in the request path.
- **a local directory.** `kessa verify --dids ./public` reads the same tree
  offline. `did.DocumentPath` is the single source of truth for the mapping, so
  the read and write sides cannot drift.

The root is **host-partitioned** (`<root>/<host>/…`), so serve one host's
subdirectory as its document root. The hostname is the operator's and may be
internal-only or air-gapped. `did:web:vault.corp.internal:orgs:acme` publishes
and verifies fine while resolving nowhere on the public internet.

Secrets never enter the publication root: minted credentials are written outside
it (mode `0600`), and private keys are never written at all. Revocation is a
rewritten, re-signed static file. Propagation is your host's cache policy, and
nothing calls home.

## Known limits

Surfaced in the verifier's output rather than hidden. What a clean verdict
proves, and does not, is stated precisely in [How Kessa
Works](docs/how-it-works.md#what-a-clean-verdict-actually-proves).

- **The verdict is relative to the DID documents you supply.** `--dids` is the
  trust root. Every signature is checked against a key read from that directory
  (or fetched over HTTPS with `--fetch-dids`), so a wholly fabricated export
  verifies clean when the DID documents it names are fabricated to match. This is
  deliberate (anchoring to a Kessa service would defeat the entire design) but
  it means a PASS says *consistent with these keys*, never *genuine*. If the
  export and the DID documents reached you from the same party, you have confirmed
  that party agrees with itself. Obtain the DID documents independently.
- **Completeness is bounded.** The envelope signature covers the entry count and
  log tip, so nobody can shorten a signed export after the fact (R2-02). It does
  not prove the enforcement point logged everything it decided: a short log signed
  honestly and a short log signed by a proxy that declined to record something are
  indistinguishable from the file alone. Closing that needs the tip anchored
  somewhere the enforcement point does not control, which Kessa does not yet do.
- **Revocation is only checkable where the issuer made it checkable.** A hop
  minted with no status-list reference is permanently unrevocable. The verifier
  now says so per entry (`LIMIT:`) instead of skipping it silently.
- **A verified policy is not a correct policy.** Consequentiality is re-derived
  from the carried, signed policy rather than trusted as a bare bit, so the
  verifier proves the allows are consistent with the policy the enforcement
  point published. It cannot prove that policy is the *right* one for the
  environment. Inspect the carried policy to judge that.
- **Status is checked against the *current* list**, not the list as of action
  time (S1, deferred). Re-verifying an old export after a later revocation flips
  previously-legitimate entries from PASS to FAIL. This is an honest false-FAIL,
  not an exploit: current-list semantics cannot make a genuinely-bad historical
  action *pass*.
- **Denials are not independently re-derivable.** A denial can stem from policy,
  which is not carried evidence, so a denied entry passes when its hash,
  signature, and chain evidence are intact. Correct denial is *proven* by exactly
  one of the allow-checks failing; running those checks on denied entries would
  make "correctly denied" and "verifier failure" indistinguishable.

- **The log records only *attributable* decisions**, and that is a deliberate
  property rather than an accident of implementation. An entry exists only for a
  request whose proof of possession verified, so every entry is bound to a
  principal who demonstrably held the key. A request nobody can be tied to: a
  chain that does not verify, or a possession proof that does not: produces no
  decision and no entry; it is refused, and reported to the audit sink as
  telemetry instead.

  This closed a real hole (R5-06). When chain verification was the only gate
  before a write, giving someone an export gave them the ability to append to the
  log they were auditing. Possession is now checked first, so those entries are
  impossible rather than merely denied.

  **A standing characteristic, which the fix does not change and is not meant to:**
  an export carries each credential with its issuer proof, so **anyone holding one
  can re-derive a delegation chain that verifies.** That is deliberate, it is what
  lets the verifier re-check a chain offline against public keys with no shared
  secret, and it is the product's central claim. A chain proves *issuance*, which
  is public; it never proved *possession*. Design anything that consumes a chain
  accordingly: R5-06 happened because one path assumed a chain established more
  than it does.

  What this does **not** close: the endpoint still has no caller authentication, so
  anyone who can reach it may *submit*, they simply cannot make it record
  anything. Non-loopback binds are refused unless you pass
  `--allow-unauthenticated-remote`. See [`UPCOMING.md`](UPCOMING.md).

Accepted, documented risks (current boundaries, not defects):

- **VC wrapper is not the cross-org anchor.** Cross-org trust rests on the per-hop
  Ed25519 issuance signature, verified against public DID docs. The optional
  `VCWrapper` is an interop envelope only and is never verified in the trust path.
- **Expiry caveats use the proxy-chosen action timestamp** with no independent
  clock. An honest clock-trust assumption; a verifier-side time bound is the
  mitigation path if needed.
- **`--fetch-dids` can be pointed at arbitrary URLs** (an SSRF surface). It is off
  by default and evaluator-driven; scheme is HTTPS-only per did:web.
- **Committed keys are demo-only**, derived from fixed seeds for reproducibility,
  and are never referenced by any non-test path.

Open design questions and known gaps beyond these limits are collected in
[`UPCOMING.md`](UPCOMING.md).

If this matches a problem you have, or you think one of these limits is wrong,
open a [Discussions thread](https://github.com/Gneiss-Group/Kessa/discussions).

## Documentation

[How Kessa Works](docs/how-it-works.md) is the mechanical walkthrough: the
delegation, enforcement, and verification stages, and what a clean verdict
proves. The [documentation index](docs/README.md) lays out the reading order for
everything else:

| Document | What it is |
|----------|------------|
| [Signing backends](docs/signer.md) | The `Signer` seam: software keystore, macOS Secure Enclave, and precisely what each one does and does not prove. |
| [Enrollment](docs/enrollment.md) | How a device gets its own key and credential. |
| [Signing daemon](docs/daemon.md) | The long-running signer, its socket, and its trust boundary. |
| [Enclave runbook](docs/enclave-runbook.md) | Reproducing the Secure Enclave path on real hardware, including code-signing setup. |
| [Standards alignment](docs/standards-alignment.md) | Published requirements mapped to specific tests and files, with what Kessa does not address stated alongside. Not a certification. |

The adversarial review rounds were **self-run AI red-team passes, not a
third-party audit**; their findings are closed. The [security review
record](docs/security-review.md) lists what each round covered and every finding
raised, without reproducing the mechanism; the working notes are not published.

## Layout

`cmd/verify` (the independent verifier, built as `kessa`) is deliberately kept
importable from near-stdlib leaf packages; its dependency set is treated as
sacred, and [`scripts/license-check.sh`](scripts/license-check.sh) fails the
build if anything in it reaches an AGPL-tier package.

## Build & test

```sh
make test          # go test -race ./...  (the race detector is not optional)
make test-fast     # go test ./...  (the bare run, for the inner loop only)
make vet           # go vet ./...
make license-check # enforce the Apache/AGPL import boundary
make fixtures      # regenerate testdata/dids from fixed seeds
make version       # print the version this tree would release as
```

Every binary identifies itself without being run:

```sh
./bin/kessa --version    # kessa 0.0.1 (commit 1a2b3c4d5e6f, go1.26.3)
```

The version is a constant in the source, not a value injected at build time, so
building from a tag reproduces a binary that identifies itself identically. The
commit and the `-dirty` marker come from the Go toolchain's own VCS stamping.
How the number moves, and how a release is cut, is in
[`docs/branching.md`](docs/branching.md).

Determinism: fixtures and demo keys derive from fixed Ed25519 seeds, so runs are
reproducible.

## Design principles

- **Attenuation-first**: children get new, narrower credentials, never copies of
  a parent key.
- **`did:web` only** for now; conventional primitives (Ed25519 / HMAC-SHA256
  / SHA-256).
- **Self-hostable first**: DID resolution (and, later, status publication and
  audit storage) each default to a local implementation with no hard dependency
  on any hosted service.
- **Minimal, auditable dependencies**: the foundational leaf packages are
  standard-library only.
