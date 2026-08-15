<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to Kessa

Thanks for your interest. Kessa is early-stage and solo-maintained.

**Kessa is open to external contributions.** The CLA is published and the signing
flow is live (see [`CLA.md`](CLA.md)); signing takes one comment on your first
pull request.

The project is pre-1.0 and solo-maintained, so a little coordination saves
everyone time:

- Bug reports and issues are welcome and read.
- Design feedback and questions are welcome; open an issue or start a
  discussion.
- For anything beyond a small fix, **open an issue before writing code.** Not a
  formality: the licence boundary, the verifier's dependency closure, and the
  plug-point rules all constrain where a change can go, and it is cheaper to say
  so before you have written it than after.

If you are interested in a deeper collaboration (design partner, early
reviewer), open a [Discussions
thread](https://github.com/Gneiss-Group/Kessa/discussions) rather than a pull
request.

The rest of this document describes how the project is built and reviewed, so
that the ground rules are visible before contributions open.

## Licensing: read this first

Kessa uses a **two-tier license model** (see [`LICENSING.md`](LICENSING.md)): the
independent verifier and its dependency closure, plus the designated plug-point
interface, are `Apache-2.0`; the enforcement engine and server binaries are
`AGPL-3.0-only`.

**Your contribution is licensed under the license of the file(s) it touches.**
Most files say so in their own SPDX header. Formats that have no comment syntax
(all the JSON, the images) cannot carry one, so they are licensed by an annotation
in [`REUSE.toml`](REUSE.toml) instead. Both are authoritative; roughly a quarter of
the tree is licensed the second way, so **"no header" does not mean
"unlicensed"**, and the file you are editing may well be one of them.

To ask about a specific file rather than guess:

```sh
go run ./scripts/reusecheck -explain examples/policies/data-governance.json
```

It names the licence and the statement responsible, whether that is the file's own
header or the `REUSE.toml` entry covering it. Grepping is not always enough: a file
covered by a glob has nothing in it to find, and nothing matching its own path in
`REUSE.toml` either, since `examples/**` is what covers the file above.

[`scripts/reusecheck`](scripts/reusecheck/) also fails the build if any tracked
file has no licence by either route, or if the two routes disagree about one, so
the answer is never ambiguous.

## Contributor License Agreement (CLA)

Kessa requires a signed CLA before a contribution can be merged. This lets the
project be maintained under its two-tier model and the AGPL components be offered
under a commercial license.

**Signing takes one comment.** Open your pull request; a bot replies with a link
to [`CLA.md`](CLA.md) and the phrase to post back. Signatures are recorded in
`.github/cla/signatures.json` in this repository, so nothing about you is stored
with a third party. You sign once, not per pull request.

You keep ownership of your work. The CLA is a licence grant, not a copyright
assignment, and it exists for one reason: the AGPL core is also offered under a
separate commercial licence, which we cannot do with your code unless you have
said we may. If you are contributing on behalf of an employer, that employer also
needs to sign [`CLA-CORPORATE.md`](CLA-CORPORATE.md).

Issues, reproductions, and design feedback need no CLA.

## The ground rules, written down

Two documents state how this repository is written and how work moves through
it. They describe existing practice rather than new policy, and review points at
them:

- [**Go standards**](docs/go-standards.md): formatting, dependencies, package
  layout, error handling, concurrency, tests, comments, and the rules that exist
  because of what the verifier claims (fail closed; never trust a field you can
  re-derive; the verifier's dependency set is sacred).
- [**Branching, commits, and releases**](docs/branching.md): short-lived
  branches off `main`, [Conventional Commits](https://www.conventionalcommits.org)
  (which the release pipeline reads to decide the version), semantic versioning,
  and the manual, owner-only release.

Kessa is built with AI-assisted development, with every change reviewed, tested,
and owned by the maintainer exactly as if it had been typed by hand; the
project's security review posture is documented separately in
[`SECURITY.md`](SECURITY.md) and the [security review
record](docs/security-review.md).

## Building and testing

Requirements: Go (see [`go.mod`](go.mod)) and a POSIX shell for the demo.

```sh
make test          # go test -race ./...  (the race detector is not optional)
make vet           # go vet ./...
make license-check # enforce the Apache/AGPL import boundary
make demo          # the seven-scenario end-to-end story, verified offline
```

Before opening a pull request, run the full gate:

```sh
bash scripts/ci/gate-full.sh
```

It runs everything CI runs **except** the two jobs that need something your
machine may not have: CodeQL, which is a GitHub code-scanning service rather than
a local tool, and the container smoke, which needs a Docker daemon. So a green
run here is not a promise of a green CI, and it is worth knowing which way the
gap runs before you rely on it.

The first run builds `gitleaks` from source at a pinned version for the secret
scan, which takes a minute or two and then caches.

It calls [`scripts/ci/gate.sh`](scripts/ci/gate.sh), scans for committed
credentials, and then adds the nested modules under
[`experimental/`](experimental/). Those carry their own `go.mod`,
which means the root module's package walk cannot enumerate them: `go list ./...`
lists the packages of one module, and a directory with its own `go.mod` is a
different one. Checking them is therefore an extra walk rather than a wider glob.

The inner gate runs on its own when you have no network:

```sh
bash scripts/ci/gate.sh
```

That one is offline-hermetic and now says so rather than merely happening to be:
the core has no third-party runtime dependency, so it must build from a cold
module cache with the module proxy switched off, and the gate fails if that ever
stops being true. The full gate has to fetch the nested modules' dependencies the
first time it runs, which is the whole reason the two are separate. An
air-gapped build is a property worth keeping.

Know the asymmetry before relying on the offline one: a change under
`experimental/` is invisible to it, so `gate.sh` can be green on a pull request
that CI will fail.

Both need nothing beyond Go and a shell. Every check in them is a shell script or a
Go program in [`scripts/`](scripts/), including the licence checks: the REUSE
conformance check is [`scripts/reusecheck`](scripts/reusecheck/), not the FSFE's
`reuse` tool, and [`scripts/ci/secret-scan.sh`](scripts/ci/secret-scan.sh) builds
its scanner from pinned source rather than downloading one. A project whose
subject is not trusting artifacts you did not build should not fetch opaque
tooling to check itself.

All of these, plus `gofmt`, the licence lint, and a check that the golden fixtures
still reproduce from source, run in CI on every pull request
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

`make test` runs the race detector because the enforcement path mutates a
hash-chained log and an evidence map: a race there is a correctness defect, not a
performance one. Security review round 2 found one that a bare `go test` could
not see (`make test-fast` is that bare run, for the inner loop only). Do not
submit a change on `test-fast` alone.

The repository follows the [REUSE](https://reuse.software) spec, and **every new
file must be licensed**: put an SPDX header in it if its format takes comments,
and add a `REUSE.toml` annotation if it does not (JSON, images).
[`scripts/reusecheck`](scripts/reusecheck/), which the gate runs, refuses a file
that has neither, so this is a build failure rather than a review comment.

## The license boundary (do not cross it)

The permissive verifier tier must **never** import a copyleft (`AGPL`) package, or
the verifier stops being permissively licensed. `make license-check` enforces this
and runs in CI. If you add an import edge, keep it on the correct side.

## The verifier is the crown jewel

`cmd/verify` and its dependency closure are what everyone runs and trusts.
Changes there receive extra scrutiny (see [`CODEOWNERS`](CODEOWNERS)), and the
core invariant must hold: every allowed entry's verdict is **re-derived from
signed evidence, never trusted**. Explain in your PR how your change preserves
that (the PR template has a checklist).

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
