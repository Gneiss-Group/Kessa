<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to Kessa

Thanks for your interest. Kessa is early-stage and solo-maintained.

**External code contributions are not being accepted yet.** A CLA is in progress
(see [`CLA.md`](CLA.md)) and pull requests will not be merged until it is
finalized. In the meantime:

- Bug reports and issues are welcome and read.
- Design feedback and questions are welcome; open an issue or start a
  discussion.
- Please do not submit pull requests yet. They will not be merged and the work
  may be wasted.

If you are interested in a deeper collaboration (design partner, early
reviewer), reach out directly rather than through a pull request.

The rest of this document describes how the project is built and reviewed, so
that the ground rules are visible before contributions open.

## Licensing — read this first

Kessa uses a **two-tier license model** (see [`LICENSING.md`](LICENSING.md)): the
independent verifier and its dependency closure, plus the plug-point seams, are
`Apache-2.0`; the enforcement engine and server binaries are `AGPL-3.0-only`.
**Your contribution is licensed under the license of the file(s) it touches**:
each file states its license in an SPDX header.

## Contributor License Agreement (CLA)

Kessa requires a signed CLA before a contribution can be merged. This lets the
project be maintained under its two-tier model and the AGPL components be offered
under a commercial license.

> **Status:** the CLA text and signing flow are being finalized; see
> [`CLA.md`](CLA.md). Until it is published, external code contributions cannot
> be merged. Issues, reproductions, and design feedback need no CLA.

## The ground rules, written down

Two documents state how this repository is written and how work moves through
it. They describe existing practice rather than new policy, and review points at
them:

- [**Go standards**](docs/go-standards.md) — formatting, dependencies, package
  layout, error handling, concurrency, tests, comments, and the rules that exist
  because of what the verifier claims (fail closed; never trust a field you can
  re-derive; the verifier's dependency set is sacred).
- [**Branching, commits, and releases**](docs/branching.md) — short-lived
  branches off `main`, [Conventional Commits](https://www.conventionalcommits.org)
  (which the release pipeline reads to decide the version), semantic versioning,
  and the manual, owner-only release.

## Building and testing

Requirements: Go (see [`go.mod`](go.mod)) and a POSIX shell for the demo.

```sh
make test          # go test -race ./...  (the race detector is not optional)
make vet           # go vet ./...
make license-check # enforce the Apache/AGPL import boundary
make demo          # the seven-scenario end-to-end story, verified offline
```

All of these, plus `gofmt`, SPDX headers, and a check that the golden fixtures
still reproduce from source, run in CI on every pull request
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

`make test` runs the race detector because the enforcement path mutates a
hash-chained log and an evidence map: a race there is a correctness defect, not a
performance one. Security review round 2 found one that a bare `go test` could
not see (`make test-fast` is that bare run, for the inner loop only). Do not
submit a change on `test-fast` alone.

Every source file carries an SPDX header (the repo follows the
[REUSE](https://reuse.software) spec): **new files must too.**

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
