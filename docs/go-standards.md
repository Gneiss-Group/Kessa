# Go standards

The rules this codebase is actually written to. Most of them are ordinary Go
practice; the ones that are not exist because Kessa's central claim is that a
stranger can read the verifier, disbelieve everything else, and still trust the
verdict. A standard that does not serve that claim is not in this document.

Nothing here is new policy. It is the practice already visible in the tree and
in [`CONTRIBUTING.md`](../CONTRIBUTING.md), written down so it can be pointed
at in review.

## The short version

```sh
make vet           # go vet ./...
make test          # go test -race ./...  — the race detector is not optional
make license-check # no Apache-tier package may import an AGPL-tier one
gofmt -l .         # must print nothing
```

All four run in CI on every pull request, and again before any release.

## Formatting and toolchain

- **`gofmt` is the formatter.** No exceptions, no alternative style, no
  discussion in review. CI fails on any file `gofmt -l` names.
- **The Go version lives in `go.mod`** and nowhere else. CI reads it from there
  (`go-version-file: go.mod`), so there is one place to change it.
- **`go vet` must be clean.** A vet finding is fixed, not annotated away.

## Dependencies

- **The standard library is the default, and third-party modules are a decision,
  not a convenience.** `go.mod` has no `require` block today. Adding the first
  one is a design change with a licensing and audit consequence, not a chore.
- **The verifier's dependency closure is sacred.** `cmd/verify` and everything it
  can reach must stay stdlib plus our own packages: no server code, no
  enforcement engine, no network client. `TestVerifierDependencySetIsClean`
  enforces this from inside the test suite, by walking `go list -deps`, so it
  cannot be forgotten.
- **The licence boundary is a build failure, not a convention.** Every package is
  classified into the Apache tier or the AGPL tier in
  [`scripts/license-check.sh`](../scripts/license-check.sh), and an Apache-tier
  package that imports an AGPL-tier one fails the build. A package in neither
  list also fails: an unclassified package is one nobody made a decision about.
  **Adding a package means adding it to a tier in the same change.**

## Package layout

- `pkg/` is for types that cross a boundary; `internal/` is for everything else.
  A package under `internal/` cannot be imported by anyone outside the module,
  which is the default we want for anything that is not deliberately public.
- **Leaf packages stay leaves.** The foundational packages (`internal/did`,
  `internal/signer`, `internal/macaroon`, `internal/status`, `internal/audit`,
  `pkg/types`, `internal/version`) are stdlib-only by intent. A new import edge
  into one of them is a design change; say so in the pull request.
- **`cmd/` binaries are CLIs, reporters, and exit codes.** The logic they drive
  lives in a package that can be tested without a process. `cmd/verify` is the
  clearest example: it parses flags and prints, and `internal/export` does the
  verifying.

## Errors, and what a function is allowed to assume

- **Wrap with `%w`** when the caller might reasonably want to inspect the cause;
  otherwise state the failure in the message. Every error message names what was
  being attempted, not just what went wrong.
- **Fail closed.** In the enforcement and verification paths, an error is a
  denial or a `FAIL`, never a skip. Any code shaped like "if we could not check
  it, carry on" is a defect in this repository, regardless of how the surrounding
  logic reads.
- **Never trust a field you can re-derive.** This is the project's whole thesis
  expressed as a coding rule: if a struct carries a claim (`allowed`,
  `statusChecked`, `consequential`) and the evidence to recompute it, the
  verifier recomputes it. Round 1 and round 2 of the security review both found
  the same class of bug — a verdict-relevant field left outside the signed
  material or accepted as an assertion — so a new field on a signed struct
  should be assumed to be an instance of it until shown otherwise.

## Concurrency

- **Locks live with the invariants they protect,** not in the transport. The
  enforcement lock belongs to `Proxy`, which owns the hash-chained log and the
  evidence map; the HTTP handler holds none (R2-03, R2-04).
- **`make test` is the race run.** `go test -race ./...` is the merge gate
  because a race in the enforcement path is a correctness defect: round 2 found
  two concurrent decisions landing at the same sequence number, the second
  silently overwriting the first and leaving an executed action with no audit
  entry. `make test-fast` exists for the inner loop only. Do not submit on it.

## Tests

- **Table-driven where the cases are data**, one behaviour per test where they
  are not. Test names say what must hold (`TestV1Export_DisclosesThatNoEvidenceIsCarried`),
  not which function is being exercised.
- **A security finding gets a test named after it** (`TestR2_05_TrustRootIsDisclosed`)
  that fails on the unfixed code. The finding number in the name is the link back
  to the review document.
- **Goldens are frozen, and regenerating one is a deliberate act.** `make
  fixtures` regenerates `testdata/`, and doing so means the frozen export format
  changed: it needs an entry in the format-history record (`CHANGELOG.md`; see
  [`scripts/release/fixture-guard.sh`](../scripts/release/fixture-guard.sh))
  saying what changed and why. The release pipeline refuses to publish a moved
  golden without one, and refuses to call it a patch release.
- **Determinism is a requirement, not a nicety.** Fixtures and demo keys derive
  from fixed Ed25519 seeds and fixed timestamps, so `make fixtures` is a no-op in
  git and `make demo` produces the same story every run. CI checks the no-op
  property on every pull request; a golden that cannot be reproduced from source
  is indistinguishable from one that was edited by hand.

## Comments

Comment density in this repository is high and deliberately so. The convention:

- **Package and file comments explain the threat model**, not the mechanics. Read
  the top of [`cmd/verify/main.go`](../cmd/verify/main.go): it enumerates
  everything the verifier trusts, because that list is the product.
- **A comment on a non-obvious decision says what would go wrong otherwise.**
  "Locks in Proxy, not the handler" is not useful; "the transport holds no
  invariants, so a lock there would protect nothing (R2-03)" is.
- **Do not comment what the code says.** The bar is: would a reviewer have had to
  reconstruct this reasoning themselves?

## Licence headers

Every Go source file carries an SPDX header naming its tier, per the
[REUSE](https://reuse.software) spec, and the header must match the tier the
package is classified into:

```go
// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0
```

New files must carry one. CI fails on a Go file, release script, or workflow
without one; other paths are bulk-annotated in [`REUSE.toml`](../REUSE.toml).

## Versioning in code

The version is the `Version` constant in
[`internal/version`](../internal/version/version.go) and nowhere else. It is a
constant rather than a value injected with `-ldflags -X` on purpose: a project
whose trust story is "read the source, then build it yourself" should not have
its artifacts' identity supplied by the build command. Every binary answers
`--version` before parsing anything, so an artifact can be identified without
being run. See [`docs/branching.md`](branching.md) for when the number moves.
