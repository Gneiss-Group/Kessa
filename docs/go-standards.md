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
make test          # go test -race ./... : the race detector is not optional
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
  the same class of bug: a verdict-relevant field left outside the signed
  material or accepted as an assertion, so a new field on a signed struct
  should be assumed to be an instance of it until shown otherwise.
- **Validate before the side effect, never after: this repo's demonstrated blind
  spot.** Three separate security findings across three branches (R2-01, R3-01,
  R4-03) were the *same* shape: a gate that used to fire before an irreversible
  step got refactored so it fires after it: a construction-time reject becoming a
  verify-time reject, a uniqueness check running after the file was already
  overwritten. The side effect is still "eventually caught," which is exactly why
  it survives review. So it is a standing rule, not a per-instance fix: **any
  change to a validation path must keep the check ahead of every side effect it
  guards (key generation, file writes, minting, appends), and must ship a test
  that asserts the gate fires *before* the side effect**: see the Tests section.
  When you touch a validation path, assume you have moved a gate until you have
  shown you have not.
- **A coverage check enumerates its exclusions, never its inclusions.** Any check
  claiming to cover "every X" must start from the complete tracked set and
  subtract named exceptions. An inclusion list silently passes anything nobody
  remembered to enumerate, so the check reports OK while covering less than it
  claims, which is the failure mode a green build cannot report. Two instances,
  both found by accident rather than by the check: `perf` appeared in neither
  hardcoded tier list in [`scripts/license-check.sh`](../scripts/license-check.sh),
  so nothing checked its licence boundary; and `docker/demo/requests.json` fell
  outside the extension glob in [`scripts/ci/gate.sh`](../scripts/ci/gate.sh), so
  nothing checked it carried an SPDX annotation. The licence check now has the
  right shape twice over: it derives the package set from `go list ./...`, and it
  derives each package's tier from that package's own SPDX headers, so there is no
  longer a list to fall out of. The follow-on rule is worth stating separately,
  because the first fix left it standing: **a classification lives in the thing
  being classified, not in a register of it.** A list that classifies rather than
  selects is better than one that selects, but it is still a second copy, and the
  copy is what goes stale. Tier comes from the file's header and plug-point
  designation comes from the `//kessa:plugin-interface` marker in the source; both
  are unfalsifiable in the sense that matters, which is that you cannot change the
  code without the classification moving with it.

  The SPDX check in `gate.sh` carried the same debt for longer, and it is now
  paid. It walked a glob of source extensions, so it enumerated its inclusions and
  any file type nobody thought of went unchecked. It could not simply be widened,
  because a dozen files carry no inline header by design and are licensed through
  `REUSE.toml` annotations instead. The fix this note called for was "a checker
  that accepts a header *or* an annotation", and that is
  [`scripts/reusecheck`](../scripts/reusecheck/), which the gate now runs over the
  complete tracked set.

  It is written here rather than installed, and that is the second rule this
  episode produced. **The dependency question is settled by
  [`scripts/ci/secret-scan.sh`](../scripts/ci/secret-scan.sh), not re-litigated per
  tool:** gitleaks is pinned and built from source because "don't trust an
  artifact you did not build" is the product's thesis and CI is not exempt from
  it. The FSFE's `reuse` is the reference implementation and a good tool, but
  installing it means eleven prebuilt Python wheels, which would contradict the
  script sitting next to it in the same directory. A hundred lines of Go and a
  parser for the four keys `REUSE.toml` actually uses was the cheaper side of that
  trade. Revisit it if `REUSE.toml` ever needs real TOML, not before.

  The reimplementation is narrower than the spec on purpose, and **stricter in the
  one place that matters.** `reuse lint` answers "does every file resolve to some
  licence?". `scripts/reusecheck` also answers "do all of the repository's
  statements about that file agree?", and fails when they do not. REUSE resolves
  that case silently by precedence, which is how `docs/enrollment.md` carried an
  `AGPL-3.0-only` header under a glob claiming `Apache-2.0` with no tool
  objecting; it was found by hand. Note what the strictness buys: the checker does
  not model precedence at all, because precedence only decides who wins when two
  statements disagree, and a disagreement is now a build failure. **A rule you
  enforce is cheaper than a rule you emulate.**

  The residual hazard is the glob itself, which claims every file added to a
  directory later. `docs/*.md` is gone for that reason; the docs are named
  individually, which is safe here only because an unlicensed file is now a
  failure rather than a silent default.

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
- **A validation gate is tested for WHEN it fires, not just THAT it fires.** For
  any check that guards a side effect, assert the rejection leaves no partial state
 : the existing record is untouched, the file was not written, the key was not
  minted, not merely that an error is returned. A "the verifier eventually rejects
  it" test cannot tell an early gate from a late one, and the late-gate bug
  (R2-01/R3-01/R4-03) is precisely the one this codebase keeps reintroducing.
  `TestEnroll_DuplicateDID_RejectedBeforeSideEffect` is the pattern to copy.
- **A concurrency regression test is not trusted until it has been observed to
  fail with its guard removed.** An interleaving test only tests anything if the
  racing requests still reach the code path they contend over. When an upstream
  gate starts rejecting them earlier, the test stops exercising the interleaving
  and keeps passing: it goes vacuous while staying green, so nothing reports it.
  This happened to the R2-04 concurrency tests when proof of possession became a
  pre-log gate (R5-06): the racing requests were refused before the append they
  were written to contend over, and the assertions held for the wrong reason. So
  run the test against the code with its fix removed, watch it fail, and do it
  again whenever the path in front of it changes. Say in the pull request that
  you did. **A concurrency test that has never been mutation-checked is not known
  to test anything.**
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

## Standing rule: open items are recorded in UPCOMING.md only

A new open item is created in UPCOMING.md, never solely in a code comment,
a citation to a private document, or left implicit in a PR description. If
the reasoning needs more room than a comment allows, the comment points at
UPCOMING.md, not the reverse. This does not require moving already-settled
register content; it applies only to where a *new* open item first gets
written down.

## Known gap, not yet a rule: stale docs outside the touching PR

Documents describing current system behavior or limits (README claims,
mcp.md, etc.) are not self-auditing. Nothing catches drift in a document
that a given PR didn't itself touch, even when that PR is exactly what made
the document's claim false. Three instances found in one 2026-08-11 session
alone, all pre-existing text describing a state the code had already left
behind. No mechanism proposed yet. Revisit if a fourth instance appears.

## Prose style

Comments, documentation, and commit messages are written to be read, so the same
discipline applies to the prose as to the code.

**Em dashes (U+2014) are not used anywhere in this repository.** Neither are en
dashes (U+2013). This is not a preference to weigh case by case; it is a rule, and
`scripts/ci/gate.sh` fails the build on any occurrence in a tracked file. The only
exception is `LICENSE` and `LICENSES/`, which are third-party legal text and are
never edited.

Reach for these instead, whichever the sentence actually wants:

| Situation | Use |
|---|---|
| the clause continues the thought | a comma |
| an explanation, definition, or list follows | a colon |
| two independent clauses join | a semicolon |
| an aside interrupts the sentence | parentheses |
| a range | a plain hyphen (`F1-F10`) or the word "to" |

If none of those fits, the sentence wants rewriting rather than a dash. The rule
is enforced mechanically because it was stated repeatedly and kept coming back:
a convention that lives only in someone's memory is a convention that decays.

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
