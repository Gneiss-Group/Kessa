# Licensing

Kessa is open source under a **two-tier license model**. Every source file
carries an SPDX identifier; full license texts live in [`LICENSES/`](LICENSES/).
The repository follows the [REUSE](https://reuse.software) specification. The
root [`LICENSE`](LICENSE) file carries the `AGPL-3.0-only` text and governs
everything not otherwise marked.

Copyright © 2026 Gneiss Group Inc.

## The two tiers

**Permissive, `Apache-2.0`.** The independent verifier, the libraries it depends
on, the designated plug-point interfaces, and passive tooling that inspects or
classifies without gating anything. The verifier's entire value is that *anyone*
can run it and trust no one, including us, so it is licensed as permissively as
possible. The plug-point interfaces are permissive so that independent (including
proprietary) implementations can build against them freely.

**Protective, `AGPL-3.0-only`.** The components that actually wield authority:
the enforcement engine, the proxy, the issuer, and the agent. These are open and
self-hostable, but protectively licensed so a platform cannot run our core as a
competing managed service without reciprocity.

## Where the boundary is

A package is **permissive** when both of these hold:

1. **No protective dependency.** Its full dependency closure contains no
   AGPL-tier package.
2. **No enforcement action.** It neither grants nor attenuates authority, nor
   decides whether a real action may proceed. Reading, classifying, predicting,
   and verifying are not enforcement. Issuing, delegating, gating, and approving
   are.

Anything failing either test is **protective**.

This is written as a test rather than a list of components on purpose. An
enumerated boundary has to be re-drafted every time something is added, and that
re-drafting is precisely when the mistake gets made: the tier of an unanticipated
component should fall out of the rule, not out of a judgement call made under
deadline. A new passive tool that classifies without gating is permissive
automatically, with no amendment to this document.

Applied to what exists today, permissive covers `cmd/verify` (shipped as `kessa`)
and its transitive closure, the `auditsink` plug-point seam, and `cmd/shadow`
(`kessa-shadow`) with `internal/shadow`, which predicts what a policy would
classify and enforces nothing. Protective covers `internal/enforce`,
`internal/keystore`, `cmd/proxy`, `cmd/issuer`, `cmd/agent`, and the `perf`
benchmarks that link the enforcement engine.

Because copyleft is viral through imports, **no Apache-tier package may import an
AGPL-tier package.** [`scripts/license-check.sh`](scripts/license-check.sh)
(`make license-check`) enforces that in CI, so the permissive-verifier guarantee
cannot regress.

A package's tier is read from the SPDX headers on its own files, not from a list
kept somewhere else. Every Go file in the repository carries one, so the check
derives the tier of every package in `go list ./...` and fails on any package
whose files carry no identifier or disagree with each other. The test above
therefore cannot be bypassed by adding a package and classifying it nowhere:
there is nowhere to classify it, only headers to write.

## Commercial licensing

The `AGPL-3.0-only` components are also available under a separate commercial
license for organizations that cannot meet the AGPL's terms:
<sales@gneiss-group.com>.

## Designated plugin interfaces: the marker

A **designated plugin interface** is a seam a third party may implement and
license on their own terms. Which packages are designated is stated in the source
and nowhere else, by this marker:

```go
//kessa:plugin-interface
```

This is the canonical definition of the marker. Nothing else in this repository
redefines it, and no file enumerates the designated packages by name.

**Syntax.** A Go directive comment: two slashes, no space, `kessa:plugin-interface`,
nothing after it on the line. Written as a directive so `gofmt` keeps it attached
to the declaration instead of reflowing it into surrounding prose.

**Placement.** In the file that *declares* the interface, either in that file's
package doc comment or immediately above the interface type. Never in a file that
merely implements or imports the interface: the marker says "the boundary is
here," and a marker on an implementation would put the boundary wherever someone
last pasted a comment. Contributors should write a short comment beside it saying
what it does, as [`auditsink/auditsink.go`](auditsink/auditsink.go) does.

**Meaning, and the obligation it creates.** Marking a package asserts two things
and binds you to the second:

1. The exported interface types in the marked file are a designated plug point.
   An independent implementation of them may be conveyed under its author's own
   licence, once the Section 7 permission is in force (see below).
2. The marked package depends on nothing but the standard library and other
   marked packages. This is what makes the first claim true rather than merely
   stated: if a designated package imported the core, then every implementation
   of its interface would link the core too, the permission's condition could not
   be satisfied by anyone, and the combined binary would fall back to AGPL-3.0 in
   full.

`scripts/license-check.sh` enforces all of this from the marker alone. It fails
when a marked package reaches outside that closure, when the marker sits on a file
declaring no exported interface, when a marked package is not permissively
licensed, and, fail-closed, when a package is *shaped* like a plug point
(permissive, externally importable, exporting an interface type) but carries no
marker. Interfaces under `internal/` need no marker: the Go toolchain already
prevents another module from importing them, so they are not external seams.
[`internal/licensing`](internal/licensing/) tests each of these rejections, and
tests that they are the rejections doing the work.

**Status of the permission itself.** The Section 7 additional permission that
gives the designation its legal effect is **in force.** Its authoritative text is
the section headed `KESSA ADDITIONAL PERMISSION UNDER SECTION 7` at the end of
[`LICENSE`](LICENSE), reviewed by Canada-competent counsel and applied 2026-08-05.
[`NOTICE.md`](NOTICE.md) reproduces it for recipients of a binary, and
[`PLUGIN_LICENSING.md`](PLUGIN_LICENSING.md) explains the mechanism in prose.
Where any of those differ from `LICENSE`, `LICENSE` governs; the clause says so
itself.

**Every marked file also carries a pointer to the clause**, a comment beginning
`// ADDITIONAL PERMISSION:`, and `scripts/license-check.sh` fails the build on a
marked file that lacks one. The reason is a copy taken out of the distribution:
the marker travels with the file, `LICENSE` does not, and a designation whose
grant the reader cannot locate is worse than no designation. The notice points at
the clause and never reproduces it, because two copies of operative text is how
they come to disagree.

## Contributing

Contributions will be accepted under a Contributor License Agreement, which is
still being finalized (see [`CLA.md`](CLA.md)); external code contributions
cannot be merged until it is published. A contribution is licensed under the
license of the file(s) it touches (see each file's SPDX header). See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
