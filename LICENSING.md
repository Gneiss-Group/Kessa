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
cannot regress. It additionally fails when any package in the module sits in
neither tier, so the test above cannot be quietly bypassed by adding a package and
classifying it nowhere.

## Commercial licensing

The `AGPL-3.0-only` components are also available under a separate commercial
license for organizations that cannot meet the AGPL's terms. Contact Gneiss Group
Inc.

## Plugin interfaces

We intend to add a Section 7 additional permission designating specific plugin
interfaces (starting with `auditsink`) as independent modules, so that
implementations can be licensed freely. That permission is **not yet in effect**:
see [`PLUGIN_LICENSING.md`](PLUGIN_LICENSING.md) for the intent and its current
status.

## Contributing

Contributions will be accepted under a Contributor License Agreement, which is
still being finalized (see [`CLA.md`](CLA.md)); external code contributions
cannot be merged until it is published. A contribution is licensed under the
license of the file(s) it touches (see each file's SPDX header). See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
