<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

## What & why

<!-- What does this change do, and why? -->

## Checklist

- [ ] `make test`, `make vet`, and `make demo` pass.
- [ ] `make license-check` passes (no Apache-tier package imports an AGPL-tier one).
- [ ] New files carry an SPDX header (REUSE), and any new package is classified into a licence tier.
- [ ] Commit subjects follow Conventional Commits, and a breaking change is marked `!` or carries a `BREAKING CHANGE:` footer (see [`docs/branching.md`](../docs/branching.md)). The release pipeline reads these to pick the next version.
- [ ] I have signed the CLA (see `CONTRIBUTING.md`), if this includes code.

## If this touches the verifier or its dependency closure

<!-- cmd/verify and the Apache-tier packages. Delete this section if not applicable. -->

- [ ] Every allowed entry's verdict is still **re-derived from signed evidence**, not trusted.
- [ ] No verdict-relevant field moved outside the hashed/signed material.
- [ ] The verifier's dependency set is unchanged (still stdlib + our packages; no server/policy-engine/network dependency introduced).
- [ ] Frozen goldens are unchanged, or the change is deliberate and explained below.

## Notes for reviewers

<!-- Anything that helps the review: threat-model reasoning, edge cases, etc. -->
