# Project instructions

The standards for this codebase live in [`docs/go-standards.md`](../docs/go-standards.md),
which is the document review points at. Read it rather than duplicating it here.

Two things worth having in front of you at all times:

- **Prose style.** No em dashes (U+2014), no en dashes (U+2013), anywhere: code,
  comments, docs, commit messages, PR bodies, or chat. Use a comma, a colon, a
  semicolon, or parentheses. `scripts/ci/gate.sh` fails the build on any
  occurrence, so this is enforced rather than requested. See the *Prose style*
  section of `docs/go-standards.md` for which mark to use when.
- **Validate before the side effect**, and be suspicious of a check that can pass
  without testing anything (optional-when-present, first-occurrence-only,
  presence-without-type, enumerated-inclusion, and a concurrency test whose
  requests no longer reach the path they race on). Both are standing rules that
  came out of review rounds, not preferences. `docs/go-standards.md` has the
  detail.

Before opening a PR, run `bash scripts/ci/gate-full.sh`. It runs everything CI
runs except the two jobs that need something a laptop may not have: CodeQL (a
GitHub service) and the container smoke (a Docker daemon). A green run here is
not a promise of a green CI, and treating it as one is how a committed secret
reaches a pull request.

`scripts/ci/gate.sh` is the offline subset it calls: every check except the
nested modules under `experimental/`, which have their own `go.mod` and need
their dependencies fetched. Use it when you have no network, and know the
asymmetry before you rely on it: a change under `experimental/` is invisible to
the offline gate, so it can be green on a PR that CI will fail.

## Never write a session log inside this repository

Session logs, handoffs, reconciliation notes and similar working documents go
**outside any git working tree**. In this project that is `~/Documents/kessa-logs/`.
If a destination is not obvious for some other document, ask where it should go
rather than defaulting to the repo root.

This repository is **public**. A working document written inside it is one
`git add -A` away from being published, and that is not a hypothetical: it
happened on 2026-08-14, and what caught it was the licence check reporting
`UNLICENSED` rather than anyone noticing the file did not belong. The gate was
right by accident, since it objects to a missing SPDX header and knows nothing
about session logs.

`/session-log-*.md` is in `.gitignore` as a backstop, but the rule is the point:
the file should not be in the tree at all. An ignore entry only covers the name
someone thought of in advance.
