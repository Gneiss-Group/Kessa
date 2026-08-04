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

Before opening a PR, run `bash scripts/ci/gate.sh`. It is the same gate CI runs.
