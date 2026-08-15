<!--
SPDX-FileCopyrightText: 2026 Gneiss Group Inc.

SPDX-License-Identifier: Apache-2.0
-->

# experimental/policy-opa

An OPA-backed implementation of `policy.Evaluator`, built to find out whether
that interface is a real boundary or just a type that happens to compile.

**This is not shipped OPA support**, and building it does not commit the project
to any. Nothing in the shipped product imports this package. Read `docs/` and the
spec before treating anything here as a feature.

## Why it is a separate module

Kessa's core is stdlib-only Go with no third-party runtime dependency, which is a
property the project makes claims about rather than an accident. OPA arrives with
roughly a hundred transitive modules.

This directory has its own `go.mod`, so it is a different module from the one at
the repository root. A nested module is invisible to the parent's package walk:

```bash
go list ./...          # from the repo root: does not include this directory
go build ./...         # from the repo root: cannot pull OPA in, even by mistake
```

The root `go.mod` has no `require` block at all, and `scripts/ci/gate.sh` now
asserts that positively by building the core with the module proxy switched off.
The dependency arrow points one way only: this module reaches into the core
through the `replace` directive in its `go.mod`, and the core never reaches back.

## What was actually proved

The interface held. Both implementations pass one shared conformance suite
(`internal/policy/conformance`), which is written against `policy.Evaluator` and
never against a concrete type, so neither backend can be the one the cases were
secretly written for. On top of that, `TestDifferentialAgainstHandRolled` runs
the cross product of a few thousand actions through both evaluators and requires
the full `Decision` to match, which catches divergences nobody thought to write a
case for.

No change to `policy.Evaluator` was needed to accommodate a real third-party
engine. Two things the spec flagged as open turned out not to bite:

- **`context.Context` is not in the signature.** An in-process Rego evaluation
  never needs it, so the interface does not have to close that gap
  speculatively. It would become a real gap for OPA-over-HTTP, and only then.
- **`Version()` was sufficient** as the hook for a backend's policy identity.

The one thing that did need stating out loud was **ordering**. Kessa's classifier
is first-match-wins; Rego is declarative and its rules are unordered by
construction. Order cannot survive the translation implicitly, so each policy rule
becomes a member of a `matches` set keyed by its position and the decision is the
entry at `min(matches)`. That assumption was resting silently inside the single
implementation until a second one had to carry it across.

It also found a real defect in the core, which is the outcome that justifies
building a second implementation from a different author's assumptions rather
than testing the first one harder. The classifier compared RFC3339 timestamps as
`float64(t.UnixNano())`, which at a 2026 epoch resolves only to 256ns, while
OPA's `time.parse_rfc3339_ns` orders such instants exactly. On that one input
class OPA was right and the shipped code was wrong. It was carried here as a
pinned known divergence for a while, because `internal/macaroon` held a
byte-identical copy of the same coercion and correcting one alone would have made
the enforcement proxy and the independent verifier disagree about whether a
caveat holds. Both are now one implementation in `internal/scalar`, comparing
integer nanoseconds, and the divergence is closed.

## Running it

The core gate does not build this module, by design: `scripts/ci/gate.sh` stays
offline-hermetic so the no-network demo path keeps working. The full gate does.

```bash
bash scripts/ci/gate-full.sh
```

Or directly:

```bash
cd experimental/policy-opa && go test -race ./...
```

## Reading the translation

`Evaluator.Source()` returns the generated Rego module, which is the artifact
this experiment mostly exists to produce. For a policy with one rule it looks
roughly like:

```rego
package kessa.policy

scalar(s) := v if {
	v := time.parse_rfc3339_ns(s)
} else := v if {
	v := to_number(s)
}

default decision := {"allowed": true, "consequential": false, "ruleFired": "default", "policyVersion": "commerce-security-v1", "reason": "routine by default"}

decision := d if {
	d := decisions[min(matches)]
}

# high-value-transfer
matches contains 0 if {
	scalar(input.ctx["amount"]) >= scalar("100")
}

decisions := {
	0: {"allowed": true, "consequential": true, "ruleFired": "high-value-transfer", "policyVersion": "commerce-security-v1", "reason": "transfers at or above 100 need approval"},
}
```

Two details in there are load-bearing rather than stylistic:

- Every field read is `input.ctx[...]`, and a missing key is undefined in Rego,
  which fails the enclosing rule body. That is what reproduces the classifier's
  fail-closed treatment of an absent field, including under `!=`, where "audience
  is not internal" would otherwise read as true for an action carrying no
  audience at all.
- Builtin errors are left non-fatal, so an uncoercible comparison
  (`scalar("lots")`) is undefined and the rule simply does not match, rather than
  failing the evaluation.
