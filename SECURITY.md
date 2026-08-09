<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

Kessa is security infrastructure, its entire value is a cryptographic assurance
claim, so we take vulnerability reports seriously and want them to reach us
privately, before they are public.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately to: **security@gneiss-group.com**

GitHub's private vulnerability-reporting flow is the preferred channel **where
this repository has it enabled**: check the *Security* tab. If you do not see it
there, it is not available on this repository yet; use the email address above.
Do not fall back to a public issue.

Include what you have: the affected component and version/commit, a description,
and (ideally) a proof of concept or the exact invariant you believe is broken.

We aim to acknowledge within **3 business days** and to keep you updated as we
investigate and fix.

## What matters most (in scope)

Kessa's guarantees rest on a small set of invariants. Reports that break one of
these are the highest priority:

- The **independent verifier accepting an export it should reject**: a forged or
  unjustified `Allowed: true` passing verification.
- **Attenuation broadening** rather than narrowing delegated authority.
- Any **verdict-relevant field the verifier trusts** instead of re-deriving from
  signed evidence.
- **Secrets** (private keys/seeds) reaching the publication root, an export, or a
  log line.
- **Path traversal** from a crafted DID or status identifier.

## How severity is decided

One rule: **a finding's severity is how far it goes toward invalidating the
claim Kessa exists to make**, which is that a verdict can be re-derived from
signed evidence without trusting the system that produced it.

That is the classification. It is deliberately not CVSS, and it is deliberately
not a scanner's label. **CodeQL and Scorecard severities are treated as input to
this judgement, never as the judgement**, because those tools rate a code pattern
in the abstract and have no way to know which of this project's invariants a given
line is holding up. The same rule can be Critical in the verifier and irrelevant in
a test helper.

- **Critical.** Breaks an invariant in [What matters most](#what-matters-most-in-scope).
  A verdict that should not have been reachable becomes reachable, or evidence
  that should be re-derivable stops being so. If a reader could point at the
  finding and say "then the central claim is false", it is Critical.
- **High.** Defeats a control the invariants rest on, without directly producing
  a false verdict. A revocation that does not revoke, an authority check that
  checks the wrong thing, a gate that admits input it should refuse.
- **Medium.** Real and reachable, but bounded: needs an unusual configuration, a
  non-default flag, or an attacker position that is already privileged. Denial of
  service from pathological input lands here by default.
- **Low.** Correct to fix and hard to exploit, or exploitable only against a setup
  that is already broken for other reasons.
- **Informational.** A limitation worth recording that no attacker gains from.

Two consequences worth stating, since both have already come up:

- A tool's Critical can be our High. The `go/request-forgery` finding in the
  did:web resolver is rated High in its advisory, not Critical, because it needs a
  non-default flag and produces no false verdict.
- Our Critical can be a tool's nothing. Most invariant breaks in this project are
  logic, not memory safety, and no scanner has ever flagged one of them. Every
  Critical to date came from a review round.

## Known boundaries (not findings on their own)

- The **software keystore and software signer are POC mocks** (labeled as such in
  the code); "keys live in software" is a documented boundary, not a vulnerability
  in itself. A leak of a mock boundary into a shipping path *is* worth reporting.
- **Denial of service** from pathological inputs is welcome, but rated below an
  invariant break.
- **Capacity hints on append-only buffers** are not allocation-overflow
  vulnerabilities here. `make([]byte, 0, len(a)+len(b))` allocates length zero and
  the code appends; `append` is memory-safe and grows as needed, a wrong capacity
  costs a reallocation rather than a corruption, and a negative one panics rather
  than under-allocating. Overflowing `int` on 64-bit needs the summed lengths to
  reach roughly 9.2 exabytes of already-resident memory, and every release target
  is 64-bit. Static analysis reports this pattern regularly; it is dismissed as a
  class, not case by case.
- **Scorecard checks that a solo-maintained project cannot satisfy** are not
  findings. `Code-Review` requires a second human, and most of `Branch-Protection`
  requires reviewers or code owners. These are accurately reported and accurately
  unfixable today, and turning them on would mean bypassing them on every merge,
  which is worse than scoring zero honestly.

This list grows by **class, not by instance**. A class named here covers every
future report of the same shape, which is what keeps the
[security review record](docs/security-review.md) a record of decisions rather
than a log of scanner output.

## Committed demo material (deliberate, not a leak)

Kessa is a proof of concept with **mock key management**, and it commits fixed key
material so that `make demo`, `make stories`, and the golden fixtures are
deterministic and reproducible. **None of it is a real credential**, none of it is
referenced by any non-test path, and a real deployment generates fresh keys behind
the `signer.Signer` seam (see `internal/keystore` and the README's *Known limits*).
A credential scanner will flag some of these values; that is expected, and they
are allowlisted by path in [`.gitleaks.toml`](.gitleaks.toml) with this section as
the rationale.

The committed values, exhaustively:

| Where | Value | What it is |
|-------|-------|------------|
| `examples/issuer/keystore.json`, `scripts/demo/keystore.json`, `scripts/stories/keystore.json` | Ed25519 **seeds** (e.g. `1111…`, `3131…`, `dada…`) | Fixed 32-byte signing seeds. Low-entropy repeated bytes, chosen for reproducibility. Each file carries a `MOCK KEY MANAGEMENT` header comment. |
| `examples/issuer/spec.json`, `scripts/demo/spec.json`, `scripts/stories/spec.json` | `rootKeyHex` (`00112233…`, `d0d0…`) | Fixed macaroon HMAC root keys. Each file's `_comment` marks it `NON-SECRET demo value`. |
| `internal/enforce/enforce_test.go` | `macRootKeyHx = "00112233…"` | The same demo root key, used by the enforcement tests. Allowlisted only in test code, only for this exact constant. |
| `testdata/dids/**/did.json` | `publicKeyJwk.x` | **Public** keys: published by design; a DID document is public key material. |
| `testdata/audit_export_v2.golden.json` | `holderKey` | The holder's **public** key, the same value published in each DID document. High-entropy base64, so a scanner flags it, but it is public. |

If you find committed key material that is **not** in this table, or a fixed seed
reused by a shipping (non-test, non-demo) code path, that *is* worth reporting;
see the in-scope item on secrets above.

## Disclosure

We support coordinated disclosure: report privately, allow reasonable time for a
fix, and we will credit you (if you wish) when it ships.

Findings raised after a public release are published as a **GitHub security
advisory** once a fixed version is available, not before. The advisory carries
the detail; the [security review record](docs/security-review.md) links to it, so
the public register stays complete without handing a working description of the
flaw to anyone still running an unfixed version.

Findings from pre-release hardening are documented directly in that record
instead, since no released version ever carried them.

### What this policy does not commit to yet

There is **no embargo clock and no severity threshold** that routes a finding into
a particular handling path. Stating one now would be a promise to reporters and
users who do not exist yet, on a project with no revenue and a single maintainer,
and a promise on a clock is worth less than no promise if it is made before anyone
can keep it reliably.

There is also **no private-fix workflow in practice**. GitHub's advisory flow
offers a private fork so a fix can be developed unseen and published with its
advisory. Kessa does not use it today: fixes land as ordinary public pull requests
and the advisory follows. A reader should know that, because it means the fix for a
reported issue may be visible in the commit history before the advisory describing
it is published.

Both are deliberate deferrals rather than oversights. They earn their cost when
volume or stakes make case-by-case judgement unreliable, and this project is not
there. Until then, a report gets a prompt, honest, human answer.
