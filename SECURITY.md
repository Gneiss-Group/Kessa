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

## Known boundaries (not findings on their own)

- The **software keystore and software signer are POC mocks** (labeled as such in
  the code); "keys live in software" is a documented boundary, not a vulnerability
  in itself. A leak of a mock boundary into a shipping path *is* worth reporting.
- **Denial of service** from pathological inputs is welcome, but rated below an
  invariant break.

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
