<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Standards alignment

A mapping from published requirements to the specific thing in this repository
that addresses them.

**Read the disclaimer before the table.** Kessa is **not certified, audited, or
assessed** against any standard listed here. No external audit has been
commissioned; the adversarial review rounds were self-run AI red-team passes (see
the [security review record](security-review.md)). This document claims one thing
only: that for each row, the artifact named in the last column exists and does
what the row says. Nothing here is a compliance attestation, and using Kessa does
not make a system compliant with anything.

The discipline this table is written to, and the reason it is worth reading:
**every row points at a file, a test name, or a documented limit that you can go
check yourself.** A row that could only be supported by a bare assertion is not in
the table. Where Kessa addresses part of a requirement and not the rest, the row
says so rather than rounding up.

## How to check a row

Test names are real and runnable:

```sh
go test ./... -run TestAttenuate_RejectsBroadening -v
```

File paths are relative to the repository root. Limit references point at named
sections of [`README.md`](../README.md) or [`UPCOMING.md`](../UPCOMING.md), which
state boundaries in the negative rather than describing capability.

---

## NIST SP 800-207 (Zero Trust Architecture)

The tenets in section 2.1. Kessa is not a full zero-trust architecture; it is an
authorization and evidence layer that several tenets bear on directly.

| Tenet | Requirement, in one clause | What Kessa does | Check it |
|---|---|---|---|
| 3 | Access is granted per-session | Each delegation hop mints a new credential rather than passing a token along, and a hop cannot broaden what it received | `TestAttenuate_NarrowsAndVerifies`, `TestAttenuate_RejectsBroadening`, `TestIssuerRefusesBroadeningDelegation` |
| 4 | Access is determined by dynamic policy | Consequentiality is re-derived from the carried, signed policy at decision time, not read as a stored bit | `TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted`, [`internal/policy`](../internal/policy/) |
| 6 | Authentication and authorization are dynamic and strictly enforced *before* access | Chain verification and proof of possession run before any decision is recorded or action allowed; a request that fails either produces no log entry at all | `TestProofOfPossession_HolderControlsKey`, `TestProofOfPossession_BoundToActionAndSeq`, `TestTokenLoan_CopiedBlobFailsPoP` |
| 7 | Collect state about assets and communications, and use it to improve posture | Every consequential decision is recorded as signed, hash-chained evidence that a third party can re-derive offline | [`internal/audit`](../internal/audit/), `TestAcceptance_TamperedExportFailsAtExactlyThatEntry` |

**Partial, stated plainly.** Tenet 2 (all communication secured regardless of
network location) is **not** addressed: the enforcement endpoint has no caller
authentication, and non-loopback binds are refused unless you pass
`--allow-unauthenticated-remote`. See [Known limits](../README.md#known-limits).

## EU AI Act

Articles 12 and 15 as they apply to high-risk systems. Kessa is a component, not
a system, so it can support an obligation but never discharge one.

| Article | Requirement, in one clause | What Kessa does | Check it |
|---|---|---|---|
| Art. 12 (record-keeping) | Automatic recording of events over the system's lifetime | Consequential decisions are appended to a hash-chained log, signed with the entry count and log tip covered, so entries cannot be edited, reordered, or dropped after the fact | `TestR2_02_TruncatedExportIsRejected`, `TestR2_04_TipCarriesPrevHash` |
| Art. 12 (traceability) | Records support traceability of the system's functioning | Each entry carries the delegation chain, the policy, and the approval as evidence, so a verdict can be re-derived rather than trusted | [`docs/how-it-works.md`](how-it-works.md#what-a-clean-verdict-actually-proves) |
| Art. 15 (robustness) | Resilience against attempts to alter use or performance by exploiting vulnerabilities | Tampering with a signed export fails at exactly the altered entry and marks everything after it unverified | `TestScenario7_Tamper`, `make demo` scenario 7 |

**Partial, stated plainly.** Art. 12 asks for logging over the lifetime of the
system. Kessa's log is complete only for what the enforcement point chose to
record: a short log signed honestly and a short log signed by a proxy that
declined to record something are indistinguishable from the file alone. Closing
that needs the log tip anchored somewhere the enforcement point does not control,
which Kessa does not do. See [Known limits](../README.md#known-limits).

## DORA (Regulation (EU) 2022/2554)

| Article | Requirement, in one clause | What Kessa does | Check it |
|---|---|---|---|
| Art. 9 (protection and prevention) | Ensure the authenticity and integrity of data | Evidence is signed per hop and chained; the verifier re-derives every verdict from public keys with no service of ours in the path | `TestIssuedChainVerifiesAgainstPublishedDIDDocs`, `TestPublishedStatusListIsSignedByItsIssuer` |
| Art. 9 (protection and prevention) | Prevent the unauthorised use of data or systems | Revocation is checked against a signed status list at action time, so revoking a mid-chain credential stops the consequential actions depending on it | `TestAcceptance_RevokedThenUsedFailsThatEntry`, `TestR2_01_RevocationSurvivesAStatusRefEdit` |

**Partial, stated plainly.** Status is checked against the *current* list, not the
list as of action time, so re-verifying an old export after a later revocation
flips previously-legitimate entries to FAIL. This is an honest false-FAIL and is
documented as such under [Known limits](../README.md#known-limits).

---

## Considered and not claimed

Listed because their absence is information. A standard Kessa does not address is
more useful to a reader than a row stretched to cover one.

| Standard | Why there is no row |
|---|---|
| RATS architecture (RFC 9334) and EAT | Kessa's audit export is its own format (`kessa-audit-export/v2`), not an EAT or any RATS-defined evidence format. There is no interoperability claim to make. |
| OWASP Agentic AI Top 10 | Several items are plainly adjacent to what Kessa does, but the list's item identifiers and wording are still moving. A row citing an ID that later shifts is worse than no row. Revisit when the numbering is stable. |
| SOC 2, ISO 27001 | Organizational controls audited against an operator, not properties of a piece of software. Kessa can be evidence inside such an audit; it cannot align with one. |
| NIST SP 800-207 tenets 1 and 5 | Tenet 1 concerns resource inventory and tenet 5 continuous posture measurement. Kessa does neither. |

---

## Caveats on this document

**Clause numbers and article references have not been checked against the primary
sources by anyone other than the author of this file.** They are cited from the
published structure of each standard and should be verified before this document
is relied on externally or quoted in a procurement response.

**Every "what Kessa does" cell is a statement about this repository**, and those
are checkable directly. If a row's artifact does not do what the row says, that is
a defect in this document; please report it.
