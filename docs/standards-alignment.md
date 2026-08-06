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

> **Verified against the primary source.** NIST Special Publication 800-207,
> *Zero Trust Architecture*, 59 pages, August 2020
> ([doi:10.6028/NIST.SP.800-207](https://doi.org/10.6028/NIST.SP.800-207)).
> Tenet numbering and wording below were read from section 2.1 of that document
> on **2026-08-05**. See the verification log at the end of this file.

The tenets in section 2.1. Kessa is not a full zero-trust architecture; it is an
authorization and evidence layer that several tenets bear on directly. Tenet
wording is quoted from the publication; the "what Kessa does" column is ours.

| Tenet | The tenet, as published | What Kessa does | Check it |
|---|---|---|---|
| 3 | "Access to individual enterprise resources is granted on a per-session basis." | Each delegation hop mints a new credential rather than passing a token along, and a hop cannot broaden what it received | `TestAttenuate_NarrowsAndVerifies`, `TestAttenuate_RejectsBroadening`, `TestIssuerRefusesBroadeningDelegation` |
| 4 | "Access to resources is determined by dynamic policy." | Consequentiality is re-derived from the carried, signed policy at decision time, not read as a stored bit | `TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted`, [`internal/policy`](../internal/policy/) |
| 6 | "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | Chain verification and proof of possession run before any decision is recorded or action allowed; a request that fails either produces no log entry at all | `TestProofOfPossession_HolderControlsKey`, `TestProofOfPossession_BoundToActionAndSeq`, `TestTokenLoan_CopiedBlobFailsPoP` |
| 7 | "The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture." | Every consequential decision is recorded as signed, hash-chained evidence that a third party can re-derive offline | [`internal/audit`](../internal/audit/), `TestAcceptance_TamperedExportFailsAtExactlyThatEntry` |

**Partial, stated plainly.** Tenet 2, "All communication is secured regardless of
network location", is **not** addressed: the enforcement endpoint has no caller
authentication, and non-loopback binds are refused unless you pass
`--allow-unauthenticated-remote`. See [Known limits](../README.md#known-limits).

Tenet 4 continues past the clause quoted above, to include "the observable state
of client identity, application/service, and the requesting asset" and possibly
"other behavioral and environmental attributes". Kessa's policy input is the
carried credential chain and the action, not device posture or behavioural
signals, so it satisfies the quoted clause and not the full tenet.

## EU AI Act

> **NOT yet verified against the primary source.** Article numbers and headings
> below were taken from secondary sources on 2026-08-05. EUR-Lex serves its texts
> from behind a bot-protection layer that refuses automated retrieval, so the
> Official Journal text has not been read directly. Treat every article reference
> in this section as unconfirmed until the verification log at the end of this
> file says otherwise.

Regulation (EU) 2024/1689 of 13 June 2024. Articles 12 and 15 as they apply to
high-risk systems. Kessa is a component, not a system, so it can support an
obligation but never discharge one.

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

> **Verified against the primary source.** Regulation (EU) 2022/2554 of
> 14 December 2022 on digital operational resilience for the financial sector,
> OJ L 333, 27.12.2022. Article 9, "Protection and prevention", sits in Chapter II
> (ICT risk management). Read directly on **2026-08-05**; paragraph references and
> quoted wording below come from that text.

DORA places obligations on **financial entities**, not on software. Kessa is a
tool such an entity could use toward them; it cannot discharge an obligation, and
no row below should be read as saying otherwise.

| Provision | The requirement, as published | What Kessa does | Check it |
|---|---|---|---|
| Art. 9(2) | ICT security policies, procedures, protocols and tools that "maintain high standards of availability, authenticity, integrity and confidentiality of data, whether at rest, in use or in transit" | Addresses **authenticity and integrity** for one class of data, the authority and audit record: evidence is signed per hop and hash-chained, and the verifier re-derives every verdict from public keys with no service of ours in the path. Availability and confidentiality are not addressed. | `TestIssuedChainVerifiesAgainstPublishedDIDDocs`, `TestPublishedStatusListIsSignedByItsIssuer`, `TestR2_04_TipCarriesPrevHash` |
| Art. 9(3)(b) | ICT solutions that "minimise the risk of corruption or loss of data, unauthorised access and technical flaws" | Tampering with a signed export is detected at exactly the altered entry rather than minimised, and entries cannot be reordered or dropped without breaking the signature over the count and tip | `TestAcceptance_TamperedExportFailsAtExactlyThatEntry`, `TestR2_02_TruncatedExportIsRejected` |
| Art. 9(4)(c) | Policies that "limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only", with controls addressing access rights | Each delegation hop is minted strictly narrower than its parent, and revocation is checked against a signed status list at action time, so a revoked mid-chain credential stops the consequential actions depending on it | `TestAttenuate_RejectsBroadening`, `TestAcceptance_RevokedThenUsedFailsThatEntry`, `TestR2_01_RevocationSurvivesAStatusRefEdit` |

**Partial, stated plainly.** Art. 9(4)(c) is written about a financial entity's
own access-rights administration across its ICT estate. Kessa governs one thing
inside that: authority delegated to agents. It is a mechanism an entity could
point at for part of this provision, not coverage of it.

Status is also checked against the *current* list, not the list as of action time,
so re-verifying an old export after a later revocation flips previously-legitimate
entries to FAIL. This is an honest false-FAIL and is documented as such under
[Known limits](../README.md#known-limits).

---

## Considered and not claimed

Listed because their absence is information. A standard Kessa does not address is
more useful to a reader than a row stretched to cover one.

| Standard | Why there is no row |
|---|---|
| RATS architecture (RFC 9334) and EAT | Kessa's audit export is its own format (`kessa-audit-export/v2`), not an EAT or any RATS-defined evidence format. There is no interoperability claim to make. |
| OWASP Agentic AI Top 10 | Several items are plainly adjacent to what Kessa does, but the list's item identifiers and wording are still moving. A row citing an ID that later shifts is worse than no row. Revisit when the numbering is stable. |
| SOC 2, ISO 27001 | Organizational controls audited against an operator, not properties of a piece of software. Kessa can be evidence inside such an audit; it cannot align with one. |
| NIST SP 800-207 tenets 1 and 5 | Tenet 1 is "All data sources and computing services are considered resources", a classification decision an enterprise makes about its own estate. Tenet 5 is "The enterprise monitors and measures the integrity and security posture of all owned and associated assets". Kessa does neither: it has no view of the estate and measures no asset's posture. |

---

## Verification log

Standards texts drift, and a mapping that was right in 2026 can be wrong later
without anything in this repository changing. So each standard carries the date
its citations were last read against the primary source, and what "primary
source" meant.

| Standard | Last verified | Against what | By |
|---|---|---|---|
| NIST SP 800-207 | 2026-08-05 | The publication itself, 59 pages, August 2020, retrieved from `nvlpubs.nist.gov` and read directly. Tenet numbering and wording quoted from section 2.1. | Maintainer |
| DORA (2022/2554) | 2026-08-05 | The Official Journal text, OJ L 333, 27.12.2022, 79 pages, read directly. Article 9's heading, its position in Chapter II, and the wording of paragraphs 2, 3(b) and 4(c) confirmed. | Maintainer |
| EU AI Act (2024/1689) | **never** | Secondary sources only. EUR-Lex refuses automated retrieval (bot protection), so the Official Journal text has not been read. | |

**A row is only as good as its date.** When a standard is revised, re-read it and
update both the row and this table, or delete the row. An out-of-date mapping
presented as current is worse than no mapping, because a reader has no way to tell
which it is.

### What verifying the last one requires

EUR-Lex serves the Official Journal from behind a bot-protection layer, so it
cannot be fetched by tooling; the DORA text above was verified from a copy
retrieved by hand. The AI Act section needs the same treatment: open
Regulation (EU) 2024/1689 and confirm, for each row, the article number, the
article heading, and that the quoted requirement is the article's operative text
rather than a commentary site's gloss.

## Caveats on this document

**Every "what Kessa does" cell is a statement about this repository**, and those
are checkable directly by the test names and paths in the last column. Those were
verified when this file was written. If a row's artifact does not do what the row
says, that is a defect in this document; please report it.

The claims in the *other* direction, about what each standard requires, are only
as reliable as the verification log above says. The two are different kinds of
statement and are worth reading differently.
