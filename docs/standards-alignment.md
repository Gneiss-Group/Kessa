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

> **Verified against a named secondary source, not the Official Journal.** Article
> text read on **2026-08-05** from `artificialintelligenceact.eu`, which states it
> reproduces the Official Journal version of 13 June 2024. EUR-Lex refuses
> automated retrieval, so the OJ PDF itself has not been read for this section.
> This is a weaker check than the other two sections and the log says so.

Regulation (EU) 2024/1689. Article 12 as it applies to high-risk systems. **Kessa
is not an AI system**, and Article 12's obligations fall on the provider of one,
so nothing here is Kessa discharging an obligation.

| Provision | The requirement, as published | What Kessa does | Check it |
|---|---|---|---|
| Art. 12(1) and 12(2)(c) | High-risk AI systems shall "technically allow for the automatic recording of events (logs) over the lifetime of the system", including events relevant for "monitoring the operation of high-risk AI systems referred to in Article 26(5)" | Provides **one input** to such a log, not the log: a record of which agent actions were authorised, under what delegated authority, and whether they were allowed. A deployer would still need to log the system's own operation separately. | [`internal/audit`](../internal/audit/), [`docs/how-it-works.md`](how-it-works.md#what-a-clean-verdict-actually-proves) |

**Where Kessa exceeds what the article asks, and where it falls short.** Article 12
requires that logging exist; it does not require the log to be tamper-evident.
Kessa's record is hash-chained and signed over the entry count and log tip, so
entries cannot be edited, reordered, or silently dropped
(`TestR2_02_TruncatedExportIsRejected`, `TestR2_04_TipCarriesPrevHash`). That is
more than the article demands, on a narrow slice.

The slice is the limitation. Article 12 wants logging of the AI system's operation
over its lifetime; Kessa records authorisation decisions about agent actions,
which is one category of event inside that. Completeness is also bounded: a short
log signed honestly and a short log signed by a proxy that declined to record
something are indistinguishable from the file alone. See
[Known limits](../README.md#known-limits).

Article 12(3) sets specific requirements (period of each use, reference database,
matching input data, identity of the natural persons verifying results) that apply
to the biometric systems in Annex III point 1(a). Kessa addresses none of them and
they are outside its scope.

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
| **EU AI Act Art. 15** (accuracy, robustness, cybersecurity) | **Removed after reading it.** The draft of this document claimed Art. 15 on the strength of tamper-evidence. Art. 15(5) is about systems withstanding "attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities", and its enumerated measures are model-layer: data poisoning, model poisoning, adversarial examples, confidentiality attacks, model flaws. Kessa addresses none of these. Detecting alteration of the *record after the fact* is a different property from resisting alteration of the *system's outputs*, and conflating the two was an overclaim. Kessa governs authority, not content. |
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
| EU AI Act (2024/1689) | 2026-08-05, **weaker** | Article 12 and 15 text read from `artificialintelligenceact.eu`, which states it reproduces the Official Journal version of 13 June 2024. The OJ PDF itself was **not** read: EUR-Lex refuses automated retrieval. Treat as a named-secondary check, not a primary one, and redo it against the OJ when someone has the text to hand. | Maintainer |

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
