<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Standards alignment

Kessa is an authorization and evidence layer for delegated agent authority. This
document maps published requirements to the specific mechanism that addresses
them, and to a test you can run.

**Every row cites a runnable test name or a file path.** That is the property
worth checking this document against: no row rests on an assertion you have to
take on trust, and where Kessa covers part of a requirement, the row says which
part. Kessa is not certified or audited against any standard here; no external
audit has been commissioned (see the [security review record](security-review.md)).

Test names are real:

```sh
go test ./... -run TestAttenuate_RejectsBroadening -v
```

---

## OWASP Top 10 for LLM Applications, LLM06:2025 Excessive Agency

The closest fit to what Kessa is for. OWASP names three root causes of excessive
agency and four mitigations; Kessa implements the four mitigations directly.

| OWASP recommends | What Kessa does | Check it |
|---|---|---|
| "Limit the permissions that LLM extensions are granted to other systems to the minimum necessary" | Every delegation hop mints a **new, strictly narrower** credential. A hop that tries to broaden its own authority is rejected at mint time, not at use time | `TestAttenuate_RejectsBroadening`, `TestIssuerRefusesBroadeningDelegation`, `TestVerify_NonSubsetAttenuationFails` |
| "Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not" | The decision lives in an enforcement proxy the agent cannot alter, not in the model or its prompt. The agent presents a credential chain; the proxy decides | [`internal/enforce`](../internal/enforce/), `TestScenario2_ScopeViolation`, `TestScopeViolationDenied` |
| "Enforce the complete mediation principle so that all requests made to downstream systems via extensions are validated against security policies" | Every action is checked against the carried, signed policy, and consequentiality is re-derived rather than read as a stored bit | `TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted`, `TestAllowList_RoutineRuleAllowsWithoutApproval` |
| "Utilise human-in-the-loop control to require a human to approve high-impact actions before they are taken" | Consequential actions require a signed human approval, one approval authorizes exactly one action, and a forged approval is refused | `TestScenario3_ConsequentialRequiresApproval`, `TestConsequentialWithoutApprovalDenied`, `TestR2_04_OneApprovalAuthorizesOneAction`, `TestForgedApprovalDenied` |

Against the three root causes OWASP names: **excessive permissions** is addressed
by attenuation, **excessive autonomy** by the approval gate on consequential
actions, and **excessive functionality** by policy-scoped credentials that a hop
cannot widen.

**What Kessa adds beyond the recommendation.** OWASP asks that authorization
happen in a downstream system. Kessa also makes the resulting decision
independently checkable: an offline verifier re-derives every verdict from signed
evidence, so a proxy that cut a corner produces an export that fails.

## NIST SP 800-207 (Zero Trust Architecture)

| Tenet | The tenet, as published | What Kessa does | Check it |
|---|---|---|---|
| 3 | "Access to individual enterprise resources is granted on a per-session basis." | Each hop mints a new credential rather than passing a token along, and cannot broaden what it received | `TestAttenuate_NarrowsAndVerifies`, `TestAttenuate_RejectsBroadening` |
| 4 | "Access to resources is determined by dynamic policy." | Consequentiality is re-derived from the carried, signed policy at decision time | `TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted`, [`internal/policy`](../internal/policy/) |
| 6 | "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | Chain verification and proof of possession run before any decision is recorded or action allowed; a request failing either produces no log entry at all | `TestProofOfPossession_HolderControlsKey`, `TestProofOfPossession_BoundToActionAndSeq`, `TestTokenLoan_CopiedBlobFailsPoP` |
| 7 | "The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture." | Every consequential decision is recorded as signed, hash-chained evidence a third party can re-derive offline | [`internal/audit`](../internal/audit/), `TestAcceptance_TamperedExportFailsAtExactlyThatEntry` |

**Scope.** Kessa is one layer of a zero-trust architecture, not the architecture.
Tenet 4 also reaches device posture and behavioural signals, which are inputs your
policy engine supplies, not ones Kessa observes. Tenets 1, 2, and 5 (resource
classification, securing all communication, continuous asset posture) belong to
your estate and transport design.

## DORA (Regulation (EU) 2022/2554)

DORA binds financial entities. Kessa is a tool such an entity uses toward its
obligations, and these rows are what it contributes.

| Provision | The requirement, as published | What Kessa does | Check it |
|---|---|---|---|
| Art. 9(2) | Maintain high standards of "availability, authenticity, integrity and confidentiality of data, whether at rest, in use or in transit" | Delivers **authenticity and integrity** for the authority and audit record: evidence is signed per hop and hash-chained, and verdicts are re-derived from public keys with no service of ours in the path | `TestIssuedChainVerifiesAgainstPublishedDIDDocs`, `TestPublishedStatusListIsSignedByItsIssuer`, `TestR2_04_TipCarriesPrevHash` |
| Art. 9(3)(b) | ICT solutions that "minimise the risk of corruption or loss of data, unauthorised access and technical flaws" | Tampering with a signed export is *detected at exactly the altered entry*, and entries cannot be reordered or dropped without breaking the signature over the count and tip | `TestAcceptance_TamperedExportFailsAtExactlyThatEntry`, `TestR2_02_TruncatedExportIsRejected` |
| Art. 9(4)(c) | Policies that "limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only" | Applies exactly this rule to delegated agent authority: each hop is minted strictly narrower, and revocation is checked against a signed status list at action time | `TestAttenuate_RejectsBroadening`, `TestAcceptance_RevokedThenUsedFailsThatEntry`, `TestR2_01_RevocationSurvivesAStatusRefEdit` |

**Scope.** Art. 9(4)(c) covers a financial entity's access-rights administration
across its whole ICT estate. Kessa governs the part of that estate where agents
act. Availability and confidentiality under Art. 9(2) are properties of your
deployment, not of the evidence format.

## EU AI Act (Regulation (EU) 2024/1689)

Article 12's obligations fall on the provider of a high-risk AI system. Kessa is a
component such a provider integrates.

| Provision | The requirement, as published | What Kessa does | Check it |
|---|---|---|---|
| Art. 12(1), 12(2)(c) | Systems shall "technically allow for the automatic recording of events (logs) over the lifetime of the system", including events relevant for "monitoring the operation of high-risk AI systems referred to in Article 26(5)" | Supplies the authorization record: which agent actions were permitted, under what delegated authority, and on whose approval. Unlike ordinary application logs, it is **tamper-evident**, which Art. 12 does not require and most logging does not provide | [`internal/audit`](../internal/audit/), `TestR2_02_TruncatedExportIsRejected`, `TestR2_04_TipCarriesPrevHash` |

**Scope.** Kessa records authorization decisions. Logging the AI system's own
operation, and the Art. 12(3) items specific to Annex III biometric systems, stay
with the provider.

---

## Not claimed

| Standard | Why |
|---|---|
| EU AI Act Art. 15 | Art. 15(5) requires resilience "against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities", with measures aimed at data poisoning, model poisoning, adversarial examples, confidentiality attacks and model flaws. Those are model-layer properties. Kessa governs authority, not content, and does not inspect what an agent produces. |
| RATS (RFC 9334), EAT | Kessa's export is its own format (`kessa-audit-export/v2`). No interoperability claim to make. |
| SOC 2, ISO 27001 | Audited against an operator's controls, not properties of software. Kessa can be evidence inside such an audit. |

## Verification log

Standards drift. Each row's citations were read against a source on the date
below; a mapping is only as current as its last check.

| Standard | Last read | Source |
|---|---|---|
| OWASP LLM06:2025 | 2026-08-05 | OWASP's own repository for the Top 10 for LLM Applications |
| NIST SP 800-207 | 2026-08-05 | The publication, 59 pages, August 2020 |
| DORA 2022/2554 | 2026-08-05 | Official Journal text, OJ L 333, 27.12.2022 |
| EU AI Act 2024/1689 | 2026-08-05 | Official Journal text, OJ L, 12.7.2024, 144 pages ([ELI](http://data.europa.eu/eli/reg/2024/1689/oj)) |

Claims about **what Kessa does** are checkable from the last column of every table.
Claims about **what a standard requires** are as good as this log says.
