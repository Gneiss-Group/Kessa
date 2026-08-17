# Security review record

This is the public index of Kessa's adversarial review rounds: what was reviewed,
when, which findings were raised, and where each one stands. It is deliberately a
**register, not a report**, it records that a finding existed and was closed,
without reproducing the mechanism.

**What this is not.** Every round was a **self-run AI red-team pass, not a
third-party audit.** No independent, named audit has been commissioned. A clean
record here says the maintainers attacked their own design and fixed what they
found; it does not carry the assurance of an external assessment. What a clean
verifier verdict does and does not prove is a separate question, stated precisely
in [what a clean verdict actually
proves](how-it-works.md#what-a-clean-verdict-actually-proves).

## Method

Each round takes a defined slice of the system, states a threat model for it, and
tries to break the claims rather than confirm them. The standing bar is
*re-derive, don't trust* and *fail closed*. Findings are fixed before the branch
merges; each fix lands with a regression test, on the principle that a fix without
a test is a fix with an expiry date.

Two rules in [Go standards](go-standards.md) exist because a round produced them
rather than because they were designed in advance: most notably *validate before
the side effect*, which was escalated to a standing rule after recurring across
rounds.

**What a round cannot do, learned in R7.** A test suite is not a witness. R7-03
was not merely missed by the conformance contract that covers that code, it was
asserted BY it as correct behaviour, under a name that claimed the opposite. A
green suite says the code still does what someone once decided it should, and
whether that decision was right is a separate question no amount of green
answers. So a round is now expected to read what a check CLAIMS and test that
claim, rather than treating a passing check as a surface already covered.

## Rounds

| Round | When | Scope | Outcome |
|---|---|---|---|
| **R1** | before first publication | Core delegation, enforcement, audit chain, and verifier | Ten findings (F1 to F10), highest severity High. All closed or accepted as documented boundaries before any code was published |
| **R2** | 2026-07-22 | Second adversarial pass over the same core, plus the export envelope and audit-sink path | Seven findings (R2-01 to R2-07), one Critical. All closed before any code was published |
| **R3** | 2026-07-26 | Scoped P-256 employee key and algorithm-agile verification (`feat/scoped-p256-employee-key`, merged 2026-07-27) | No critical or high. No false-PASS path. Four findings, all closed |
| **R4** | 2026-08-01 | The whole on-device issuer surface: enrollment, Secure Enclave backend, signing daemon, agent wiring (`feat/issuer-enrollment`, merged 2026-08-01) | No critical or high. No false-PASS path in the verifier. Four findings plus two scope observations, all closed |
| *(spec alignment)* | 2026-08-03 | Not a review round: see below. Conformance work bringing the MCP listener to revision 2026-07-28 | Surfaced one security-relevant defect (SA-01) as a by-product |
| **R5** | 2026-08-03 | The ingress surface of both listeners, reviewed because it had just changed | Six findings. Five closed (R5-01 to R5-05, no critical or high). **R5-06 was High** and is closed *as to the attack* (possession became an attribution gate, so the harm is unreachable) while the property it rests on is unchanged by design. No false-ALLOW path in any of them |
| **R6** | 2026-08-06 | Pre-publication pass over the whole product surface: end-to-end workflow logic, availability, the cryptographic primitives, and general application-security posture. Excluded the surrounding tooling (CI, licensing, REUSE) | Six findings. **R6-01 was High**: revocation lists were not bound to the party entitled to revoke, defeating revocation at both the proxy and the verifier. Closed, by a signed-format change, after the first fix attempted was wrong. Three more closed (R6-02, R6-04, R6-05), one deferred (R6-03), one informational (R6-06). No other false-ALLOW path was found in the verifier |
| **R7** | 2026-08-14 to 2026-08-15 | The delta since R6, narrowed to three surfaces: configuration-file support, the policy evaluator and its OPA seam, and brokered enforcement-point key custody. Excluded the rest of the delta by name | Seven findings, all closed in **0.2.0**. The one **High** is disclosed as [GHSA-vmr6-pgh2-c33x](https://github.com/Gneiss-Group/Kessa/security/advisories/GHSA-vmr6-pgh2-c33x) rather than described here, since it affected a released version. Three Medium: a `--check-config` report claiming checks it had not performed, config keys that resolved differently from how the file reads, and **the conformance contract that had certified the High as correct**. Three Low. First round whose findings all landed post-release, so it is also the first to run the fix-release-then-disclose order end to end |

**R1 and R2 predate this repository's first commit** (2026-07-23). Their fixes are
contained in the initial publication, so no released or published version of Kessa
ever carried them unfixed.

### Why the spec-alignment row is marked differently

SA-01 was **not found by looking for it.** It surfaced while reconciling the MCP
listener against a published specification: the defect was noticed because the
spec said a header was required and the code treated it as optional, not because
anyone was hunting for a bypass.

That is a weaker kind of evidence than a finding from a review round, and the
distinction is recorded rather than smoothed over, because it bears on how much
weight this register should carry. A round is a claim that a surface was
deliberately attacked. A by-product is a claim that one defect was noticed while
doing something else, which says nothing about what a real attempt would have
turned up on the same surface.

R5 is the answer to exactly that question: the ingress surface was then reviewed
properly, on the theory that a defect class found by accident is unlikely to have
only one instance. It had four more.

The working notes for every round are retained privately and are not published.
The entries below are drawn from them.

## Findings index

Severity is as each round rated it. Identifiers appear throughout the source as
`(R2-01)`-style references, so any comment or test naming a finding resolves here.

### R1

Round 1 raised ten findings. F1 to F4 were four instances of a single class: a
verdict-relevant field left outside the signed material, which became the
project's central coding rule. F5 to F6 were low-severity hardening. F7 to F10 were
informational: they were resolved by deciding and documenting a boundary rather
than by changing behaviour, and they are the origin of the *Accepted, documented
risks* list in the [README](../README.md#known-limits).

| ID | Sev | Area | Status |
|---|---|---|---|
| F1 | High | Verifier re-derivation of consequentiality from the carried policy | Closed |
| F2 | High | Export format version bound into the signed material; integrity-only exit semantics | Closed |
| F3 | Medium | Proof-of-possession binding to a specific action | Closed |
| F4 | Medium | Binding of possession and approval to an entry's position in the log | Closed |
| F5 | Low | Host validation on the status publication path | Closed |
| F6 | Low | Inbound request size limit on the enforcement endpoint | Closed |
| F7 | Info | Role of the VC wrapper in cross-org trust | Closed: documented as not load-bearing |
| F8 | Info | Clock trust for expiry caveats (no independent clock) | Accepted, documented boundary |
| F9 | Info | Surface of the opt-in `--fetch-dids` mode | Accepted, documented boundary |
| F10 | Info | Committed demo key material | Accepted, documented boundary |

### R2: 2026-07-22

Seven findings, plus one item on `macaroon.Verify`. Two were further instances of
the round-1 class; the rest included one class the round-1 principle did not
cover. The round also recorded negative results: attacks attempted that did not
work: against the round-1 open items.

| ID | Sev | Area | Status |
|---|---|---|---|
| R2-01 | **Critical** | Coverage of credential and status references by the issuance signature | Closed |
| R2-02 | High | Export envelope completeness: entry count and log tip | Closed |
| R2-03 | High | Audit-sink dispatch behaviour under a slow or hung sink | Closed |
| R2-04 | Medium | Concurrency on the hash-chained audit log | Closed |
| R2-05 | Low | Disclosure of the verifier's trust root in its own output | Closed |
| R2-06 | Low | An overclaiming statement in the documented guarantees | Closed |
| R2-07 | Low | Policy rule and version handling in re-derivation | Closed |

### R3: scoped P-256 employee key (2026-07-26)

| ID | Sev | Area | Status |
|---|---|---|---|
| R3-01 | Medium | Boundary validation at credential construction | Closed |
| R3-02 | Low-Med | JWK encoding of non-P-256 EC keys | Closed |
| R3-03 | Low | ECDSA signature malleability on the employee-key path | Closed (recorded judgment) |
| R3-04 | Low | End-to-end verifier coverage with a P-256 employee key | Closed |

### R4: on-device issuer (2026-08-01)

| ID | Sev | Area | Status |
|---|---|---|---|
| R4-01 | Low | Per-connection deadline on the signing daemon | Closed |
| R4-02 | Medium | Hardware backing required for approval keys in the daemon | Closed; op-level policy deferred |
| R4-03 | Medium | Enrollment ordering: validation before any side effect | Closed; escalated to a standing rule |
| R4-04 | Low | Org root key passed on the command line | Closed |
| SO-1 |: | Org-DID preflight limited to local files | Closed |
| SO-2 |: | Enrolled Enclave key not loadable by the daemon | Closed |

### SA-01: surfaced by spec alignment, not by review (2026-08-03)

| ID | Sev | Area | Status |
|---|---|---|---|
| SA-01 | Medium | Mirrored request headers on the MCP listener validated only when present, so a client could omit them and skip the check entirely | Closed |

The listener advertised conformance to MCP revision 2026-07-28 while implementing
the model that revision replaced. Reconciling the two turned up SA-01: the
specification makes the mirrored headers required, and the code treated them as
optional-if-present. The headers exist so an intermediary can route without
parsing the body, so a skippable check is a route-versus-enforce split.

Recorded separately from the numbered rounds because of how it was found. See
[Why the spec-alignment row is marked differently](#why-the-spec-alignment-row-is-marked-differently).

### R5: ingress surface (2026-08-03)

Scoped to ingress because that is what the spec-alignment work had just changed,
and anchored on SA-01's defect class: **a check that does not fire.** Two findings
are checks that fired only under some inputs; two are checks that were absent
altogether. The sixth is what following the fifth to its root turned up: a check
that fires correctly and still does not establish what the endpoint needed.

| ID | Sev | Area | Status |
|---|---|---|---|
| R5-01 | Medium | No `Origin` validation on either listener: a DNS-rebinding path to the chokepoint and to the audit export | Closed |
| R5-02 | Medium | Mirrored header validated only in its first occurrence, so a repeated, contradictory value went unread | Closed |
| R5-03 | Low | An explicit null JSON-RPC id processed as a request | Closed |
| R5-04 | Low | Required `clientCapabilities` checked for presence only, so a null satisfied it | Closed |
| R5-05 | Low | No request `Content-Type` validation, leaving cross-origin forgery defence incidental rather than deliberate | Closed |
| R5-06 | **High** | An export is a bearer artifact: the chain re-derives from it, and chain verification was the only gate before an audit entry was written, so an export doubled as a write credential for a reachable proxy | **Closed as to the attack**: unexploitable at `/enforce`. The bearer property itself is unchanged and is a standing characteristic; see below |

R5-06 was the only High in this round and is not an ingress bug: following R5-05
to its root turned up an architectural property instead. It is stated in full
below, including how it was closed, because it changes what the other five
findings mean.

These findings touch **two properties that must be stated separately**, because
"no false-ALLOW" on its own is the more flattering half and would leave the other
unsaid.

**1. No unauthorized action was allowed.** An ALLOW still requires a proof of
possession signed by the holder's key and bound to the action and the entry's
position. None of that machinery was reachable through these findings, so no
attacker obtained an authorization they did not hold.

**2. An unauthorized party could write to the system of record.** This is the
distinct property, and for a product whose claim *is* the audit trail it is the
one that matters. The only gate before an entry is written is chain verification,
and a delegation chain verifies against **public** DID documents, so it carries
no secret. It is a bearer artifact: anyone holding a copy can present it. A
request bearing a copied chain and a worthless proof of possession is *denied*,
and **that denial is recorded**: a genuine entry, correctly signed, correctly
hash-chained, which the independent verifier re-derives as PASS.

The verifier is not wrong to pass it. It re-derives what the enforcement point
saw, and the enforcement point saw a request it had no business accepting. The
defect is upstream of every guarantee the verifier makes.

Two consequences follow, neither covered by "no false-ALLOW":

- **Record pollution.** Entries an operator did not cause, indistinguishable
  after the fact from ones they did, in the log that is meant to settle exactly
  that question.
- **Denial of correct operation.** Each write advances the tip. A legitimate
  caller's proof of possession is bound to the position it read, so an attacker
  writing entries makes honest in-flight requests fail against a position that
  has moved.

Audit disclosure under rebinding (R5-01) compounds both: the same page that can
write can also read the export.

### R5-06: the export is a bearer artifact (High, closed as to the attack)

Naming *what* the write gate actually is, rather than what it looks like:

**Chain verification is public verifiability, not authentication.** A delegation
chain verifies against public DID documents. That is deliberate and load-bearing:
it is exactly what lets the independent verifier re-check a chain offline, with no
shared secret and nothing of ours running. It is the property the product is built
on.

A v2 export carries each credential together with its issuer proof, for the same
reason. So **the chain can be re-derived from an export alone**: demonstrated, not
inferred: a chain rebuilt from nothing but exported bytes verifies.

Chain verification being the only pre-write gate therefore means a chain proves
**issuance**, which is public, where the endpoint needed **possession**, which is
what a private key is for. This is not a flaw in the chain design. It is the chain
design meeting an ingress path that assumed more than a chain provides.

**The reach is wider than R5's browser framing.** R5-01 and R5-05 defend against a
web page. This needs no browser: a plain HTTP POST with an export-derived chain and
a worthless signature is enough. Observed end to end: the entry is written, the
tip advances, and an honest caller whose proof was bound to the previous position
is then denied. No key, no browser, no insider access; only an export, which is the
artifact this system exists to hand out.

**The customer-facing statement.** "Treat an export as a write credential" is
accurate and too soft. An export exists to be handed to parties who do not trust
you and whom you need not trust. So: **anyone you give an export to gains the
ability to write to the log they are auditing**: auditor, regulator,
counterparty, opposing counsel. That is a property of the distribution model the
product is built on, not a deployment caveat, and it is where a reader lands
within a minute of the limitation anyway.

**How far it reaches: bounded, and the bound was checked rather than assumed.**
A proxy resolves DIDs with `did.FileResolver` over its local `--dids` directory
and has **no network resolution**; there is no `--fetch-dids` on the proxy as
there is on the verifier. A chain is therefore only usable against a proxy whose
trust root resolves **every** hop of it. Verified: an unrelated org's root rejects
the chain, and so does a partially-trusting root. The reach is:

1. the deployment that issued the export, which necessarily resolves its own DIDs;
2. any proxy deliberately configured to trust that org: the cross-org case,
   working as designed.

**It does not reach an arbitrary party on the internet.** The recipient of your
export can write to *your* log, not to a stranger's. That distinction is stated
explicitly because a reader who cannot tell will assume the worse one, and the
worse one would be disqualifying rather than merely bad.

**Severity is High and gated on reachability.** The listeners bind to loopback by
default, so the practical precondition is network reach to the endpoint, which a
non-local bind, or the documented container command's published ports, grants.
Loopback is the current mitigation and it is not authentication.

**How it was closed: by moving the attribution boundary, not by adding
authentication.** The two obvious ingress fixes are both wrong: carrying fewer
credentials in the export breaks the offline verifier, and silently dropping a
failed proof of possession erases the evidence of the attack. The third option was
to notice that the design was internally inconsistent. An unverifiable *chain* was
already refused unlogged as "not attributable"; an unverifiable *possession* was
recorded as a decision about the holder, when the one thing established was that
it was not the holder. Both are attribution failures.

Proof of possession is therefore now a **gate**, checked before anything is
appended. A request that fails it is refused (HTTP 422) and produces no entry. The
resulting property is stronger than the one it replaced: **the log records only
attributable decisions**, so an entry from a party nobody can identify is not
defended against, it is impossible.

Refused attempts are reported to the audit sink as telemetry
(`Outcome: "unattributable"`), with their own dispatch budget so a flood cannot
evict the records that reveal it. That half is not optional: without it, closing
the hole would have converted a loud attack into a silent one.

Two consequences worth recording. Every entry now carries the proof that
attributed it, including denials, which previously carried none when the denial
came from policy or authority. And a concurrent caller that loses the race for a
slot is now refused rather than logged: its proof was bound to a position another
request took, so honest races no longer leave denials in the record either. The
refusal names the position and the retry, because the proxy cannot distinguish a
stale proof from a forged one and does not pretend to.

**What is closed, and what is not: stated separately, because "closed" alone
invites the wrong conclusion.**

*Closed:* the harm. Pollution and tip-advance are unreachable at `/enforce`. An
export can no longer be turned into an audit entry in anyone's log.

*Unchanged, by design:* the property underneath. **An export is still re-derivable
into a verifying delegation chain by anyone holding it.** That was never a defect
to fix, it is public verifiability, the thing that lets the offline verifier work
against public keys with no shared secret, and removing it would remove the
product's central claim. It is recorded here as a **standing characteristic**, not
as a resolved finding, so that a future ingress path is designed knowing a chain
proves issuance and not possession. R5-06 happened because one path assumed
otherwise; the property will still be there for the next one.

*Still open:* the narrower question of **who may submit at all**. The endpoint has
no caller authentication; a non-loopback bind is refused unless
`--allow-unauthenticated-remote` is passed, which is a fail-closed default rather
than an answer. See [`UPCOMING.md`](../UPCOMING.md).

R5-01 and R5-05 also applied to the generic HTTP listener, which had not changed.
They were fixed there too: a defence applied to one of two doors is not a defence.

### R6: pre-publication pass over the product (2026-08-06)

Scoped to the product itself rather than to a surface that had just changed, on
the theory that the last review before a repository goes public should not be a
narrow one: end-to-end workflow logic, availability under unsophisticated abuse,
the cryptographic primitives, and general application-security posture. The
surrounding tooling (CI, licensing, REUSE) was excluded.

| ID | Sev | Area | Status |
|---|---|---|---|
| R6-01 | **High** | Revocation lists were verified against a key the list named for itself, so nothing bound a list to the party entitled to revoke | Closed; format change, see below |
| R6-02 | Medium | No timeouts on any HTTP listener, so a half-open request parked a goroutine and a connection indefinitely | Closed |
| R6-03 | Medium | `GET /export` is an unauthenticated amplifier that holds the enforcement lock | Deferred; see [`UPCOMING.md`](../UPCOMING.md) |
| R6-04 | Medium | Caller-supplied proof-of-possession and approval bytes were unbounded and recorded verbatim into the signed log, on denied requests too | Closed |
| R6-05 | Low | The documented expiry limitation understated itself: the timestamp is supplied by the party the caveat constrains, not merely by an untrusted clock | Closed: documentation |
| R6-06 | Info | DID verification relationships (`authentication`, `assertionMethod`) are not enforced; the first verification method is used for every purpose | Open, informational |

Two observations from the round are worth keeping, because they say something
about where the previous five rounds were not looking.

**R6-02 and R6-04 are the same shape**: a bound that was never set, on a resource
an attacker chooses the size of. Neither is an authority bug and neither can
produce a false ALLOW, which is likely why five rounds aimed at authority walked
past them. Both are in the transport layer, which no earlier round had scoped.

**R6-05 is a documentation finding and is recorded as one deliberately.** Nothing
was newly broken; the stated limitation did not match the code, and it was wrong
in the flattering direction. That is the same failure as the round-2 correction to
`internal/credential`'s package doc, and it earns a finding number for the same
reason: a limitation that understates itself is worse than the limitation.

### R6-01: a revocation list was not bound to the party entitled to revoke (High, closed)

A status list is a self-asserting artifact: it carries the DID of its own signer,
and both trust paths resolved the verification key from that field. The check
therefore confirmed that whoever a list claimed had signed it had in fact signed
it, and established nothing about that party's authority to revoke. Revocation
was defeatable at the proxy and at the verifier, and the resulting export
re-derived as a clean, evidence-backed PASS.

This is R5-06's shape rather than R5's. The R5 class was *a check that does not
fire*; here the check fired every time and verified correctly while answering a
question nobody had asked. The rule the two share, and the one worth carrying
forward: **a self-asserting artifact cannot be allowed to name the key it is
checked against.**

**Reachability, stated so the severity is not read as worse than it is.** No
network status resolver ships today; both the proxy and the verifier read
operator-supplied files, so this was not remotely exploitable. It mattered at the
verifier, where an auditor is routinely handed the export *and* its status lists
by the party being audited, and it would have become directly exploitable the day
an HTTPS status resolver shipped.

**The first fix was wrong, which is why the finding is written up rather than
tabulated.** Requiring a list's signer to equal each hop's own issuer broke the
product's own primary example, because one organization publishing one revocation
list for its whole delegation subtree is the intended design and is what the
herd-privacy floor exists for. *Who minted a credential* and *who is authoritative
for its revocation* are different questions, and the first fix assumed they were
one. The test suite caught it, not review.

**How it was closed.** Since neither the list nor the chain could answer the
second question, the credential now does: a status reference names its revocation
authority, read through a single accessor both trust paths call so they cannot
disagree. The field sits inside the issuance signature (R2-01), so it is
issuer-chosen and not holder-steerable; omitting it narrows to the credential's
own issuer rather than relaxing the check, which is the opposite polarity to the
`omitempty` shapes R5 was full of and has its own regression test. The format
change and its retroactive-tightening consequence are recorded in
[`CHANGELOG.md`](../CHANGELOG.md).

Five regression tests cover both trust paths, including a genuine revocation still
denying, without which a proxy that denied everything would satisfy the rest. All
were confirmed to fail with the binding removed.

### R7: configuration, the evaluator seam, and key custody (2026-08-14 to 2026-08-15)

Scoped to the delta since R6 and narrowed to three surfaces that had just changed:
configuration-file support, the policy evaluator and its OPA seam, and brokered
enforcement-point key custody. The rest of the delta was excluded by name rather
than left unmentioned, which is the same enumerate-and-exclude rule the coverage
checks in the codebase are held to.

**This is the first round whose findings all landed against a released version**,
so it is the first to run the order this page commits to: fix, release, then
disclose against a version a reader can install.

| ID | Sev | Area | Status |
|---|---|---|---|
| R7-03 | **High** | An attacker-supplied action attribute could classify a consequential action as routine | Closed in 0.2.0. Disclosed as [GHSA-vmr6-pgh2-c33x](https://github.com/Gneiss-Group/Kessa/security/advisories/GHSA-vmr6-pgh2-c33x), not described here |
| R7-04 | Medium | The conformance contract asserted R7-03's outcome as correct and named it "fails closed" | Closed in 0.2.0; see below |
| R7-01 | Medium | `--check-config` reported status lists as signature-checked when it had only parsed them, and reported the DID trust root as loaded without opening it | Closed in 0.2.0 |
| R7-02 | Medium | A duplicate or differently-cased JSON key resolved silently, so a config file's reviewed content and its effective content could differ | Closed in 0.2.0 |
| R7-05 | Low | The signing daemon tightened the permissions of whatever directory its socket path named, reaching outside its own footprint | Closed in 0.2.0 |
| R7-06 | Low | The derived set of flags refused alongside `--config` missed pointer- and slice-nested tags, failing permissively. Latent: no schema used those shapes | Closed in 0.2.0 |
| R7-07 | Low | No timeout, size cap or recursion bound on policy evaluation, and no defence at the evaluator boundary against an implementation that panics | Closed in 0.2.0 |

**R7-04 is the finding worth carrying forward, and it is not a defect in the
product.** The shared conformance contract, which exists so that two independent
policy backends can be held to one meaning, asserted the very outcome R7-03
produces and labelled it "fails closed" while running under the posture in which
it is the permissive one. So the differential could not have found R7-03: both
implementations agreed, because the contract required them to.

The fix was therefore not only to the classifier. Every ordering case in the
contract now runs under both postures and asserts the resulting decision rather
than whether one rule matched, and the new Rego was written from the stated
semantics rather than transcribed from the Go, with a mutation check in both
directions confirming each side's guard is load-bearing.

**R7-01 and R7-02 are the same shape as each other**: a report or a file that a
reader would take one way and the system took another. Neither can produce a false
ALLOW. Both matter because the artifact they undermine is the one an operator uses
to decide whether a deployment is correct.

## Published advisories

Findings raised after a tagged release are disclosed through GitHub's security
advisory workflow rather than described here, for the reason given under [How
this record will work going forward](#how-this-record-will-work-going-forward).
This section is the index; the advisory is the account.

| Advisory | Sev | Affected | Fixed in | What it covers |
|---|---|---|---|---|
| [GHSA-mw7q-jp9f-576r](https://github.com/Gneiss-Group/Kessa/security/advisories/GHSA-mw7q-jp9f-576r) | High | `<= 0.0.1` | **0.0.2** | did:web resolution could be steered to unintended hosts when `--fetch-dids` is enabled |
| [GHSA-vmr6-pgh2-c33x](https://github.com/Gneiss-Group/Kessa/security/advisories/GHSA-vmr6-pgh2-c33x) | High | `<= 0.1.0` | **0.2.0** | an attacker-supplied action attribute could classify a consequential action as routine, skipping the human approval gate |

Two things about that advisory are worth recording here, because they are
decisions rather than facts about the defect.

**It is one advisory covering a defect fixed in two parts.** Host confusion and
uncontrolled redirects were closed first, and the choice of destination second.
Splitting them would have produced two advisories for one exposure and invited a
reader to patch half of it, so the advisory stayed a draft until both halves
shipped in the same release. Disclosing once, against a version that carries the
whole fix, is the trade this makes deliberately.

**No CVE was requested.** An advisory published here reaches the channels that
matter for software distributed from this repository. A CVE earns its place when
notification has to travel further than that, which is a judgement about
distribution rather than about severity. A third party taking a dependency on
Kessa, or redistributing it, would each put consumers beyond the reach of this
page, and either would change the answer.

What remains after the fix is stated in [Known
limits](../README.md#known-limits) rather than left implied: `--fetch-dids`
reaches only hosts the operator names, at paths the DID chooses.

**GHSA-vmr6-pgh2-c33x is one advisory covering three defects for the same
reason**, and in its case the three are not merely related: fixing the first
extended the third. An infinity was made unparseable, which is correct where a
rule declares something routine and, until the third defect was closed, was the
permissive answer where a rule declares something consequential. Disclosing them
separately would have described a sequence of partial states none of which was
ever released.

Its own account records two things this page will not repeat, and they are the
part worth reading: two of the three had been publicly described in commit
messages before the advisory existed, and the third had been **certified as
correct by this project's own conformance suite**, which asserted the defective
outcome and called it "fails closed" while running the posture in which it was
the permissive one. That is why the differential test between the two policy
backends could not have found it. Both implementations agreed, by contract.

## Deferred, and why

These are recorded as open rather than closed. All but the first are design
decisions or scale-dependent work rather than unfixed defects:

- **R6-03: `GET /export` amplification**, and with it the absence of any
  connection-count cap on the listeners. See [`UPCOMING.md`](../UPCOMING.md).

- **Caller authentication on the enforcement endpoint.** R5-06 is closed: an
  unattributable request can no longer cause a write, but the endpoint still does
  not establish *who may submit at all*. A non-loopback bind is refused unless
  `--allow-unauthenticated-remote` is passed, which is a fail-closed default rather
  than authentication. See [`UPCOMING.md`](../UPCOMING.md).

- **S1: status is checked against the current status list**, not the list as of
  action time. Re-verifying an old export after a later revocation flips
  previously-legitimate entries to FAIL. An honest false-FAIL: current-list
  semantics cannot make a genuinely bad historical action pass.
- **Op-level approval-vs-possession policy** in the signing daemon (the fuller
  R4-02 design). Enforcement today stops at the hardware/software gate.
- **A hard connection-count cap** on the daemon socket (R4-01), low value behind
  the peer-uid gate.
- **Secure Enclave persistence under a signed Go binary.** The mechanism is
  hardware-validated; the compiled daemon has not itself run under a provisioning
  profile. See [Signing backends](signer.md).

The full list of open questions and known gaps is in
[`UPCOMING.md`](../UPCOMING.md); the limits of a clean verdict are under [Known
limits](../README.md#known-limits).

## Reporting something new

Please do not open a public issue for a suspected vulnerability. The reporting
channel, what is most in scope, and the expected response time are in
[`SECURITY.md`](../SECURITY.md).

## How this record will work going forward

Findings raised **before** Kessa's first tagged release are documented here, since
no version carrying them was ever released, there is nothing in the field to
attack.

Findings raised **after** a public release are handled through GitHub's security
advisory workflow instead: reported privately, fixed, and published as an advisory
once a fixed version is available. [Published
advisories](#published-advisories) links each one rather than describing the
finding, so the public record stays complete without handing a map to anyone
still running an older version.

"Once a fixed version is available" means *released*, not merged. An advisory
names a version a reader can install, so it publishes after the release
completes rather than alongside it.
