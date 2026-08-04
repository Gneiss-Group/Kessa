# Security review record

This is the public index of Kessa's adversarial review rounds: what was reviewed,
when, which findings were raised, and where each one stands. It is deliberately a
**register, not a report** — it records that a finding existed and was closed,
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
rather than because they were designed in advance — most notably *validate before
the side effect*, which was escalated to a standing rule after recurring across
rounds.

## Rounds

| Round | When | Scope | Outcome |
|---|---|---|---|
| **R1** | before first publication | Core delegation, enforcement, audit chain, and verifier | Ten findings (F1–F10), highest severity High. All closed or accepted as documented boundaries before any code was published |
| **R2** | 2026-07-22 | Second adversarial pass over the same core, plus the export envelope and audit-sink path | Seven findings (R2-01–R2-07), one Critical. All closed before any code was published |
| **R3** | 2026-07-26 | Scoped P-256 employee key and algorithm-agile verification (`feat/scoped-p256-employee-key`, merged 2026-07-27) | No critical or high. No false-PASS path. Four findings, all closed |
| **R4** | 2026-08-01 | The whole on-device issuer surface: enrollment, Secure Enclave backend, signing daemon, agent wiring (`feat/issuer-enrollment`, merged 2026-08-01) | No critical or high. No false-PASS path in the verifier. Four findings plus two scope observations, all closed |
| *(spec alignment)* | 2026-08-03 | Not a review round — see below. Conformance work bringing the MCP listener to revision 2026-07-28 | Surfaced one security-relevant defect (SA-01) as a by-product |
| **R5** | 2026-08-03 | The ingress surface of both listeners, reviewed because it had just changed | Five findings (R5-01–R5-05), no critical or high. No false-ALLOW path |

**R1 and R2 predate this repository's first commit** (2026-07-23). Their fixes are
contained in the initial publication, so no released or published version of Kessa
ever carried them unfixed.

### Why the spec-alignment row is marked differently

SA-01 was **not found by looking for it.** It surfaced while reconciling the MCP
listener against a published specification — the defect was noticed because the
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

| ID | Area | Status |
|---|---|---|
Round 1 raised ten findings. F1–F4 were four instances of a single class — a
verdict-relevant field left outside the signed material — which became the
project's central coding rule. F5–F6 were low-severity hardening. F7–F10 were
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
| F7 | Info | Role of the VC wrapper in cross-org trust | Closed — documented as not load-bearing |
| F8 | Info | Clock trust for expiry caveats (no independent clock) | Accepted, documented boundary |
| F9 | Info | Surface of the opt-in `--fetch-dids` mode | Accepted, documented boundary |
| F10 | Info | Committed demo key material | Accepted, documented boundary |

### R2 — 2026-07-22

Seven findings, plus one item on `macaroon.Verify`. Two were further instances of
the round-1 class; the rest included one class the round-1 principle did not
cover. The round also recorded negative results — attacks attempted that did not
work — against the round-1 open items.

| ID | Sev | Area | Status |
|---|---|---|---|
| R2-01 | **Critical** | Coverage of credential and status references by the issuance signature | Closed |
| R2-02 | High | Export envelope completeness — entry count and log tip | Closed |
| R2-03 | High | Audit-sink dispatch behaviour under a slow or hung sink | Closed |
| R2-04 | Medium | Concurrency on the hash-chained audit log | Closed |
| R2-05 | Low | Disclosure of the verifier's trust root in its own output | Closed |
| R2-06 | Low | An overclaiming statement in the documented guarantees | Closed |
| R2-07 | Low | Policy rule and version handling in re-derivation | Closed |

### R3 — scoped P-256 employee key (2026-07-26)

| ID | Sev | Area | Status |
|---|---|---|---|
| R3-01 | Medium | Boundary validation at credential construction | Closed |
| R3-02 | Low-Med | JWK encoding of non-P-256 EC keys | Closed |
| R3-03 | Low | ECDSA signature malleability on the employee-key path | Closed (recorded judgment) |
| R3-04 | Low | End-to-end verifier coverage with a P-256 employee key | Closed |

### R4 — on-device issuer (2026-08-01)

| ID | Sev | Area | Status |
|---|---|---|---|
| R4-01 | Low | Per-connection deadline on the signing daemon | Closed |
| R4-02 | Medium | Hardware backing required for approval keys in the daemon | Closed; op-level policy deferred |
| R4-03 | Medium | Enrollment ordering — validation before any side effect | Closed; escalated to a standing rule |
| R4-04 | Low | Org root key passed on the command line | Closed |
| SO-1 | — | Org-DID preflight limited to local files | Closed |
| SO-2 | — | Enrolled Enclave key not loadable by the daemon | Closed |

### SA-01 — surfaced by spec alignment, not by review (2026-08-03)

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

### R5 — ingress surface (2026-08-03)

Scoped to ingress because that is what the spec-alignment work had just changed,
and anchored on SA-01's defect class: **a check that does not fire.** Two findings
are checks that fired only under some inputs; two are checks that were absent
altogether.

| ID | Sev | Area | Status |
|---|---|---|---|
| R5-01 | Medium | No `Origin` validation on either listener — a DNS-rebinding path to the chokepoint and to the audit export | Closed |
| R5-02 | Medium | Mirrored header validated only in its first occurrence, so a repeated, contradictory value went unread | Closed |
| R5-03 | Low | An explicit null JSON-RPC id processed as a request | Closed |
| R5-04 | Low | Required `clientCapabilities` checked for presence only, so a null satisfied it | Closed |
| R5-05 | Low | No request `Content-Type` validation, leaving cross-origin forgery defence incidental rather than deliberate | Closed |

**No false-ALLOW path in any of them.** A request still needs a verifiable
delegation chain and a valid proof of possession before it can become an ALLOW,
and none of that machinery was involved. What these findings allowed was
unauthenticated traffic reaching the enforcement path and the audit log at all,
and audit disclosure under rebinding — a different property from "cannot forge a
decision", and one this register should not let blur into it.

R5-01 and R5-05 also applied to the generic HTTP listener, which had not changed.
They were fixed there too: a defence applied to one of two doors is not a defence.

## Deferred, and why

These are recorded as open rather than closed. They are design decisions or
scale-dependent work, not unfixed defects:

- **S1 — status is checked against the current status list**, not the list as of
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
no version carrying them was ever released — there is nothing in the field to
attack.

Findings raised **after** a public release are handled through GitHub's security
advisory workflow instead: reported privately, fixed, and published as an advisory
once a fixed version is available. The register above will link to the advisory
rather than describe the finding, so the public record stays complete without
handing a map to anyone still running an older version.
