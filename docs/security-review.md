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
| **R1** | before first publication | Core delegation, enforcement, audit chain, and verifier | All findings closed before any code was published |
| **R2** | before first publication | Second adversarial pass over the same core, plus the export envelope and audit-sink path | All findings closed before any code was published |
| **R3** | 2026-07-26 | Scoped P-256 employee key and algorithm-agile verification (`feat/scoped-p256-employee-key`, merged 2026-07-27) | No critical or high. No false-PASS path. Four findings, all closed |
| **R4** | 2026-08-01 | The whole on-device issuer surface: enrollment, Secure Enclave backend, signing daemon, agent wiring (`feat/issuer-enrollment`, merged 2026-08-01) | No critical or high. No false-PASS path in the verifier. Four findings plus two scope observations, all closed |

**R1 and R2 predate this repository's first commit** (2026-07-23). Their fixes are
contained in the initial publication, so no released or published version of Kessa
ever carried them unfixed. Their round-by-round working notes are not published;
the entries below reconstruct scope from the finding references that remain in the
code and documentation.

## Findings index

Severity is recorded where the round recorded one. Identifiers appear throughout
the source as `(R2-01)`-style references, so any comment or test naming a finding
resolves here.

### R1

| ID | Area | Status |
|---|---|---|
| F1 | Verifier re-derivation of consequentiality from the carried policy | Closed |
| F2 | Verifier output and exit-code semantics, including integrity-only downgrades | Closed |
| F3 | Proof-of-possession binding to a specific action | Closed |
| F4 | Binding of possession and approval to an entry's position in the log | Closed |
| F5 | Publication and DID path handling | Closed |
| F6 | Inbound request size limits on the enforcement endpoint | Closed |
| F7 | Scope of the VC wrapper in the cross-org trust path | Closed (documented boundary) |

### R2

| ID | Area | Status |
|---|---|---|
| R2-01 | Coverage of credential and status references by the issuance signature | Closed |
| R2-02 | Export envelope completeness — entry count and log tip | Closed |
| R2-03 | Audit-sink dispatch behaviour under a slow or hung sink | Closed |
| R2-04 | Concurrency on the hash-chained audit log | Closed |
| R2-05 | Disclosure of the verifier's trust root in its own output | Closed |
| R2-06 | An overclaiming statement in the documented guarantees | Closed |
| R2-07 | Policy rule and version handling in re-derivation | Closed |

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
