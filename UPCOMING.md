<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Upcoming: Open Questions and Known Gaps

This is a working list of open design questions and known gaps, **not a
committed timeline**. Nothing here is promised, dated, or in progress unless it
says so. The list is deliberately unordered: these are pulled from design notes
as they were identified, and ranking them is a separate exercise.

For what the system does today, and for the limits of a clean verdict, the
[`README`](README.md) and the code are the source of truth.

## Architecture and design

- **Directory inheritance for org structure.** How Kessa should consume an
  existing org directory (Workday, Active Directory, Okta) so that delegation
  chains inherit real reporting structure instead of being hand-built. Currently
  the biggest open architecture question after the MCP deployment model.

- **MCP deployment model.** Now understood as two separable questions rather
  than one. For self-hosted and custom-harness topologies this is solvable, and
  three candidate architectures are sketched. For closed-platform agents (Cursor,
  hosted runners) it is a structural boundary rather than a solvable gap: if the
  platform will not route tool calls through a chokepoint you control, Kessa
  cannot observe them.

- **Policy language decision: Cedar vs. Rego.** The current classifier is a
  hand-rolled, standard-library rule evaluator behind an `Evaluator` interface.
  Whether to adopt Cedar or Rego, and at what cost to the verifier's dependency
  closure, is undecided. Both spikes are unstarted.

- **Joint or dual authorization.** Consequential actions today require exactly
  one human approver, by design and for now. Requiring two, or requiring a
  specific pair, is not modeled.

- **DID to org-directory resolution.** Turning a DID into a human-facing name
  and org position, so that an audit export reads like an org chart rather than
  a list of identifiers. A candidate paid feature.

- **Linux TPM `Signer` backend.** The macOS Secure Enclave backend has no Linux
  counterpart yet. A TPM 2.0-backed, non-extractable P-256 key would drop straight
  into the algorithm-agile signing seam: a TPM does ECDSA P-256, so no verifier
  change is needed, exactly as the Enclave slotted in. The cost is real rather than
  incremental: the Go standard library has no TPM support, so it means either cgo
  against `libtss2` (a system build dependency, plus the heavier TPM 2.0 object
  model: hierarchies, sessions, create/load/sign) or the external `go-tpm`
  library (which would breach the no-external-Go-dependencies discipline). Choosing
  between those, and a `swtpm`-simulator test story, is the design decision this
  needs; unstarted. Worth building on a real trigger (a deployment needing
  hardware-backed keys on Linux *endpoints*: note a containerized daemon has no
  clean TPM access, so this is a host concern), not speculatively.

- **macOS app-bundle packaging for the signing daemon.** Persisting a Secure
  Enclave key needs the `keychain-access-groups` entitlement, which macOS treats
  as *restricted*: it must be authorized by an embedded provisioning profile, so
  the daemon has to ship as a signed, profile-bearing **app bundle**, not a bare
  binary. The Enclave mechanism itself is hardware-validated; this is the packaging
  that lets the compiled Go daemon (rather than an equivalent harness) run under a
  profile. It is **open-tier and macOS-specific**: a solo developer building from
  source hits the same wall, so it is not fleet/paid tooling, and Linux has no
  equivalent. Distinct from production Developer ID signing + notarization for
  fleet distribution, which is the separate scale-dependent piece.

- **Caller authentication on the enforcement endpoint.** No longer the thing
  standing between an export and someone else's audit log: R5-06 closed that by
  making possession an attribution gate, so an unattributable request causes no
  write. What remains is the separate question of **who may submit at all**.
  Anyone who can reach a listener may send it requests. They cannot make it record
  anything (that needs a proof of possession), but unauthenticated submission is
  still work the chokepoint performs for strangers, and a deployment that wants a
  closed perimeter has no way to ask for one. `--allow-unauthenticated-remote` is a
  fail-closed default, not an answer.

  Candidates, all unstarted: mTLS (matches the sidecar topology); a unix socket
  with a peer-uid check (matches the same-host case and reuses what the signing
  daemon already does); a bearer token (weakest, easiest). The choice interacts
  with the MCP deployment model below.

  **It is also coupled to the still-open root-of-trust layer**: org-root
  enrollment and key rotation, which [`enrollment`](docs/enrollment.md) names as
  separate open questions and which the device-enrollment ceremony deliberately
  does not cover. The coupling is a constraint, not a sequencing note. Kessa's
  reach today is bounded by an asymmetry: a proxy resolves DIDs only from its own
  local `--dids` directory and has no network resolution, so authority artifacts
  are usable only against a deployment whose trust root already resolves every
  hop of them. **Trust is granted locally by the receiving side, never asserted
  by the presenting side**, which is what confines the R5-06 blast radius to the
  deployment that issued an export plus any proxy deliberately configured to
  trust that org.

  A caller-authentication mechanism provisioned any other way would erode that.
  A credential minted by a central authority, or an mTLS trust store rooted in a
  CA spanning organizations, moves the admission decision off the receiving
  deployment and hands a presenter reach it does not have today. So the
  requirement is that whatever authenticates callers be provisioned the same way
  `--dids` is: locally, per deployment, by the side accepting the risk. The unix
  socket satisfies this by construction (the kernel is the authority, and it is
  per-host); mTLS satisfies it only if each deployment runs its own CA. Settle
  the org-root question first, or settle both together, but do not pick a caller
  authentication scheme that quietly assumes an answer to it.

- **`GET /export` is an unauthenticated amplifier that holds the enforcement
  lock** ([R6-03](docs/security-review.md#r6-2026-08-06), deferred rather than
  closed). Every call takes `Proxy.mu`, rebuilds the whole envelope, re-signs it,
  and serializes the entire audit history: measured at 5.7 ms and 704 KB per
  request against a 500-entry log, both growing linearly with the log. Because the
  work happens under the same lock `/enforce` needs, a client looping on `/export`
  slows enforcement for everyone (3.3x at 500 entries, and the ratio grows with
  the log).

  Deferred, not dismissed, and the reason is that it is the only R6 finding the
  loopback default genuinely mitigates: it costs an attacker nothing but it needs
  network reach, whereas the timeout and evidence-size fixes closed things that
  were reachable the moment anyone followed the container instructions. The fix is
  also real work rather than a constant: cache the built export keyed on the log
  tip (it only changes on append), snapshot entries under the lock and marshal
  outside it, and decide whether the endpoint should paginate. Related: the
  listeners still have no connection-count cap, which is the same shape as
  [R4-01](docs/security-review.md#r4-on-device-issuer-2026-08-01) on the daemon
  socket.

  Note also that `/export` is an unauthenticated **read** of the whole signed
  audit history. R5-01 closed the DNS-rebinding route to it; it did not make the
  endpoint require anything, and the `Origin` guard is browser-scoped by
  construction. That half belongs with caller authentication above.

- **The audit log is unbounded in entry count.** [R6-04](docs/security-review.md#r6-2026-08-06)
  capped how many attacker-chosen bytes one entry may carry, which is a per-entry
  bound; it did nothing about how many entries there are. The in-memory log is
  never trimmed, the WAL is read whole into memory at startup, and neither has
  rotation or a ceiling, so sustained traffic still grows both without limit. A
  retention or rotation design has to answer what it means to drop entries from a
  log whose envelope signature commits to its length and tip, which is why it is a
  design question and not a size constant.

## Coverage and evidence

- **Tool-call payload coverage.** Kessa authorizes today: it records that an
  action was permitted, not what data moved. A hash-commitment design would let
  an export bind the payload without carrying it. Designed, not built.

- **Signed status-list snapshot embedded in exports.** A residual limitation
  from the S1 work: verification currently reads status lists as separate
  inputs, so an export is not fully self-contained across a revocation boundary.

- **Unrevocable hops.** A delegation hop with no published status list cannot be
  revoked. Today the verifier states this as a per-entry limitation on the
  record, a label rather than a constraint. Whether such a hop should be allowed
  to carry a consequential ALLOW at all is an open product decision.

## Content and assurance

- **Curated policy packs.** The policy loader is pack-ready, but the packs
  themselves are deferred: their content should come from design partners rather
  than from guessing what a vertical considers consequential.

- **Named third-party security audit.** The adversarial review rounds were
  **self-run** AI red-team passes, not third-party; they are registered in the
  [security review record](docs/security-review.md). An independent, named audit
  has not been commissioned.
