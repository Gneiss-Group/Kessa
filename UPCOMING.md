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
  into the algorithm-agile signing seam — a TPM does ECDSA P-256, so no verifier
  change is needed, exactly as the Enclave slotted in. The cost is real rather than
  incremental: the Go standard library has no TPM support, so it means either cgo
  against `libtss2` (a system build dependency, plus the heavier TPM 2.0 object
  model — hierarchies, sessions, create/load/sign) or the external `go-tpm`
  library (which would breach the no-external-Go-dependencies discipline). Choosing
  between those, and a `swtpm`-simulator test story, is the design decision this
  needs; unstarted. Worth building on a real trigger (a deployment needing
  hardware-backed keys on Linux *endpoints* — note a containerized daemon has no
  clean TPM access, so this is a host concern), not speculatively.

- **macOS app-bundle packaging for the signing daemon.** Persisting a Secure
  Enclave key needs the `keychain-access-groups` entitlement, which macOS treats
  as *restricted*: it must be authorized by an embedded provisioning profile, so
  the daemon has to ship as a signed, profile-bearing **app bundle**, not a bare
  binary. The Enclave mechanism itself is hardware-validated; this is the packaging
  that lets the compiled Go daemon (rather than an equivalent harness) run under a
  profile. It is **open-tier and macOS-specific** — a solo developer building from
  source hits the same wall, so it is not fleet/paid tooling, and Linux has no
  equivalent. Distinct from production Developer ID signing + notarization for
  fleet distribution, which is the separate scale-dependent piece.

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
  **self-run** AI red-team passes, not third-party; their working notes are not
  published, and a consolidated write-up is being prepared. An independent, named
  audit has not been commissioned.
