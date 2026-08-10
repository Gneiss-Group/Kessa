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

- **Policy hot-reload is an export-format change, not a loader feature.** A proxy
  loads one policy at startup, and every audit entry pins that policy's
  content-address, so one export carries exactly one policy and the verifier
  re-derives every allowed entry against it. Reloading a policy into a running
  proxy therefore produces a log spanning two policies, which the current export
  format cannot represent. Making it work means the export carrying multiple
  content-addressed policies and the verifier pinning per entry rather than per
  export: a format-and-verifier change on the Apache-tier side, which is the
  expensive kind, and it is where this has to be designed rather than worked
  around.

  What exists today is **not a head start.** `Proxy.recoverFrom` refuses to
  resume a durable log whose entries were written under a policy whose
  content-address differs from the one now loaded. That guard has the opposite
  polarity to a reload (it refuses a differing policy rather than admitting a
  newly authorized one) and it encodes the single-policy-per-export assumption a
  reload has to dismantle. It is that constraint surfacing, not progress against
  it, and it must not be extended into a reload mechanism.

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

- **Fuzzing: started, partial.** Native Go fuzz targets now exist for the parsers
  that read bytes chosen by someone else. No new dependency: `testing.F` is
  standard library, so the verifier's dependency closure is untouched, which was
  always the condition for doing this at all.

  Covered today, with the property each target asserts:

  | Target | Package | Property under test |
  |---|---|---|
  | `FuzzParse` | `internal/export` | Only `{v1, v2}` are accepted; a v1 envelope carries no v2 evidence; a carried policy is one `policy.Validate` also accepts; an accepted export survives its own serializer |
  | `FuzzMCPIngress` | `internal/enforce` | A JSON-RPC *result* is reachable only through the complete guard set (Origin, content type, `jsonrpc`, non-null id, both mirrored headers, `_meta` protocol version and client capabilities) |
  | `FuzzDocumentPath` | `internal/did` | A `did:web` identifier can never name a path outside the publication root |
  | `FuzzDIDWebToURL` | `internal/did` | The identifier determines the host fetched, with no smuggled userinfo, query, or fragment |
  | `FuzzPublishPath` | `internal/status` | A status-list URL from a credential can never name a path outside the publication root |
  | `FuzzNarrowsIsSound` | `internal/macaroon` | If `narrows` calls a caveat a subset, no context satisfies the child and not the parent, so an attenuation can never broaden authority |
  | `FuzzAttenuateAgreesWithExtends` | `internal/macaroon` | Anything `Attenuate` mints at delegation time, `Extends` accepts at verification time; `Attenuate` never mutates its input; a caveat dropped or rewritten breaks the HMAC chain |

  The targets assert properties rather than "does not panic", which was the part
  that made this worth doing: two of the eight found a real defect on their
  first bounded run, both fixed in the same branch. `FuzzDIDWebToURL` found
  `webhost.Validate` accepting bracketed literals that are not IPv6 addresses
  (`[0]`, `[ffff]`, `[1.2.3.4]`), a character-class check standing in for
  parsing the address. `FuzzParse` found that a policy RULE needed no reason,
  only the default block did, so a firing rule could write an ALLOW into a
  signed audit entry whose stated cause was the empty string. Both failing
  inputs stay in `testdata/fuzz/` as permanent regression seeds.

  A third arrived later and from an unexpected direction: the ten-second CI
  smoke run, which exists as a liveness check rather than for discovery, failed
  on an unrelated documentation branch. `FuzzDIDWebToURL` had found
  `webhost.Validate` accepting `+1` as a port, because `strconv.Atoi` tolerates a
  leading sign while `net/url` refuses `:+1` outright, so `did:web:0%3A+1`
  validated and then built a URL nothing could parse. Same shape as the bracket
  defect and the denylist before it: a check that describes a value rather than
  matching the grammar of the layer that consumes it. The fix is a digit rule
  plus a test asserting the shared invariant (anything `Validate` accepts,
  `net/url` can parse), so the next instance is caught as a class.

  Worth knowing operationally: because the smoke run explores randomly, it can
  surface a genuine `main` defect on a branch that did not cause it. A red gate
  on an unrelated PR is therefore not automatically flaky, and should be read
  before it is re-run.

  The macaroon package has no parser, so the untrusted input there is the caveat
  values rather than a byte stream, and the property worth searching is the
  narrowing lattice: inclusive against exclusive endpoints, sets, and a value
  grammar that is RFC3339-or-float. That is arithmetic a table of examples tests
  thinly.

  **Not yet covered:** credential JSON decoding (`internal/credential`) and the
  audit-log recovery path (`internal/enforce` WAL replay). Those are the next
  targets, not a decision to stop here.

  **Where it runs.** `make fuzz-smoke` (ten seconds per target, wired into CI) is
  a liveness check, not discovery: it keeps the targets compiling and their seed
  corpora loading on every PR. Real discovery is a bounded run at minutes per
  target, driven by hand today. An unbounded fuzz job still does not belong in
  the PR gate, and a scheduled workflow for longer campaigns remains the likely
  shape and is not built.

- **Named third-party security audit.** The adversarial review rounds were
  **self-run** AI red-team passes, not third-party; they are registered in the
  [security review record](docs/security-review.md). An independent, named audit
  has not been commissioned.
