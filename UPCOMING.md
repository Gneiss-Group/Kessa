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

- **`==`, `!=` and `in` are still spelled twice, though they now agree.** Policy
  conditions and macaroon caveats are written against one field vocabulary
  (`types.Action.Context()`), and the ORDERING operators get their meaning from
  one place (`internal/scalar`), so the enforcement proxy and the independent
  verifier cannot answer `<`, `<=`, `>` or `>=` differently. The other three
  never moved. They are two copies that agree, which is the condition that
  produced both defects found so far rather than a resting state.

  The `in` divergence that used to be recorded here is FIXED. `internal/policy`
  honoured a member that trimmed to nothing while `internal/macaroon.splitSet`
  dropped it, so a trailing comma (`"us,eu,"`, an ordinary typo rather than the
  exotic policy this note once claimed) put `""` in the set, and an action
  carrying `region=""` matched. Under allow-list posture, where a rule declares
  something ROUTINE, that match was the permissive outcome and skipped the
  approval gate. Policy now drops empty members, which is what macaroon always
  did, so nothing on the authority side changed. It cost no compatibility: every
  `in` value in the repository, including the one inside
  `testdata/audit_export_v2.golden.json` that a verifier re-derives, was checked
  and none contains an empty member, so the change is observationally a no-op on
  every existing policy and export.

  **What is left is the duplication itself, and it wants a decision rather than a
  patch.** Hoisting the three into one implementation, the way ordering went into
  `internal/scalar`, is the obvious move, but that package is named and documented
  for scalar ordering and equality/membership do not belong under that name
  without rescoping it or adding a second shared package, which would put the seam
  somewhere new rather than removing it. Worth an hour of design before any code.

  **Also open, and deliberately not taken: whether a trailing comma should be
  refused rather than tolerated.** Dropping the empty member silently accepts a
  policy whose author probably made a typo, which sits against the instinct that
  produced the mandatory `default` block, where an omitted posture is refused
  rather than inferred. Refusing it is the stricter reading and the RISKIER change,
  which is backwards from intuition and the reason it is parked: `Validate` is
  shared by `policy.Parse` and `export.Parse` precisely so the proxy and the
  verifier cannot disagree, so tightening it means an existing export carrying such
  a policy would stop PARSING altogether, failing wholesale instead of degrading
  one entry. Available later as a deliberate call once it is known that no deployed
  export carries one.

- **A conformance suite proves agreement, not correctness, and the `in` bug is the
  case that shows it.** `internal/policy/conformance` runs one contract against
  the hand-rolled classifier and the OPA backend, and it caught the infinity
  divergence because Rego's `to_number` independently refused what the classifier
  accepted. It did NOT catch the `in` bug, because that backend's `in` was written
  to mirror the classifier and mirrored it faithfully while it was wrong. Both
  agreed, and the suite stayed green throughout.

  This is not an argument against the suite, which has now paid for itself twice.
  It is a limit worth stating where it will be read: a differential catches a
  divergence, and a bug reproduced on purpose is not one. The corollary for any
  future backend is that translating the reference implementation's behaviour is
  exactly the way to build a second implementation that cannot find anything.

  **That limit was understated, and R7 is what showed it.** Catching the infinity
  divergence was not the end of the story. It was resolved by converging both
  backends onto the answer `to_number` gives, refusing an infinity, and freezing
  that as a conformance case. Refusing is correct where a rule declares something
  ROUTINE, and it is the PERMISSIVE outcome where a rule declares something
  CONSEQUENTIAL, because there a rule that does not fire is the one that lets an
  action through. So the convergence propagated a posture-specific assumption into
  both implementations, and the case then asserted it: the contract expected the
  defective outcome and named it "fails closed" while running the posture in which
  it was not. See [GHSA-vmr6-pgh2-c33x](https://github.com/Gneiss-Group/Kessa/security/advisories/GHSA-vmr6-pgh2-c33x).

  The stronger corollary, then. A differential does not only fail to find a bug
  the two implementations share: RESOLVING a real divergence can create one, if
  the answer both sides converge on is right for the posture in front of you and
  wrong for the other. What makes that recoverable is asserting the DECISION a
  policy reaches under a stated posture, rather than whether a rule matched, which
  is what the contract does now.

- **Nobody has attacked policy authorship, and R7 made it worth more.** Every
  round so far has attacked what an agent can submit against a policy taken as
  given. Who may write the policy a proxy loads, replace it between restarts, or
  supply the path it is read from, has not been examined, and `--config` naming a
  policy path put that question one file further from the operator's hands.

  R7-03's fix raised the stakes rather than lowering them. A policy rule that
  cannot be evaluated now DENIES, so policy is no longer only a classifier that
  says what needs a human: it can refuse outright. That is the right behaviour and
  it means whoever controls a policy file controls more than they did.

  What already holds: a policy is content-addressed, pinned per audit entry, and
  carried in the export, so the verifier re-derives every allowed entry against
  the policy that actually decided it and a substituted policy fails
  (`export.PolicyID`). That covers substitution AFTER the fact. It says nothing
  about who was entitled to author the policy in the first place, which is the
  open question and is a round of its own rather than a fix.

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

  **Deferred, deliberately, and not a v1 blocker.** The cost of a stranger's
  request is bounded rather than open-ended: `enforce.Handle` rejects an absent
  chain before doing any work, request bodies are capped at `maxRequestBody`
  (1 MB) and chains at `chain.MaxDepth` (8 hops), and nothing reaches policy
  evaluation until chain verification and then proof-of-possession have both
  passed. What is missing is not a bound on what a request costs, it is a check on
  *who* may spend that bounded cost repeatedly. That is a volume question, and it
  is the same shape as `GET /export` below, already named as an unauthenticated
  amplifier and already accepted rather than fixed. Treated the same way: named,
  bounded, accepted.

  This was nearly mis-sized. An initial reading of the container CMD defect (see
  `docker/proxy.Dockerfile`) framed it as a reopened security fix, which would have
  turned a bounded, already-precedented gap into an authentication design project.
  Tracing the actual code path is what corrected it. Sizing a finding off the first
  plausible-sounding story, rather than off the path and its real bounds, is the
  error to avoid repeating.

  **Revisit triggers**, any one of which reopens this: sustained abuse actually
  observed against a deployment; a design partner naming it a hard requirement; or
  the deployment shape changing such that the bound stops holding, in particular
  unbounded *connection* volume rather than unbounded per-request cost. Absent one
  of those, this is V2-or-paid-tier work, not v1 work.

  Candidates, all unstarted, preserved as design input for whenever a trigger
  fires: mTLS (matches the sidecar topology); a unix socket with a peer-uid check
  (matches the same-host case and reuses what the signing daemon already does); a
  session-scoped macaroon check at submission time (reuses the existing
  delegation-chain verification rather than a new trust mechanism, so it stays
  local to the receiving deployment by construction and needs no separate
  trust-domain decision, unlike mTLS or SPIFFE; the natural fit if the chain's
  own verification logic turns out to generalize to a pre-work admission check,
  not just a post-work possession check); SPIFFE/SPIRE (workload identity, fits
  the sidecar and multi-node shapes, and brings its own trust-domain question); a
  bearer token (weakest, easiest). The choice interacts with the MCP deployment
  model below, and with which of that model's shapes are same-host by
  construction (sidecar, in-process plugin) versus inherently network-spanning
  (in front of an existing gateway, standing in as the gateway itself); the
  socket-based candidate only answers the former.

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

- **Durability is off by default, which the fail-closed posture says it should not
  be.** `--audit-wal` defaults to `""`, so the shipped default configuration can
  return an allowed action and then lose the record of it in a crash. The
  log-before-act machinery to prevent that exists and works; it is simply not on
  unless an operator asks for it.

  This is a gap between a decision and its default, not an unbuilt feature. The
  proxy's failure posture is **uniform fail-closed**: any failure that prevents a
  sound, logged decision denies the action. Durable logging was named as one of
  the availability dependencies that posture rests on, and log-before-act ordering
  was named as the work it unblocked. That work shipped. The default did not
  follow it.

  **Two prerequisites before flipping it**, and neither is optional:

  - **A WAL benchmark, which does not exist.** The harness builds its proxy with
    no WAL (`perf/harness_test.go` passes no `WAL` to `enforce.Config`), so every
    throughput number in [`perf/README.md`](perf/README.md) describes a
    non-durable configuration. fsync-per-decision is usually a dominant cost
    rather than a marginal one, so flipping the default would change what those
    measurements describe without changing the measurements themselves. Benchmark
    first, and state any throughput figure against the configuration it was
    measured in.
  - **A decision about where the WAL lives.** `--audit-wal` takes a path, not a
    boolean, so defaulting durability on means the binary picks a filesystem
    location: writable, persistent across restarts, and sane inside a container
    whose working directory is `/`. That is a deployment question, not a constant.

  **It must flip on both paths at once.** Flags defaulting off while a config file
  requires an explicit answer is tolerable, because neither is claiming something
  untrue. Flags defaulting off while config defaults on would mean the two ways of
  starting the same binary disagree about whether the deployment is durable, which
  is worse than either default on its own.

  Surfaced 2026-08-11 while designing config-file support, where `audit_wal` is
  specified as a **required** field for this reason: requiring it forces the
  durability decision to be conscious without this question having to be answered
  first.

- **The audit log is unbounded in entry count.** [R6-04](docs/security-review.md#r6-2026-08-06)
  capped how many attacker-chosen bytes one entry may carry, which is a per-entry
  bound; it did nothing about how many entries there are. The in-memory log is
  never trimmed, the WAL is read whole into memory at startup, and neither has
  rotation or a ceiling, so sustained traffic still grows both without limit. A
  retention or rotation design has to answer what it means to drop entries from a
  log whose envelope signature commits to its length and tip, which is why it is a
  design question and not a size constant.

- **Enforcement-point key custody: decided and built, with a named residual.**
  `kessa-proxy serve` now takes either `--keystore` (the mock keystore, seeds in
  the clear, evaluation only) or `--signer-sock`, which brokers the enforcement
  point's key through `kessa-issuer daemon` so the private key never enters the
  proxy's process. Exactly one, never both and never neither: defaulting either
  way would pick a custody model on the operator's behalf. The daemon classifies
  such a key under a third `signerd.KeyPolicy`, `Attestation`, because it is
  neither a proof-of-possession key nor a human approval key (see
  [`docs/signer.md`](docs/signer.md)).

  What is **not** closed by that:

  - The brokered key is still software. `Attestation` permits software
    deliberately, since Approval's hardware rule exists to force a per-use human
    gesture and no human is present on an unattended server. A
    *non-extractability* requirement is a different and weaker claim, unaddressed,
    and `Attestation` is where it would land if it is ever wanted. On Linux it
    would also need the TPM backend above.
  - The peer-uid gate means the proxy must run as the daemon's owner uid and share
    the socket's filesystem. For containers that is one uid and a shared volume,
    not two service accounts. This is a real constraint on any deployment tooling,
    including the Terraform module.
  - Batch mode (`kessa-proxy run`) stays on the mock keystore by design: it needs
    it anyway to mint each fixture's PoP and approval, so brokering only the
    enforcement point's key would leave the other two as seeds in a file.

- **Config files cover the long-lived commands only.** `kessa-proxy serve` and
  `kessa-issuer daemon` take `--config` ([configuration](docs/configuration.md));
  the one-shot subcommands (`proxy run`, `issuer publish`, `revoke`, `enroll`,
  `issuer serve`) deliberately do not. They are invoked by a human or a script
  with arguments that differ every time, so a config file buys them little.

  The revisit trigger is specific: **if deployment tooling ends up running
  `issuer publish`**, that command wants a config too, since the whole point of
  the file is that tooling renders it rather than assembling a command line. That
  is an open question in the Terraform work, not here.

  `cmd/verify` is excluded on stronger grounds and should stay excluded. Its
  posture is that you point it at files and it reads nothing else; a config file
  is another input to a tool whose selling point is having almost none.

  Config **reload** is also out, and not merely unbuilt: it should not arrive as a
  cheaper-looking version of the policy hot-reload problem above, which is an
  export-format change rather than a loader feature.

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

- **A version is written two ways, and one of them cannot change.** The git tag
  is `v0.1.0`; the version constant, `--version` output and the container image
  tag are all bare `0.1.0`. The `v` is added in exactly one place,
  [`release.yml`](.github/workflows/release.yml) (`tag=v$next`), and stated in the
  [`Makefile`](Makefile)'s versioning comment as "the git tag is v plus it".

  **This is not a naming inconsistency to tidy away.** This repository is a public
  Go module, and Go's module system requires version tags to be `vX.Y.Z`:
  `go get github.com/Gneiss-Group/Kessa@v0.1.0` resolves through that tag.
  Dropping the prefix would make the module unfetchable at a version. Container
  registries take the opposite convention, and `notes.sh` substitutes the bare
  version into the documented `docker pull` line accordingly. Both sides are
  right; they simply disagree, and neither is free to move.

  **What it costs, which is the reason this is written down at all.** Reaching for
  the git-tag form against the registry returns **404**, and 404 is also what GHCR
  returns for a package you may not see. So the wrong spelling is indistinguishable
  from a permissions problem, and it routes diagnosis toward "did the package go
  private" rather than "did I type the tag right". That happened on 2026-08-14
  while resolving the v0.1.0 proxy digest, and it briefly looked like a visibility
  regression.

  **Options, none of them obviously correct.** Publish both `0.1.0` and `v0.1.0`
  image tags so either spelling works, at the cost of doubling the tag list and
  implying a distinction that does not exist. Or leave one spelling and make the
  documentation carry the whole load, which is the current state and is what just
  failed. Or say it once, loudly, where someone is about to type a tag: the
  release body and `docker/README.md`, rather than only in a comment next to the
  code that adds the prefix. The last is the cheapest and is the recommendation;
  it is not done.
