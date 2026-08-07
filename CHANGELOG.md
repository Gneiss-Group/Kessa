<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

Kessa follows [semantic versioning](https://semver.org). Releases are cut by
hand from `main` (see [`docs/branching.md`](docs/branching.md)); the sections
below are generated from the commit history by the release workflow, so this
file records what was released rather than what someone remembered to write
down.

Kessa is pre-1.0: the interfaces are not yet declared stable, so a breaking
change bumps the **minor** version and is called out under **Breaking changes**
in the release it lands in. That section, not the version number, is the signal
to read before upgrading.

## Export format history

The audit export is the artifact with a compatibility promise attached, so its
shape is recorded here rather than only in the code. This section is the record
[`scripts/release/fixture-guard.sh`](scripts/release/fixture-guard.sh) requires
an entry in whenever a frozen golden moves, since regenerating a golden means the
format changed. It sits above the release sections because it is not tied to any
one release, and it predates all of them.

**Nothing has been released yet**, so there are no release sections below. The
format history exists anyway: `v2` is what the verifier reads today, and a reader
should be able to learn why there is a `v1` without going to the source.

| Version | Status | What it is |
|---|---|---|
| `kessa-audit-export/v1` | superseded, still readable | Integrity-only. Carries entries and their hash chain, no evidence. The verifier reads it and returns **DOWNGRADED** with a non-zero exit: never a clean pass, because there is nothing to re-derive a verdict from. |
| `kessa-audit-export/v2` | **current** | Self-contained evidence envelope: entries plus the deduplicated, content-addressed credential set (each credential with its issuer proof) and the signed policy the verifier re-runs. One file, no companion artifacts. |

There is no `v3`, and no second shape of `v2` was ever published.

**Round 2 of the security review changed what several signing inputs cover**, and
those changes are format-affecting: the issuance signature now covers the whole
credential rather than an enumerated field list (R2-01); the envelope signature
now covers the entry count and log tip (R2-02); the entry payload carries a
status-checked hop count rather than a boolean assertion. They were finalized
**pre-release**, so the evidence format settles at `v2` with those contents
rather than minting a `v3` for a `v2` nobody ever received.

The trade that makes acceptable, stated rather than left implicit: an export from
an intermediate pre-round-2 build would carry the same `v2` label with different
signed contents, so it fails at hash and signature re-derivation rather than at a
clean version refusal. That is only acceptable because no such export exists
outside regenerable goldens. Once a version ships, this option is gone and a
format change means a new version string.

**Round 6 added one field to signed material** (R6-01): a credential's status
reference now carries an optional `issuer`, naming the principal entitled to
publish revocations for that credential. It is covered by the whole-credential
issuance signature, so a holder can neither add it nor repoint it. Omitted means
the credential's own issuer, which is the strictest reading, so a credential that
says nothing accepts revocations from exactly one key rather than from any key.

Because it is omitted whenever it would restate the issuer, **the frozen goldens
did not move**: `make fixtures` is still a no-op in git, and this entry is
recorded because the format changed rather than because the guard demanded it.

It is nonetheless a **retroactive tightening**, stated plainly for the same reason
the round-2 trade is. An export minted before this change, whose chain routed a
hop through an issuer other than its own (one organization publishing one list for
its whole delegation subtree, which the shipped issuer spec does), now fails
verification: the credential names no authority, so the default applies and the
list's signer no longer matches. Re-mint such a chain with the field set. This is
acceptable only because nothing has been released; once a version ships, a change
of this kind means a new version string rather than a quiet tightening.

The authoritative statement of the current format is
[`internal/export`](internal/export/export.go); the findings behind the round-2
changes are in the [security review record](docs/security-review.md).

<!-- releases below; newest first -->

## v0.0.1: 2026-08-07

_First tagged release._

### Breaking changes

- make possession an attribution gate, closing R5-06
- bring the MCP listener to revision 2026-07-28
- algorithm-agile verification + scoped P-256 employee key
- serve dual, independently configurable listeners
- Signer.Public() and did.ResolveKey now return crypto.PublicKey;
- the proxy serve --addr flag is renamed to --http-addr. Update any deployment that passed --addr (the Docker CMD and repo scripts are updated in this change).

### Features

- publish the CLA and wire up the signing flow
- grant the Section 7 additional permission
- designate plug points by in-code marker, not by list
- bring the MCP listener to revision 2026-07-28
- issuer image + containerized end-to-end demo
- enforce hardware-backed approval keys + load enrolled keys (R4-02, SO-2)
- B4 on-device enrollment + employee->credential mapping
- on-device signing daemon + agent socket wiring
- macOS Secure Enclave backend for the employee/device key
- algorithm-agile verification + scoped P-256 employee key
- durable log-before-act audit WAL
- serve dual, independently configurable listeners
- add MCP-native listener adapter

### Fixes

- check house style AFTER generating the changelog, before pushing (#37)
- apply house style to text lifted from commit messages (#36)
- write signatures to their own branch, and open the project
- keep the guardrail test's fixture headers out of its own licensing
- correct what the demo and its GIF actually show
- run DID-uniqueness gate before side effects (R4-03)

### Security

- bind a revocation list to the party entitled to revoke (R6-01)
- bound caller-supplied evidence before it reaches the log (R6-04)
- give every listener read, write and idle timeouts (R6-02)
- restore R2-04 concurrency coverage; qualify the R5-06 closure
- make possession an attribution gate, closing R5-06
- name R5-06, an export is a bearer artifact (High, open)
- close the ingress checks that do not fire (R5-01..R5-05)

### Documentation

- trim the R6 entries to register depth
- state that a status list must come from the credential's named authority
- record the export amplifier and the unbounded log as deferred (R6-03)
- the expiry timestamp is caller-supplied, not proxy-chosen (R6-05)
- invite the commercial licence conversation rather than advertise a product
- publish the corporate terms, not a form nobody can sign
- state every departure from the Apache agreements, and make the corporate one executable
- drop "complete", scope "what matters", link the finding IDs, reorder
- drop a method claim that implied the other checks were weaker
- surface the standards mapping as a summary table
- lead with what Kessa does, and add the row that was missing
- read the AI Act articles, and drop Article 15 as an overclaim
- verify DORA Article 9 against the Official Journal text
- verify NIST 800-207 against the publication, and date every claim
- licensing statement, standards mapping, navigation, and a next step
- stop publishing the substance of legal advice in comments
- adopt counsel's wording for the permission notice
- drop the briefing cross-reference from the notice-check comments
- say where a file's licence actually lives, and stop calling internal seams pluggable
- record the export format history, and the caller-auth/root-of-trust coupling
- state the AI-assisted development posture
- coverage checks exclude explicitly, and mutation-check concurrency tests
- move the house style into go-standards, out of the front page
- state R5-06 in distribution-model terms, and bound its reach
- state the audit-write property separately from "no false-ALLOW"
- register SA-01 and R5, and mark how each was found
- drop citations to the private design note, keep the reasoning
- prune interim comments that outlived what they pointed at
- publish severity ratings for rounds 1 and 2
- ground the review register in the retained working notes
- add the security review record and fix the reporting-channel gap
- stop stating a fixed count of security review rounds
- separate the plugin interface grant from the combination question
- fix stale review-doc pointers, surface the signing docs, state prerequisites
- reclassify the macOS app-bundle packaging residual as §2a (open), not §2b
- persistence mechanism validated on hardware (free team)
- correct the persistence-signing requirement (empirical)
- add signer.md, code-grounded Signer seam behavior reference

### Other changes

- scope the release token, document the CLA scopes, and fix a release guard that could never pass (#35)
- exempt the copyright holder from signing his own CLA (#34)
- grant CodeQL and Scorecard the token scopes they actually query (#30)
- drop the transitional tier lists from the licence check
- check REUSE conformance in Go, and stop REUSE.toml contradicting a header
- drop the same entry from .dockerignore
- drop the ignore entry for a file that no longer lives here
- name the dash characters by code point in CLAUDE.md
- remove every em dash, and enforce it so it cannot come back
- Bump the github-actions group with 4 updates
- rename audit.Record to audit.EntryDraft
- cover docker/demo/ in the licence annotations
- server idle deadline, root key from file, remote org-DID preflight
- Initial commit to Github

### Verifying what you downloaded

Each archive is listed in `SHA256SUMS`, every binary answers `--version`
without running anything, and every artifact carries signed build provenance
binding it to this repository's release pipeline:

```sh
sha256sum -c SHA256SUMS
gh attest verify kessa_*_linux_amd64.tar.gz --repo Gneiss-Group/Kessa
./kessa --version
```

The verifier bundle (`kessa_*`) is Apache-2.0; the server bundle
(`kessa-server_*`) is AGPL-3.0-only. See `LICENSING.md`.

### Container images

Multi-arch (linux/amd64 + arm64), distroless, signed with build provenance:

```sh
docker pull ghcr.io/gneiss-group/kessa:VERSION          # verifier (Apache-2.0)
docker pull ghcr.io/gneiss-group/kessa-proxy:VERSION    # enforcement proxy (AGPL-3.0-only)
gh attest verify oci://ghcr.io/gneiss-group/kessa:VERSION --repo Gneiss-Group/Kessa
```
