<!--
SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# On-device enrollment (`kessa-issuer enroll`)

Enrollment is how a real employee/device key *enters* the system. It generates
the key **on the employee's own machine**, in the secure element where possible,
and only the **public** half ever leaves. It then mints the `org → employee`
credential that positions that key in the delegation chain, and records the
device in a durable mapping so it can later be revoked.

This is the one place a hardware **P-256** key is minted. Every other principal
(org, proxy, status issuer) stays software **Ed25519**, simply because that is
what mints them — the verifier remains role-blind and algorithm-agile and is not
touched by enrollment. The chain shape enrollment builds toward is:

```
org (Ed25519, root)  ──issues──▶  employee (P-256, device key)  ──issues──▶  agent
```

`enroll` builds the first hop (the employee's own credential). The
`employee → agent` hop is a separate act — the employee issuing to an agent from
their own device, signing with the Touch-ID-gated Enclave key. The grant caveats
written onto the `org → employee` credential deliberately **do not** constrain
what kind of principal the employee may issue to next: a service/automation
identity is a valid next hop under the identical credential format.

## What one enrollment does

1. **Org-DID preflight.** Resolves the org's own published `did:web` document
   through the normal resolver before doing anything else. An employee credential
   whose issuer resolves to nothing is dead on arrival at the verifier, so this
   fails loudly rather than mint it. (It does **not** cover org-root enrollment or
   key rotation — those are separate, still-open root-of-trust questions.)
2. **Generate the device key.** Secure Enclave (P-256, non-extractable, Biometric
   use-gate) when available; a non-production software P-256 key with
   `--software-key` (CI, demos, dev machines that cannot code-sign). It never
   silently downgrades: if the Enclave is present but rejects the key for lack of
   an entitlement, enrollment fails with instructions rather than quietly minting
   a software key.
3. **Trust-on-first-use confirmation.** Displays the key fingerprint and, unless
   `--yes`, requires the operator to confirm it — the same ceremony `ssh` uses for
   a new host key. No secret crosses between two parties. This is the pluggable
   [enrollment backend](#enrollment-backends) seam; the default is `local-tofu`.
4. **Publish the device DID document** (public key only) into the publication root.
5. **Mint and sign** the `org → employee` credential and write it out (kept out of
   the public root, like any credential).
6. **Record the mapping** (written last, so it never references a credential that
   was not produced).

Steps 1 and 3 both run **before** anything is written or minted, so a failed
preflight or a declined fingerprint leaves no partial state.

## Example

```bash
kessa-issuer enroll \
  --identity   alice@acme.example \
  --did        did:web:localhost:employees:alice-laptop \
  --org-did    did:web:localhost:orgs:acme \
  --keystore   examples/issuer/keystore.json \
  --root-key-hex 00112233445566778899aabbccddeeff \
  --identifier acme-alice-laptop \
  --status-url https://localhost/orgs/acme/status.json \
  --status-index 9 \
  --root       public \
  --mapping    enrollment-map.json \
  --out        alice-laptop.credential.json \
  --caveat     'action.type:==:payment.transfer'
```

`--keystore` here is the **mock** key custody used by the POC tools: it holds the
org's *software Ed25519* signing key (the org key is not the one enrollment mints
in hardware). Real deployments broker the org key differently; the `enroll` logic
in `internal/enroll` takes an already-materialized signer, so it is unchanged by
how that key is custodied.

On a dev machine without a code-signing identity, add `--software-key` to mint a
non-production key; the command prints a clear warning, and the mapping records
`keyBackend: "software"` so this is never silently forgotten.

## The employee → credential mapping

The mapping (`--mapping`) is what makes revocation **targetable**. Revocation
enforcement (flip a status-list bit) was already built and adversarially tested;
what was missing was knowing *which* bit belongs to *which* device. The mapping is
that index, and it is a byproduct of enrollment, not separate bookkeeping.

It is WebAuthn-shaped: one durable employee **identity** owns N device
**credentials**, each with its own DID and its own status bit. A DID is unique
across the whole map, so:

- **Adding a device** (multi-device, or replacing a lost one) — enroll again with
  the same `--identity` and a **new** `--did`; it appends, no collision.
- **A duplicate `--did`** is refused as the real error it is.

### Device loss / replacement

Symmetric with initial enrollment, with no new mechanism:

1. `kessa-issuer enroll` the replacement device (same identity, new DID).
2. `kessa-issuer revoke --index <old device's statusIndex>` to retire the lost
   device's credential (the old `statusIndex` is in the mapping).

## Enrollment backends

Enrollment is a pluggable seam (`internal/enroll.Backend`). The default,
`local-tofu`, is self-administered trust-on-first-use — honest and sufficient
wherever there is no organizational gap between "admin" and "employee" (solo,
home lab, small team). A stronger backend that binds enrollment to a live
corporate IdP session (Okta/Azure AD) satisfies the same interface and drops in
without touching the orchestration; it is deliberately **not** built here, and
whether it ships open or paid is a separate, deferred decision. Rejected
alternatives (admin-issued bearer tokens, SSH-key derivation) are recorded in the
deployment doc, not offered.

## Real Secure Enclave persistence

When run from a **code-signed** binary with a `keychain-access-groups`
entitlement, `enroll` generates a **persistent** Enclave key under a keychain tag
(`--tag`, default derived from the DID) and records the tag + `keyBackend:
"secure-enclave"` in the mapping. The [signing daemon](daemon.md) then loads that
key by tag with `--mapping`, brokering it as an **approval-capable** key across
restarts — the generate-once / load-by-tag property that makes the device identity
durable. The daemon refuses to broker a software-enrolled key for that role, so
the human-approval control is only ever backed by hardware (R4-02). The
signing-identity setup and the signed persistence tests are covered in the
[Secure Enclave runbook](enclave-runbook.md); `enroll` on a signed binary is the
first flow that exercises persistence for real (as opposed to the unsigned
interop path).
