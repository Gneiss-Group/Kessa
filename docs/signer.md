<!--
SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
SPDX-License-Identifier: Apache-2.0
-->

# The `Signer` seam — behavior reference

A code-grounded reference for developers, auditors, and future contributors: how
`Signer` and its backends actually behave. Not *why* they were designed this way
(that's the MCP deployment design decision log) and not the enrollment ceremony
narrative (that's [`enrollment.md`](enrollment.md)). If you hold a `Signer`, are
implementing one, or are auditing what got signed, this is what you need to know.

Grounded in the code as it exists today (B1–B4, including the R4-02/SO-2 fixes).
Where this doc and the code ever disagree, the code wins.

## 1. The interface

```go
// internal/signer/signer.go
type Signer interface {
	Sign(data []byte) (sig []byte, err error)
	Public() crypto.PublicKey
	DID() types.DID
}
```

That is the whole seam. A caller that needs a signature goes through it and never
touches a private key.

**Algorithm-agile.** Two algorithms are supported, and a caller does not choose or
even need to know which one it holds:

- **Ed25519** — signs the message directly (no pre-hash).
- **ECDSA / NIST P-256** — signs `SHA-256(message)` and emits an **ASN.1 DER**
  signature.

Verification is a single free function that recovers the algorithm from the key's
concrete type, so algorithm agility lives in exactly one place:

```go
func Verify(pub crypto.PublicKey, data, sig []byte) bool   // dispatches on pub's type
func KeysEqual(a, b crypto.PublicKey) bool                 // false on any cross-type mismatch
```

You determine which algorithm you're holding from the concrete type of `Public()`
(`ed25519.PublicKey` vs `*ecdsa.PublicKey`), or, off the wire, from the DID
document's JWK (`kty`/`crv`: `OKP`/`Ed25519` or `EC`/`P-256`). An unknown key type,
or a P-256 key on any other curve, makes `Verify` return `false` — never panic, never
skip: a key we cannot verify is a failed verification.

**The interface carries no notion of role.** There is no "employee", "org",
"agent", or "approver" anywhere in `Signer` — and, more importantly, none in the
verification path either. The verifier is **role-blind**: it accepts Ed25519 or
P-256 for *any* DID key, dispatched purely on key type, with no per-role logic. The
statement "the employee key is the hardware P-256 key" is a property of what
*enrollment generates*, not a rule the verifier enforces. If you extend this system,
do not add role-awareness to verification — it would break the "empty trusted
bucket" property the whole security argument rests on. (This is the property most
often misunderstood by someone extending the system; rationale is in the design
decision log.)

## 2. Backends

Every backend below satisfies the one `Signer` interface above; nothing upstream of
the seam changes when you swap one for another.

### Software Ed25519 — `signer.SoftwareSigner`
`NewSoftwareSigner(did)` (random) / `NewSoftwareSignerFromSeed(did, seed)`
(deterministic, for fixtures/demos). The private key lives **in process memory**
while signing. This is what mints every non-device principal: **org, proxy, and
status-issuer keys**, plus the POC/demo mock keystore.

### Software P-256 — `signer.ECDSASigner`
`NewECDSASigner(did)` / `NewECDSASignerFromSeed(did, seed)` (deterministic *key*,
not deterministic signatures — see below). Exists so the whole P-256 path is
exercisable without hardware. It is also what `kessa-issuer enroll --software-key`
mints for a device key.

> **Not hardware backing.** A software signer's private key exists in plaintext in
> process memory during signing and can, in principle, be read by anything with
> access to that process. This is a *different and weaker* guarantee than the Secure
> Enclave, where the key never exists outside the hardware. `--software-key` is a
> non-production convenience (CI, demos, dev machines that can't code-sign); a key
> minted this way must never carry the "non-extractable" claim, and the mapping
> records `keyBackend: "software"` so it is never mistaken for one.

P-256 signatures are **not deterministic**: `crypto/ecdsa` draws a fresh nonce per
signature. Fixtures therefore *verify* a P-256 signature rather than byte-comparing
it — a real hardware key is non-deterministic for the same reason.

### Secure Enclave (macOS) — `enclave.Signer`
Built only under `darwin && cgo`; every other build gets a stub whose constructors
return `ErrUnsupported`, so Linux and the verifier stay pure-Go. `Available()`
reports which build you have.

- **Non-extractable** means exactly this: the private key is generated *inside* the
  Secure Enclave and never leaves it. `Sign` proxies to the Enclave, which performs
  `SHA-256 + ECDSA-P256` and returns an ASN.1 DER signature — the same shape
  `signer.Verify` already checks, so nothing above the seam changes. `Public()`
  exports only the public point.
- **P-256 only**, and this is a *hardware limitation, not a choice*: the Secure
  Enclave cannot generate an Ed25519 key at all. A key generated in the Enclave at
  enrollment is P-256, full stop.
- Constructors: `Generate` (persistent, by keychain tag), `GenerateEphemeral` (no
  keychain, no entitlement needed), `Load` (by tag), `Delete` (by tag). Persisting a
  key needs a `keychain-access-groups` entitlement, which on macOS is *restricted*:
  it must be authorized by an embedded **provisioning profile**, so the binary has to
  be a signed, profile-bearing **app bundle** — a hand-`codesign`'d bare binary is
  killed at launch (AMFI, `-413`), and an unsigned one gets `ErrMissingEntitlement`.
  See [`enclave-runbook.md`](enclave-runbook.md).

### TPM (Linux)
**Not built.** A TPM-backed P-256 signer is the natural Linux counterpart to the
Enclave and is named in the design (§2a) as intended core work, but no
implementation exists in the tree today. Do not assume Linux hardware backing.

### Windows
**Not built**, and its status is deliberately open — treated as a raw
engineering-cost question (Windows platform crypto is materially more work), tracked
separately (§2b), not silently omitted and not a "lesser security tier" decision.

### Daemon client — `signerd.Signer`
`signerd.Dial(sock, did)` returns a `Signer` whose `Sign` round-trips to a local
daemon over a Unix socket; the **private key never reaches the client process**.
This is how `cmd/agent --agent-sock` gets its key. It is a drop-in `Signer`, so it
flows through the exact same PoP path any other signer does.

## 3. Access control model

Access control is a per-**key** property set at generation by the key's role, and it
is separate from non-extractability (which is unconditional for an Enclave key).

- **`DeviceUnlock`** — key use is gated only on the device being unlocked, with **no
  per-signature prompt**. This is the routine **proof-of-possession** policy: an
  agent's daemon-resident PoP key signs as the agent works, and a Touch ID tap per
  action would break the background-resident (ssh-agent-shaped) model.
- **`Biometric`** — every signature additionally requires a **fresh biometric
  match**. This is the **approval / issuance** policy: the human key's deliberate,
  infrequent acts, matching the passkey "approve" convention. `kessa-issuer enroll`
  mints the device key under this policy.

### The `hardwareGated` enforcement (this is real, not a convention)
`signerd.NewKeys` **refuses to broker an approval-capable key that is not
hardware-backed.** A key registered with `Policy: Approval` must satisfy the
`hardwareGated` marker interface (`Hardware() bool`), which `enclave.Signer`
implements and software signers do not. A software approval key is rejected at
construction. Concretely, `kessa-issuer daemon --mapping` loads enrolled Enclave
keys as `Approval` and **refuses to start** if a mapping entry is software-backed;
`--keystore` keys are always `Routine`. This is code-enforced (R4-02), so the
integrity of "a human deliberately approved this" cannot silently degrade to an
unenforced convention just because a software key was handed in.

### What is NOT yet enforced
There is **no op-level distinction between a PoP sign and an approval sign**. The
daemon signs whatever bytes an authorized client sends; it cannot tell, at the
operation level, that a given `Sign` is producing an approval versus a PoP. The
current floor is the *hardware/software gate above* plus the Enclave's own per-use
`Biometric` gesture — not a per-operation policy. Op-level approval-vs-PoP policy is
deferred, real future work. Know the boundary precisely: hardware-backing of the
approval key is enforced; per-operation intent is not.

## 4. Daemon broker behavior

What the daemon will and won't do, at the bytes level (the wire protocol itself is
an implementation detail of `internal/signerd`):

- **`list`** — returns the DIDs the daemon holds.
- **`public <DID>`** — returns that key's public half as a JWK.
- **`sign <DID> <data>`** — returns a signature over `data` by the held key. The
  daemon signs **arbitrary bytes** for any DID it holds (see §3 for why that is
  bounded by the hardware gate, not by op-level policy). The **private key never
  crosses the socket** in any operation.

**Access to the socket** is two independent gates:

- **Filesystem:** the socket's parent directory is `0700` and the socket is `0600`,
  so only the daemon's own uid can open it.
- **Peer-uid check:** every connection's peer uid is checked (`SO_PEERCRED` on
  Linux, `LOCAL_PEERCRED` on darwin) and a connection from any uid other than the
  daemon owner is refused before a byte is read. It **fails closed**: if the peer's
  identity can't be established, the connection is refused.

**What this does not protect against:** a process running as the *same uid* (the
owner) is, by design, allowed — the threat model is other local users, not the owner
attacking themselves. There is a 30s idle read deadline per connection (R4-01), but
**no hard connection-count cap**, so a same-uid client could still open many
connections; this is a self-DoS, heavily mitigated by the uid/permission gates but
not fully eliminated.

## 5. Key lifecycle

The durable-identity loop, end to end:

1. **Generate** — at enrollment (`kessa-issuer enroll`), a P-256 key is generated in
   the Secure Enclave under a keychain **tag** (default derived from the device DID),
   with the `Biometric` policy. Only the public half is published (in the device's
   DID document).
2. **Persist** — the key lives in the keychain under its tag; it survives restarts
   (this needs a code-signed binary; see §2).
3. **Load** — the daemon (`kessa-issuer daemon --mapping`) loads each enrolled key
   **by tag** on every start (`enclave.Load`). Generate-once, load-by-tag: a restart
   does not force re-enrollment.
4. **Sign** — clients broker signatures through the daemon; the key never leaves it.

**Revocation ≠ deletion.** A key becomes *untrusted* by flipping its credential's
bit in the issuer's signed **status list** (server-side), which the verifier
re-checks — revocation holds regardless of any local key state. `enclave.Delete`
removes the local key from the keychain, which is **device hygiene only, not part of
the trust model**: deleting the local key does not revoke anything, and revoking a
credential does not require touching the local key. Keep these separate.

**Device loss / replacement.** Re-run enrollment for the same durable employee
identity with a new device DID (the mapping is keyed by identity and holds N device
credentials, one per device, each with its own DID and status bit); then revoke the
lost device's credential via its status-list index. This is *symmetric by
construction* — no new mechanism — but the **polished CLI flow for it is not yet
built**; today it is two deliberate commands (`enroll`, then `revoke`).

## 6. Known limitations (read this first if you're deciding whether to trust a claim)

Blunt, and only what's true today:

- **Secure Enclave persistence: mechanism validated on hardware; the Go binary's
  macOS *packaging* is the residual.** The generate→persist-by-tag→reload-by-tag→
  sign→delete loop is confirmed on a real Enclave (free Personal Team), so
  "non-extractable hardware-backed identity" is a hardware-proven fact, not just a
  reviewed design. What was validated was a Swift harness issuing the identical
  Security.framework calls inside a profile-bearing app bundle; the compiled Go
  `enclave.Signer` itself hasn't run under a profile yet, because a `go build`/`go
  test` binary can't carry one. Closing that means shipping the daemon as a signed,
  profile-bearing **macOS app bundle** — a **macOS-specific, open-tier packaging**
  task (a solo build-from-source user hits the same wall; it is *not* a paid/fleet
  concern and *not* a mechanism gap). Linux/TPM has no equivalent bundling wall.
- **No op-level approval-vs-PoP policy.** Enforcement stops at the hardware/software
  gate on approval keys (§3); the daemon cannot distinguish a PoP sign from an
  approval sign per operation.
- **No hard connection-count cap** on the daemon socket (§4).
- **No TPM (Linux) backend** and **no Windows backend** exist (§2).
- **No service/automation identity.** The no-human-in-the-loop delegation case
  (an org-controlled automation identity issuing to unattended agents) is designed in
  shape but **not built**; the credential format is forward-compatible with it, but
  the provisioning flow does not exist.

---

*Design rationale (why scoped P-256, why the verifier is role-blind, why R4-02 was
fixed rather than deferred) lives in the MCP deployment design decision log — the
project's internal "why" record — not here. Enrollment ceremony details are in
[`enrollment.md`](enrollment.md); daemon operation in [`daemon.md`](daemon.md); the
Secure Enclave test/validation runbook in [`enclave-runbook.md`](enclave-runbook.md).*
