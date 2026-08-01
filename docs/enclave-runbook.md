<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Secure Enclave signer — test & validation runbook

`internal/signer/enclave` is the macOS Secure Enclave backend for the
employee/device key (§2a, B2): a non-extractable NIST P-256 key generated in the
Enclave, satisfying `signer.Signer`. It is built only under `darwin && cgo`;
every other build gets a stub, so Linux CI and the pure-Go verifier are
unaffected. There is deliberately **no CI for the Enclave** (GitHub's macOS
runners cost more and code-signing secrets add complexity for a pre-revenue,
solo project); this document is the manual runbook that stands in for it.

## What runs where

The Enclave splits into two paths with very different requirements, because
persisting a key in the keychain needs an entitlement that generating an
ephemeral one does not.

| Path | API | Needs code-signing? | Covered by |
| --- | --- | --- | --- |
| Crypto interop (sign/verify, public key, PoP) | `GenerateEphemeral` | **No** | `go test` on any Mac, unsigned |
| Persistence (durable device identity) | `Generate` / `Load` / `Delete` | **Yes** | `make test-enclave-signed` (a signing identity) |

The security-critical claim — *an Enclave signature verifies under the same
`signer.Verify` path a software P-256 signature does, and the key flows through
the DID/PoP machinery* — is the **interop** path, and it is validated **unsigned**
on real hardware. Persistence is an operational concern (reload the same key
across daemon restarts), and it needs a signed binary.

## 1. Interop tests — unsigned, any Mac with an Enclave

```bash
CGO_ENABLED=1 go test ./internal/signer/enclave/ -v
```

The `GenerateEphemeral`-based tests pass; the persistence tests **SKIP** with a
pointer here (they never fail an unsigned run). This is the everyday check.

## 2. Persistence tests — a code-signed binary with an entitlement

Persisting a Secure Enclave key uses the data-protection keychain, which requires
a `keychain-access-groups` entitlement. Empirically, on a stock machine:

- unsigned binary → `errSecMissingEntitlement (-34018)`
- **ad-hoc** signature (`codesign -s -`) → still `-34018`
- ad-hoc signature **+** the entitlement → the binary is **killed at launch**
  (AMFI rejects a restricted entitlement on an ad-hoc signature)

So persistence needs a **real Apple signing identity** — an *Apple Development*
certificate is enough, and a free Apple ID provides one via Xcode ("Personal
Team"). It does **not** need a paid Developer Program membership, and the key
never leaves the device, so no distribution/notarization is involved.

### One-time setup

1. In Xcode → Settings → Accounts, sign in with an Apple ID. This provisions an
   *Apple Development* certificate and a Team ID.
2. Find the identity and Team ID:
   ```bash
   security find-identity -v -p codesigning
   ```
3. Set the entitlement's access group to `<TeamID>.com.gneiss.kessa` in
   `build/enclave.entitlements` (the template ships with a `TEAMID` placeholder).

### Run the signed persistence tests

```bash
make test-enclave-signed SIGN_IDENTITY="Apple Development: you@example.com (XXXXXXXXXX)"
```

The target compiles the test binary (`go test -c`), code-signs it with the given
identity and `build/enclave.entitlements`, and runs it — including the
persistence tests, which now generate/load/delete real keychain-backed Enclave
keys.

## 3. Biometric path — manual smoke test

The automated tests use the `DeviceUnlock` policy so nothing prompts. The
`Biometric` policy (`kSecAccessControlBiometryCurrentSet`, for the human
approval/issuance key) triggers a Touch ID prompt on every `Sign`, so it cannot
be automated. To smoke-test it by hand, generate a `Biometric` key with a signed
binary and call `Sign` once; a Touch ID sheet should appear and a canceled prompt
should surface as `errSecAuthFailed (-25293)` / user-canceled `-128`.

## Notes

- **Non-extractability is unconditional** and holds under both policies and both
  the ephemeral and persistent paths: the private key is generated in and never
  leaves the Enclave. The access-control policy governs only whether each *use*
  needs a fresh gesture; it is not the security boundary.
- **Revocation** of a device key is enforced server-side via the status list,
  independent of anything on the device, so `Delete` is local hygiene (e.g.
  re-enrollment), not a revocation mechanism.
