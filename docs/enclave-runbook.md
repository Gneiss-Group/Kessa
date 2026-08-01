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
| Crypto interop (sign/verify, public key, PoP) | `GenerateEphemeral` | **No** | `go test` on any Mac, unsigned — **validated** |
| Persistence (durable device identity) | `Generate` / `Load` / `Delete` | **Yes — signature + provisioning profile** | **not yet validated**; needs a profile-carrying build, see §2 |

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
- **real Apple Development signature + the entitlement, on a hand-`codesign`'d
  standalone binary** → **also killed at launch** (2026-08-01, Apple-Silicon Mac,
  free Personal Team). AMFI: `Restricted entitlements not validated, bailing out.
  Error Code=-413 "No matching profile found"` / `-67671`.

> **Correction (2026-08-01), superseding the earlier "a free Personal Team is
> enough" claim.** A valid *Apple Development* identity is **necessary but not
> sufficient.** `keychain-access-groups` is a *restricted* entitlement that macOS
> validates against an embedded **provisioning profile**, not against the signature.
> A binary produced by `go test -c` is a bare Mach-O with nowhere to carry a
> profile, so AMFI SIGKILLs it at exec (`-413 "No matching profile found"`) even
> with a perfectly valid Development cert. **The `make test-enclave-signed` recipe
> below therefore does not work as-is** — the code-sign-a-test-binary approach can
> never satisfy the profile requirement. See "Getting a profile" for what actually
> validates persistence.

### One-time setup

1. In Xcode → Settings → Accounts, sign in with an Apple ID. This provisions an
   *Apple Development* certificate and a Team ID.
2. Find the identity and Team ID:
   ```bash
   security find-identity -v -p codesigning
   ```
   (If this returns `0 valid identities` while `-p codesigning` without `-v` shows
   one, the certificate chain is untrusted — install the current **Apple WWDR** and
   **Apple Root** intermediates from <https://www.apple.com/certificateauthority/>.)
3. Set the entitlement's access group to `<TeamID>.com.gneiss.kessa` in
   `build/enclave.entitlements` (the template ships with a `TEAMID` placeholder).
   **Do not commit your Team ID** — restore the placeholder before committing
   (`git checkout build/enclave.entitlements`).

### Getting a profile (the actual requirement)

A free Personal Team **cannot mint a provisioning profile by hand** (no developer
portal access). The only free way to obtain one is **Xcode automatic signing**
generating it during a build of a real app/tool **target** — which a raw `go test`
binary is not. Options, in order of effort:

1. **Xcode app/tool target (free path, one unverified assumption).** Create a tiny
   macOS command-line-tool or app target with bundle id `com.gneiss.kessa`,
   automatic signing under your Personal Team, and the **Keychain Sharing**
   capability (this is what adds `keychain-access-groups`). Building it makes Xcode
   generate + embed a development provisioning profile that authorizes the
   entitlement on this device. Exercise `Generate`/`Load`/`Delete` there — either
   reimplement the ~30 lines of Security.framework calls that
   `enclave_darwin.go` wraps, or cgo-link `internal/signer/enclave` into the target.
   **Unverified:** whether free Personal Teams are permitted the Keychain Sharing
   capability at all. If Xcode refuses to add it, this path is blocked and only a
   paid membership works — this is the next thing to test.
2. **Embed the Xcode-generated profile around the test binary.** Once step 1 has
   produced a profile (`~/Library/MobileDevice/Provisioning Profiles/*.provisionprofile`,
   or `App.app/Contents/embedded.provisionprofile`), wrap `bin/enclave.test` in a
   minimal `.app` bundle, copy the profile to `Contents/embedded.provisionprofile`,
   and re-`codesign --entitlements build/enclave.entitlements`. This runs the *real*
   Go code under a valid profile.
3. **Paid Apple Developer Program ($99/yr).** Mints an App ID + profile for any
   bundle id (a CLI tool included), which makes the entitlement authorizable
   directly. Definite, but outside the free-validation path this runbook targeted.

`make test-enclave-signed SIGN_IDENTITY="…"` only performs the signature step; it
does not embed a profile, so it will `Killed: 9` until one of the above supplies
one. Treat it as the signing helper, not a complete recipe.

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
