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
| Persistence (durable device identity) | `Generate` / `Load` / `Delete` | **Yes — signature + provisioning profile** | **mechanism validated** on real hardware via an Xcode app target (free Personal Team); see §2 |

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

### Validated on hardware (2026-08-01) — the mechanism works, free team

Option 1 above was confirmed on an Apple-Silicon Mac with a **free Personal Team**:

- **Keychain Sharing *is* available to a free Personal Team** — adding the
  capability to an Xcode macOS **App** target (bundle id `com.gneiss.kessa`,
  automatic signing) generated + embedded a provisioning profile with no error.
- Running the harness below (the exact `SecKeyCreateRandomKey` /
  `SecItemCopyMatching` / `SecItemDelete` calls and attributes `enclave_darwin.go`
  issues) **generated a permanent Enclave key by tag, reloaded the same key by a
  fresh keychain lookup, signed with it, and deleted it** — the daemon's
  restart-time `Load` is precisely that reload. It worked **without**
  `kSecUseDataProtectionKeychain`, matching the Go code's attribute set.

So: **no paid membership is required** — the wall was the hand-`codesign`'d CLI
binary, not the free team.

**Residual, stated precisely (don't let it round up):** what executed was the
Swift harness inside a profile-bearing `.app`, not the compiled Go
`enclave.Signer` itself (a `go test`/`go build` binary can't carry a profile). The
Go code is a literal passthrough to the validated calls, so this is a **packaging**
gap — running the Go path under a profile means shipping the daemon as a signed,
profile-bearing macOS **app bundle** — **not a mechanism gap.**

**Which tier this belongs to (matters — don't file it under fleet tooling):** this
packaging step is **open-tier (§2a) core work, and macOS-specific.** It is an
OS-level constraint (Gatekeeper/AMFI/entitlement inheritance), not a scale one: a
solo developer building from source on their own Mac hits the *identical* wall a
500-laptop fleet would, so it is load-bearing for the open tier's own "try this
yourself" promise, not a paid convenience. It is distinct from **production Apple
Developer ID signing + notarization for fleet-wide distribution**, which *is*
scale-dependent and correctly stays §2b. Linux/TPM almost certainly has no
equivalent bundling wall, so don't generalize this to "the daemon needs bundling
everywhere" — it's macOS specifically.

Harness (drop into the App target's `@main` `App.init()`, Run, read the console):

```swift
import SwiftUI
import Security

let kessaTag = "com.gneiss.kessa.test".data(using: .utf8)!

func kessaGenerate() -> SecKey? {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage], &err) else { print("❌ access-control:", err!.takeRetainedValue()); return nil }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kessaTag,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        print("❌ generate:", err!.takeRetainedValue()); return nil }
    return key
}
func kessaLoad() -> SecKey? {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: kessaTag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    if st != errSecSuccess { print("❌ load OSStatus:", st); return nil }
    return (out as! SecKey)
}
func kessaDelete() {
    SecItemDelete([kSecClass as String: kSecClassKey,
                   kSecAttrApplicationTag as String: kessaTag] as CFDictionary)
}
func kessaRunTest() {
    kessaDelete()
    guard kessaGenerate() != nil else { print("FAIL generate"); return }
    guard let k = kessaLoad() else { print("FAIL reload-by-tag"); return }
    var e: Unmanaged<CFError>?
    _ = SecKeyCreateSignature(k, .ecdsaSignatureMessageX962SHA256,
                              "hello".data(using: .utf8)! as CFData, &e)
    kessaDelete()
    print("RESULT: ✅ PERSISTENCE VALIDATED")
}
```

For a belt-and-suspenders *cross-process-restart* proof (optional): comment out
both `kessaDelete()` calls, Run once (generates), quit, Run again — the second run
reloads the key a prior process wrote. The reload-by-tag above already exercises a
genuine keychain retrieval, so this only removes the last "same process" caveat.

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
