// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package enclave is the hardware-backed signer.Signer for the employee/device
// key: a NIST P-256 key generated in and never leaving a platform secure element.
// The macOS Secure Enclave backend lives in enclave_darwin.go (built only under
// `darwin && cgo`); every other platform/build gets the stub in enclave_stub.go,
// so this package compiles everywhere and the verifier and Linux builds stay
// pure-Go. It satisfies the same signer.Signer seam the software signers do, so
// nothing above it changes — the Enclave signature is SHA-256 + ECDSA-P256 +
// ASN.1 DER, exactly what signer.Verify's P-256 branch already checks.
//
// Two guarantees are deliberately kept separate (they are not the same knob):
//
//   - NON-EXTRACTABILITY is unconditional: the private key is generated inside the
//     secure element and no policy changes that. This is the security claim.
//   - The USE gate is a per-key POLICY chosen at generation by the key's role,
//     because the right answer differs by signature type. An agent's PoP key signs
//     as the agent operates (potentially often) and must not demand a fresh user
//     gesture per call — that would break the background-resident daemon model
//     (§2, ssh-agent shape). A human's approval/issuance key signs only on
//     deliberate acts and SHOULD demand a fresh biometric each time, matching the
//     passkey "approve" convention. See Policy.
//
// This package is licensed Apache-2.0: per the §2a open-core decision, the
// hardware-backed identity mechanism is core to the security story and stays
// open, not paywalled.
package enclave

import (
	"errors"

	"github.com/Gneiss-Group/Kessa/internal/signer"
)

// Signer must satisfy the signing seam on every build (real or stub), so a
// cross-platform caller can hold an *enclave.Signer as a signer.Signer.
var _ signer.Signer = (*Signer)(nil)

// Policy is the access-control gate applied to key USE at generation time. It
// governs whether each signature needs a fresh user gesture; it never affects
// non-extractability, which holds under every policy.
type Policy int

const (
	// DeviceUnlock gates key use on the device merely being unlocked
	// (kSecAttrAccessibleWhenUnlockedThisDeviceOnly + private-key-usage), with no
	// per-signature prompt. This is the AGENT / PoP key policy: the daemon can sign
	// proof-of-possession as the agent works without a Touch ID tap per action.
	DeviceUnlock Policy = iota

	// Biometric additionally requires a fresh biometric match for every signature
	// (kSecAccessControlBiometryCurrentSet). This is the HUMAN key policy, for
	// approval and root-issuance signing — deliberate, infrequent acts where a
	// per-use gesture is the intended UX. Cannot be used non-interactively.
	Biometric
)

func (p Policy) String() string {
	switch p {
	case DeviceUnlock:
		return "device-unlock"
	case Biometric:
		return "biometric"
	default:
		return "unknown"
	}
}

var (
	// ErrUnsupported is returned by every constructor on a platform/build without a
	// secure-element backend (anything that is not darwin+cgo). Callers that must
	// run cross-platform check Available first and fall back to a software signer.
	ErrUnsupported = errors.New("enclave: no secure element on this platform/build")

	// ErrNotFound is returned by Load when no key exists for the given tag, so a
	// caller can distinguish "never enrolled" (generate one) from a real failure.
	ErrNotFound = errors.New("enclave: no key found for tag")

	// ErrMissingEntitlement is wrapped into the error from Generate (the permanent
	// path) when persisting a key failed for lack of a keychain-access-group
	// entitlement — i.e. the binary is not code-signed with one. GenerateEphemeral
	// avoids the keychain and never returns this. Callers/tests use errors.Is to
	// distinguish "needs signing" from a genuine failure. See docs/enclave-runbook.md.
	ErrMissingEntitlement = errors.New("enclave: keychain-access-group entitlement required (code-sign the binary)")
)
