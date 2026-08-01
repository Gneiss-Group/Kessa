// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/signer/enclave"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// backend names recorded in the mapping and shown at enrollment.
const (
	backendSecureEnclave = "secure-enclave"
	backendSoftware      = "software"
)

// DeviceKeyOptions controls how the device key is generated at enrollment.
type DeviceKeyOptions struct {
	// ForceSoftware skips the secure element and mints a software P-256 key even
	// on a platform that has one. It exists for CI, demos, and dev machines that
	// cannot code-sign; a key minted this way is NOT hardware-backed and must never
	// carry the "non-extractable" claim. The mapping records backend="software" so
	// this is never silently forgotten.
	ForceSoftware bool

	// Seed, if set (32 bytes), derives a DETERMINISTIC software key. It only
	// applies to the software path (a secure element generates its own entropy and
	// cannot import a seed) and exists solely for reproducible fixtures/tests.
	Seed []byte

	// Tag is the keychain tag the secure-element key is persisted under, so the
	// daemon can Load it by tag across restarts (the load-bearing generate-once /
	// load-by-tag property). Ignored on the software path.
	Tag []byte
}

// KeyInfo describes a freshly generated device key, without the private half.
type KeyInfo struct {
	Algorithm   string // "P-256" or "Ed25519"
	Fingerprint string // "SHA256:<base64url>" of the public-key JWK
	Backend     string // backendSecureEnclave or backendSoftware
	Tag         []byte // keychain tag (secure-element path only)
}

// ProvisionDeviceKey generates the employee's device key for did and returns a
// signer over it plus its public description.
//
// It prefers a real secure element when one is present and not overridden. The
// key it mints there is the human/employee ISSUANCE-and-approval key, so it is
// generated under the Biometric use-gate (a fresh gesture per signature) — the
// deliberate-act convention decided for the human key, distinct from the agent's
// device-unlock PoP key. Non-extractability holds regardless of that gate.
//
// It does NOT silently fall back to software when the secure element exists but
// rejects the key (e.g. a missing keychain-access-group entitlement on an
// unsigned binary): a silent downgrade would quietly void the hardware-backed
// claim. The caller is told to code-sign the binary or pass ForceSoftware
// explicitly, so a software key is always a deliberate, recorded choice.
func ProvisionDeviceKey(deviceDID types.DID, o DeviceKeyOptions) (signer.Signer, KeyInfo, error) {
	if o.ForceSoftware || !enclave.Available() {
		sg, err := softwareKey(deviceDID, o.Seed)
		if err != nil {
			return nil, KeyInfo{}, err
		}
		info, err := describeKey(sg, backendSoftware, nil)
		return sg, info, err
	}

	sg, err := enclave.Generate(deviceDID, o.Tag, enclave.Biometric)
	if err != nil {
		if errors.Is(err, enclave.ErrMissingEntitlement) {
			return nil, KeyInfo{}, fmt.Errorf(
				"enroll: secure element requires a code-signed binary with a keychain-access-group "+
					"entitlement (see docs/enclave-runbook.md); code-sign kessa-issuer, or pass --software-key "+
					"for a non-production key: %w", err)
		}
		return nil, KeyInfo{}, fmt.Errorf("enroll: generate secure-element key: %w", err)
	}
	info, err := describeKey(sg, backendSecureEnclave, o.Tag)
	return sg, info, err
}

// softwareKey mints a software P-256 key, deterministic if a seed is supplied.
// P-256 (not Ed25519) so the software path exercises the exact algorithm the
// secure element produces, keeping fixtures faithful to the hardware shape.
func softwareKey(deviceDID types.DID, seed []byte) (signer.Signer, error) {
	if len(seed) > 0 {
		return signer.NewECDSASignerFromSeed(deviceDID, seed)
	}
	return signer.NewECDSASigner(deviceDID)
}

// describeKey fills a KeyInfo from a signer's public half.
func describeKey(sg signer.Signer, backend string, tag []byte) (KeyInfo, error) {
	alg, err := algorithmOf(sg.Public())
	if err != nil {
		return KeyInfo{}, err
	}
	fp, err := Fingerprint(sg.Public())
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{Algorithm: alg, Fingerprint: fp, Backend: backend, Tag: tag}, nil
}

// algorithmOf names the signature algorithm of a resolved public key.
func algorithmOf(pub any) (string, error) {
	switch pub.(type) {
	case ed25519.PublicKey:
		return "Ed25519", nil
	case *ecdsa.PublicKey:
		return "P-256", nil
	default:
		return "", fmt.Errorf("enroll: unsupported device key type %T", pub)
	}
}

// cleanupDeviceKey tears down a freshly provisioned device key when an enrollment
// is rejected after the key was created, so a failed/declined enrollment leaves no
// partial state. It closes the signer handle and, for a PERSISTENT secure-element
// key, deletes it from the keychain (a persistent Enclave key already exists in
// the keychain the moment Generate returns). A software key needs no keychain
// cleanup; Delete on a non-darwin build is a no-op. Best-effort: cleanup errors
// are swallowed because the enrollment is already failing for another reason.
func cleanupDeviceKey(sg signer.Signer, info KeyInfo) {
	if c, ok := sg.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	if info.Backend == backendSecureEnclave && len(info.Tag) > 0 {
		_ = enclave.Delete(info.Tag)
	}
}

// Fingerprint is the stable identifier an operator confirms at trust-on-first-use.
// It is SHA-256 over the key's canonical JWK JSON — the same self-describing
// encoding the credential binds and the DID document publishes — so the value an
// operator sees at enrollment is reproducible from the published DID document
// alone, and an Ed25519 and a P-256 key can never collide. Rendered "SHA256:<b64url>"
// to match the shape ssh prints for a host key.
func Fingerprint(pub any) (string, error) {
	if _, err := algorithmOf(pub); err != nil {
		return "", err
	}
	jwk := did.PublicKeyToJWK(pub)
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("enroll: encode key for fingerprint: %w", err)
	}
	sum := sha256.Sum256(b)
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
