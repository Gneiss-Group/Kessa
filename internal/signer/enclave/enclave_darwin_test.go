// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

// These tests exercise the REAL Secure Enclave on the host Mac. They split by
// what a given machine can run:
//
//   - INTEROP tests use GenerateEphemeral (no keychain, no entitlement), so they
//     run from a plain `go test` on any Mac with an Enclave, unsigned. They cover
//     the security-critical claim: an Enclave signature verifies under the B1
//     seam, and the key flows through the DID/PoP machinery.
//   - PERSISTENCE tests use Generate (permanent keychain key), which needs a
//     code-signed binary with a keychain-access-group entitlement. On an unsigned
//     run they SKIP with a pointer to the runbook (they do not fail), so the
//     package is green unsigned and fully covered when run signed (see
//     docs/enclave-runbook.md and `make test-enclave-signed`).
//
// DeviceUnlock policy only, so no Touch ID prompt fires. Each persistence test
// uses a random keychain tag and deletes it on the way out.
package enclave

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

func randTag(t *testing.T) []byte {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return []byte("com.gneiss.kessa.test." + hex.EncodeToString(b[:]))
}

// ephemeral makes an entitlement-free Enclave signer for the interop tests.
func ephemeral(t *testing.T, d types.DID) *Signer {
	t.Helper()
	s, err := GenerateEphemeral(d, DeviceUnlock)
	if err != nil {
		t.Fatalf("GenerateEphemeral (is this a Mac with a Secure Enclave?): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// requirePersistent generates a permanent key or SKIPS if the binary lacks the
// keychain-access-group entitlement. This is what keeps an unsigned `go test`
// green while still fully covering the persistence path when run signed.
func requirePersistent(t *testing.T, d types.DID, tag []byte) *Signer {
	t.Helper()
	s, err := Generate(d, tag, DeviceUnlock)
	if errors.Is(err, ErrMissingEntitlement) {
		t.Skip("persistence needs a code-signed binary with a keychain-access-group entitlement; run `make test-enclave-signed` (see docs/enclave-runbook.md)")
	}
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return s
}

// ---- interop (runs unsigned) ----------------------------------------------

// The core interop claim: an Enclave signature verifies under signer.Verify's
// P-256 branch, exactly as a software P-256 signature does, with no special
// handling. This is the whole point of B2 slotting behind the B1 seam.
func TestEnclave_GenerateSignVerify(t *testing.T) {
	s := ephemeral(t, "did:web:localhost:agents:worker")

	msg := []byte("proof-of-possession input")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !signer.Verify(s.Public(), msg, sig) {
		t.Fatal("Enclave signature must verify under its own key via signer.Verify")
	}
	if signer.Verify(s.Public(), []byte("tampered"), sig) {
		t.Fatal("Enclave signature must not verify a different message")
	}
}

// The Enclave key's public half is a P-256 *ecdsa.PublicKey that flows through
// did.PublicKeyToJWK and back unchanged, so enrollment can publish it in a DID
// document with no special casing.
func TestEnclave_PublicIsP256AndJWKRoundTrips(t *testing.T) {
	s := ephemeral(t, "did:web:localhost:agents:worker")

	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", s.Public())
	}
	jwk := did.PublicKeyToJWK(pub)
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		t.Fatalf("unexpected JWK for an Enclave key: %+v", jwk)
	}
	back, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("JWK round-trip: %v", err)
	}
	if !signer.KeysEqual(back, pub) {
		t.Fatal("Enclave public key did not survive the JWK round trip")
	}
}

// End-to-end through B1's proof-of-possession machinery: an Enclave-held key acts
// as the terminal holder. The credential binds its public half; ProvePossession
// signs with the Enclave; VerifyPossession (which routes through signer.Verify)
// accepts it. This is the employee/device key doing its actual job.
func TestEnclave_ProofOfPossession(t *testing.T) {
	d := types.DID("did:web:localhost:agents:worker")
	s := ephemeral(t, d)

	m := macaroon.Mint([]byte("enclave-test-root-key-0000000000"), "cred-se", string(d))
	c, err := credential.New(credential.Options{
		Subject: d, Issuer: "did:web:localhost:orgs:acme", Macaroon: m, HolderKey: s.Public(),
	})
	if err != nil {
		t.Fatalf("credential.New with an Enclave public key: %v", err)
	}

	action := types.Action{Type: "payment.transfer", Target: "acct/1", Timestamp: time.Unix(0, 0).UTC()}
	prevHash := make([]byte, 32)
	pop, err := c.ProvePossession(s, []byte("nonce-se"), action, 0, prevHash)
	if err != nil {
		t.Fatalf("ProvePossession with the Enclave signer: %v", err)
	}
	if err := c.VerifyPossession(pop, action, 0, prevHash); err != nil {
		t.Fatalf("VerifyPossession must accept the Enclave-signed PoP: %v", err)
	}
}

func TestEnclave_ClosedSignerRejects(t *testing.T) {
	s := ephemeral(t, "did:x")
	_ = s.Close()
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("Sign on a closed signer must error")
	}
	_ = s.Close() // idempotent
}

// ---- persistence (skips unsigned; full coverage when signed) --------------

// Persistence is load-bearing: the daemon reloads the same non-extractable key
// across restarts. Generate, drop the handle, Load by the same tag; the loaded
// key must be the same key and able to sign.
func TestEnclave_PersistsAcrossLoad(t *testing.T) {
	d := types.DID("did:web:localhost:agents:worker")
	tag := randTag(t)
	s1 := requirePersistent(t, d, tag)
	t.Cleanup(func() { _ = Delete(tag) })
	pub1 := s1.Public()
	_ = s1.Close() // simulate process exit

	s2, err := Load(d, tag)
	if err != nil {
		t.Fatalf("Load after Close: %v", err)
	}
	defer s2.Close()
	if !signer.KeysEqual(s2.Public(), pub1) {
		t.Fatal("reloaded key differs from the generated key")
	}
	msg := []byte("post-restart signature")
	sig, err := s2.Sign(msg)
	if err != nil {
		t.Fatalf("Sign after Load: %v", err)
	}
	if !signer.Verify(s2.Public(), msg, sig) {
		t.Fatal("reloaded key must still verify its own signatures")
	}
}

func TestEnclave_LoadNotFound(t *testing.T) {
	// This one needs no persistence and runs on any build: an absent tag is
	// ErrNotFound, whether or not the binary is entitled.
	if _, err := Load("did:x", randTag(t)); err != ErrNotFound {
		t.Fatalf("Load of an absent tag = %v, want ErrNotFound", err)
	}
}

func TestEnclave_DeleteRemoves(t *testing.T) {
	d := types.DID("did:web:localhost:agents:worker")
	tag := randTag(t)
	s := requirePersistent(t, d, tag)
	_ = s.Close()
	if err := Delete(tag); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Load(d, tag); err != ErrNotFound {
		t.Fatalf("Load after Delete = %v, want ErrNotFound", err)
	}
	// Deleting an already-absent key is not an error.
	if err := Delete(tag); err != nil {
		t.Fatalf("Delete of absent key should be a no-op, got %v", err)
	}
}
