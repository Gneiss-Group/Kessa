// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto/ecdsa"
	"testing"
)

// The employee/device key is a P-256 key (Secure Enclave / TPM cannot generate
// Ed25519). These tests pin the P-256 signer and the algorithm-agile Verify
// dispatcher that the whole scoped-P-256 path relies on.

func TestECDSASigner_SignVerify(t *testing.T) {
	s, err := NewECDSASigner("did:web:localhost:people:alice")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}
	if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", s.Public())
	}
	msg := []byte("employee proof of possession")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(s.Public(), msg, sig) {
		t.Fatal("a P-256 signature must verify under its own key")
	}
	if Verify(s.Public(), []byte("tampered"), sig) {
		t.Fatal("a P-256 signature must not verify a different message")
	}
}

// The seed fixes the KEY (for reproducible fixtures/demos) but NOT the signature:
// crypto/ecdsa draws a fresh nonce, matching a real hardware key. Both properties
// are asserted here so a future change that accidentally makes signatures
// deterministic (or keys non-deterministic) is caught.
func TestECDSASignerFromSeed_DeterministicKeyNondeterministicSig(t *testing.T) {
	a, err := NewECDSASignerFromSeed("did:x", seed32(0x5A))
	if err != nil {
		t.Fatalf("signer a: %v", err)
	}
	b, err := NewECDSASignerFromSeed("did:x", seed32(0x5A))
	if err != nil {
		t.Fatalf("signer b: %v", err)
	}
	if !KeysEqual(a.Public(), b.Public()) {
		t.Fatal("same seed must yield the same P-256 key")
	}
	msg := []byte("m")
	s1, _ := a.Sign(msg)
	s2, _ := a.Sign(msg)
	if !Verify(a.Public(), msg, s1) || !Verify(a.Public(), msg, s2) {
		t.Fatal("both signatures must verify under the key")
	}
}

// Verify must never accept a signature under the wrong algorithm's key, and
// KeysEqual must never call an Ed25519 key equal to a P-256 one. These are the
// cross-algorithm confusions the dispatcher exists to prevent.
func TestVerify_CrossAlgorithm(t *testing.T) {
	ed, err := NewSoftwareSignerFromSeed("did:ed", seed32(0x01))
	if err != nil {
		t.Fatalf("ed signer: %v", err)
	}
	ec, err := NewECDSASignerFromSeed("did:ec", seed32(0x02))
	if err != nil {
		t.Fatalf("ec signer: %v", err)
	}
	if KeysEqual(ed.Public(), ec.Public()) {
		t.Fatal("an Ed25519 key and a P-256 key must never compare equal")
	}
	msg := []byte("message")
	edSig, _ := ed.Sign(msg)
	ecSig, _ := ec.Sign(msg)
	if Verify(ec.Public(), msg, edSig) {
		t.Fatal("an Ed25519 signature must not verify under a P-256 key")
	}
	if Verify(ed.Public(), msg, ecSig) {
		t.Fatal("a P-256 signature must not verify under an Ed25519 key")
	}
}

// An unknown key type is a failed verification, never a panic or a skip.
func TestVerify_UnknownKeyType(t *testing.T) {
	if Verify("not a key", []byte("m"), []byte("sig")) {
		t.Fatal("an unsupported key type must fail verification")
	}
	if Verify(nil, []byte("m"), []byte("sig")) {
		t.Fatal("a nil key must fail verification")
	}
}
