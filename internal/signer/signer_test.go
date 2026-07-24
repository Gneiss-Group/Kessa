// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// seed32 returns a deterministic 32-byte seed filled with b, for tests.
func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestSoftwareSigner_SignVerifyRoundTrip(t *testing.T) {
	s, err := NewSoftwareSigner("did:web:localhost:orgs:acme")
	if err != nil {
		t.Fatalf("NewSoftwareSigner: %v", err)
	}

	msg := []byte("attest this action")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(s.Public(), msg, sig) {
		t.Fatal("Verify returned false for a signature we just produced")
	}

	// Tampered message must not verify.
	if Verify(s.Public(), []byte("attest this OTHER action"), sig) {
		t.Fatal("Verify accepted a signature over a different message")
	}
	// Tampered signature must not verify.
	bad := bytes.Clone(sig)
	bad[0] ^= 0xff
	if Verify(s.Public(), msg, bad) {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestSoftwareSigner_SeedIsDeterministic(t *testing.T) {
	did := types.DID("did:web:localhost:orgs:acme")
	a, err := NewSoftwareSignerFromSeed(did, seed32(0x11))
	if err != nil {
		t.Fatalf("signer a: %v", err)
	}
	b, err := NewSoftwareSignerFromSeed(did, seed32(0x11))
	if err != nil {
		t.Fatalf("signer b: %v", err)
	}
	if !a.Public().Equal(b.Public()) {
		t.Fatal("same seed produced different public keys")
	}

	// A different seed must produce a different key.
	c, err := NewSoftwareSignerFromSeed(did, seed32(0x22))
	if err != nil {
		t.Fatalf("signer c: %v", err)
	}
	if a.Public().Equal(c.Public()) {
		t.Fatal("different seeds produced the same public key")
	}

	if a.DID() != did {
		t.Fatalf("DID() = %q, want %q", a.DID(), did)
	}
}

func TestNewSoftwareSignerFromSeed_BadSeedLength(t *testing.T) {
	if _, err := NewSoftwareSignerFromSeed("did:web:localhost", []byte("too short")); err == nil {
		t.Fatal("expected error for short seed, got nil")
	}
}
