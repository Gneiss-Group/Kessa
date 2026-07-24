// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package status

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

func newSigner(t *testing.T, did string, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(types.DID(did), seed32(seed))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func TestNew_EnforcesHerdPrivacyFloor(t *testing.T) {
	cases := []struct {
		req     int
		wantMin int
	}{
		{0, MinBits},
		{100, MinBits},
		{MinBits, MinBits},
		{MinBits + 1, MinBits + 8}, // rounds up to a byte boundary above the floor
		{200000, 200000},
	}
	for _, tc := range cases {
		l := New(tc.req)
		if l.Len() < tc.wantMin {
			t.Fatalf("New(%d).Len() = %d, want >= %d", tc.req, l.Len(), tc.wantMin)
		}
		if l.Len()%8 != 0 {
			t.Fatalf("New(%d).Len() = %d is not byte-aligned", tc.req, l.Len())
		}
	}
}

func TestSetLookupClear(t *testing.T) {
	l := New(MinBits)
	indices := []int{0, 7, 8, 9, 12345, MinBits - 1}
	for _, idx := range indices {
		// starts clear
		if got, err := l.Lookup(idx); err != nil || got {
			t.Fatalf("index %d: expected initially un-revoked (got %v, err %v)", idx, got, err)
		}
		// set
		if err := l.Set(idx, true); err != nil {
			t.Fatalf("Set(%d, true): %v", idx, err)
		}
		if got, _ := l.Lookup(idx); !got {
			t.Fatalf("index %d: expected revoked after Set", idx)
		}
		// clear
		if err := l.Set(idx, false); err != nil {
			t.Fatalf("Set(%d, false): %v", idx, err)
		}
		if got, _ := l.Lookup(idx); got {
			t.Fatalf("index %d: expected un-revoked after clear", idx)
		}
	}
}

func TestSet_SettingOneBitDoesNotDisturbNeighbors(t *testing.T) {
	l := New(MinBits)
	if err := l.Set(10, true); err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{8, 9, 11, 12} {
		if got, _ := l.Lookup(idx); got {
			t.Fatalf("neighbor index %d was disturbed by setting 10", idx)
		}
	}
	if got, _ := l.Lookup(10); !got {
		t.Fatal("index 10 should be set")
	}
}

func TestBitOrdering_MSBFirst(t *testing.T) {
	// Index 0 is the most-significant bit of the first byte (0x80), matching the
	// W3C bitstring convention.
	l := New(MinBits)
	if err := l.Set(0, true); err != nil {
		t.Fatal(err)
	}
	if l.Bits[0] != 0x80 {
		t.Fatalf("Bits[0] = %#x after Set(0), want 0x80", l.Bits[0])
	}
	if err := l.Set(0, false); err != nil {
		t.Fatal(err)
	}
	if err := l.Set(7, true); err != nil {
		t.Fatal(err)
	}
	if l.Bits[0] != 0x01 {
		t.Fatalf("Bits[0] = %#x after Set(7), want 0x01", l.Bits[0])
	}
}

func TestSetLookup_OutOfRange(t *testing.T) {
	l := New(MinBits)
	for _, idx := range []int{-1, l.Len(), l.Len() + 1} {
		if err := l.Set(idx, true); err == nil {
			t.Fatalf("Set(%d) should be out of range", idx)
		}
		if _, err := l.Lookup(idx); err == nil {
			t.Fatalf("Lookup(%d) should be out of range", idx)
		}
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	l := New(MinBits)
	_ = l.Set(42, true)

	if err := l.Sign(s); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if l.Issuer != s.DID() {
		t.Fatalf("Sign did not stamp issuer: got %q", l.Issuer)
	}
	if err := l.Verify(s.Public()); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Through the portable format.
	data, err := l.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := got.Verify(s.Public()); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
	if revoked, _ := got.Lookup(42); !revoked {
		t.Fatal("revocation bit lost in round trip")
	}
	if ok, _ := got.Lookup(43); ok {
		t.Fatal("unexpected bit set after round trip")
	}
}

func TestVerify_TamperedBitFails(t *testing.T) {
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	l := New(MinBits)
	if err := l.Sign(s); err != nil {
		t.Fatal(err)
	}
	// An attacker flips a revocation bit after signing.
	l.Bits[100] ^= 0x01
	if err := l.Verify(s.Public()); err == nil {
		t.Fatal("Verify should fail after a bit is flipped post-signature")
	}
}

func TestVerify_TamperedSignatureFails(t *testing.T) {
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	l := New(MinBits)
	if err := l.Sign(s); err != nil {
		t.Fatal(err)
	}
	l.Signature[0] ^= 0xff
	if err := l.Verify(s.Public()); err == nil {
		t.Fatal("Verify should fail with a tampered signature")
	}
}

func TestVerify_WrongIssuerKeyFails(t *testing.T) {
	signerA := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	signerB := newSigner(t, "did:web:localhost:orgs:bravo", 0x22)
	l := New(MinBits)
	if err := l.Sign(signerA); err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(signerB.Public()); err == nil {
		t.Fatal("Verify should fail against a different issuer's key")
	}
}

func TestVerify_TamperedIssuerOrPurposeFails(t *testing.T) {
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	l := New(MinBits)
	if err := l.Sign(s); err != nil {
		t.Fatal(err)
	}
	// Issuer is part of the signed input.
	tamperedIssuer := *l
	tamperedIssuer.Issuer = "did:web:localhost:orgs:evil"
	if err := tamperedIssuer.Verify(s.Public()); err == nil {
		t.Fatal("Verify should fail when Issuer is altered")
	}
	// Purpose is part of the signed input.
	tamperedPurpose := *l
	tamperedPurpose.Purpose = PurposeSuspension
	if err := tamperedPurpose.Verify(s.Public()); err == nil {
		t.Fatal("Verify should fail when Purpose is altered")
	}
}

func TestVerify_UndersizedListRejected(t *testing.T) {
	// Bypass New to build a too-small list, sign it honestly, and confirm Verify
	// still rejects it on the herd-privacy floor.
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	small := &StatusList{Purpose: PurposeRevocation, Bits: make([]byte, 10)}
	if err := small.Sign(s); err != nil {
		t.Fatal(err)
	}
	if err := small.Verify(s.Public()); err == nil {
		t.Fatal("Verify should reject a list below the herd-privacy minimum")
	}
}

func TestMarshal_RefusesUnsigned(t *testing.T) {
	l := New(MinBits)
	if _, err := l.Marshal(); err == nil {
		t.Fatal("Marshal should refuse an unsigned list")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	s := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	l := New(MinBits)
	_ = l.Set(7, true)
	if err := l.Sign(s); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/status.json"
	if err := Save(l, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := got.Verify(s.Public()); err != nil {
		t.Fatalf("Verify after Save/Load: %v", err)
	}
	if revoked, _ := got.Lookup(7); !revoked {
		t.Fatal("bit lost through Save/Load")
	}
}

// TestPublishPath_RejectsTraversal is the F5 (and pre-existing path) guard: a
// crafted list URL must not become a write primitive that escapes the root, the
// host is checked for traversal just like the path segments.
func TestPublishPath_RejectsTraversal(t *testing.T) {
	root := "/srv/public"
	bad := []string{
		"https://../evil/status.json",            // F5: traversal in the host
		"https://%2e%2e/evil/status.json",        // percent-encoded host traversal
		"https://acme.example/../../status.json", // traversal in the path
		"https://acme.example/a/../b/status.json",
		"ftp://acme.example/status.json", // wrong scheme
		"https:///status.json",           // no host
		"https://acme.example",           // no path
	}
	for _, u := range bad {
		if p, err := PublishPath(root, u); err == nil {
			t.Fatalf("PublishPath(%q) should be rejected, got %q", u, p)
		}
	}

	// A legitimate URL still maps beneath the root.
	good := "https://acme.example/orgs/acme/status.json"
	p, err := PublishPath(root, good)
	if err != nil {
		t.Fatalf("PublishPath(%q) should succeed: %v", good, err)
	}
	if !strings.HasPrefix(p, root+"/acme.example/") {
		t.Fatalf("PublishPath(%q) = %q, want it beneath the host dir", good, p)
	}
}
