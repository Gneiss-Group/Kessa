// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const didsRoot = "../../testdata/dids"

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

// sampleSubject stands in for the composed credential the wrapper carries.
type sampleSubject struct {
	ID    types.DID `json:"id"`
	Scope string    `json:"scope"`
}

var fixedTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// TestIssueVerify_AgainstDIDDocument is the step-5 acceptance: a VC issued by
// Org A verifies against A's published DID document.
func TestIssueVerify_AgainstDIDDocument(t *testing.T) {
	acme := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	subject := sampleSubject{ID: "did:web:localhost:agents:worker", Scope: "post.publish"}

	cred, err := Issue(acme, subject, IssueOptions{IssuedAt: fixedTime})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Resolve the issuer's key the way a peer org (with no shared config) would:
	// straight from A's published DID document.
	pub, err := did.ResolveKey(did.FileResolver{Root: didsRoot}, cred.Issuer)
	if err != nil {
		t.Fatalf("resolve issuer key: %v", err)
	}
	if err := cred.Verify(pub); err != nil {
		t.Fatalf("VC should verify against issuer DID doc: %v", err)
	}
	if err := cred.Valid(fixedTime); err != nil {
		t.Fatalf("VC should be valid at issuance time: %v", err)
	}

	// Subject round-trips.
	var got sampleSubject
	if err := cred.UnmarshalSubject(&got); err != nil {
		t.Fatalf("UnmarshalSubject: %v", err)
	}
	if got != subject {
		t.Fatalf("subject mismatch: got %+v want %+v", got, subject)
	}
}

// TestForgedIssuerFails: a forger signs with its own key but claims Org A as
// issuer. Verified against A's real key, it must fail.
func TestForgedIssuerFails(t *testing.T) {
	forger := newSigner(t, "did:web:localhost:orgs:acme", 0x22) // wrong key, claims acme
	subject := sampleSubject{ID: "did:web:localhost:agents:worker", Scope: "post.publish"}
	cred, err := Issue(forger, subject, IssueOptions{IssuedAt: fixedTime})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.Issuer != "did:web:localhost:orgs:acme" {
		t.Fatalf("unexpected issuer %q", cred.Issuer)
	}

	acmeKey, err := did.ResolveKey(did.FileResolver{Root: didsRoot}, "did:web:localhost:orgs:acme")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := cred.Verify(acmeKey); err == nil {
		t.Fatal("forged VC must not verify against the real issuer key")
	}
}

func TestTamperFails(t *testing.T) {
	acme := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	pub := acme.Public()

	base := func(t *testing.T) *VerifiableCredential {
		c, err := Issue(acme, sampleSubject{ID: "did:web:localhost:agents:worker", Scope: "post.publish"}, IssueOptions{IssuedAt: fixedTime})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("tampered credentialSubject", func(t *testing.T) {
		c := base(t)
		c.CredentialSubject = []byte(`{"id":"did:web:localhost:agents:worker","scope":"payment.transfer"}`)
		if err := c.Verify(pub); err == nil {
			t.Fatal("altered credentialSubject should fail verification")
		}
	})

	t.Run("tampered issuer", func(t *testing.T) {
		c := base(t)
		c.Issuer = "did:web:localhost:orgs:evil"
		if err := c.Verify(pub); err == nil {
			t.Fatal("altered issuer should fail verification")
		}
	})

	t.Run("tampered proof value", func(t *testing.T) {
		c := base(t)
		// flip a byte in the signature
		sig := []byte(c.Proof.ProofValue)
		sig[0] ^= 0x01 // still valid base64url alphabet-wise for most bytes; decode may still succeed
		c.Proof.ProofValue = string(sig)
		if err := c.Verify(pub); err == nil {
			t.Fatal("altered proofValue should fail verification")
		}
	})

	t.Run("missing proof", func(t *testing.T) {
		c := base(t)
		c.Proof = nil
		if err := c.Verify(pub); err == nil {
			t.Fatal("VC with no proof should fail verification")
		}
	})
}

func TestMarshalParse_RoundTripVerifies(t *testing.T) {
	acme := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	cred, err := Issue(acme, sampleSubject{ID: "did:web:localhost:agents:worker", Scope: "post.publish"}, IssueOptions{
		IssuedAt:   fixedTime,
		ExtraTypes: []string{"KessaDelegationCredential"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := cred.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := got.Verify(acme.Public()); err != nil {
		t.Fatalf("VC should verify after Marshal/Parse round trip: %v", err)
	}
	if len(got.Type) != 2 || got.Type[1] != "KessaDelegationCredential" {
		t.Fatalf("types not preserved: %v", got.Type)
	}
}

func TestValid_Window(t *testing.T) {
	acme := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	expiry := fixedTime.Add(24 * time.Hour)
	cred, err := Issue(acme, sampleSubject{ID: "did:web:localhost:agents:worker", Scope: "x"}, IssueOptions{
		IssuedAt: fixedTime,
		Expires:  &expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"before issuance", fixedTime.Add(-time.Hour), false},
		{"at issuance", fixedTime, true},
		{"within window", fixedTime.Add(time.Hour), true},
		{"after expiry", expiry.Add(time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cred.Valid(tc.at)
			if tc.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected invalid, got nil")
			}
		})
	}
}
