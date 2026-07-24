// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/internal/vc"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// genesisPrev is the PrevHash of the first entry in a fresh log, 32 zero bytes,
// mirroring audit.GenesisHash without importing it (this package is a leaf and
// stays that way).
var genesisPrev = make([]byte, sha256.Size)

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

var rootKey = []byte("credential-test-root-key-00000000")

// testAction is the action a PoP is bound to throughout these tests (F3);
// popInput also commits to the entry position: Seq and PrevHash (F4, R2-04).
var testAction = types.Action{Type: "post.publish", Target: "acct/1"}

// buildCredential composes a representative credential: a macaroon attenuated to
// a scope and bound to the holder, a status reference, and the holder key.
func buildCredential(t *testing.T, holder signer.Signer) *Credential {
	t.Helper()
	m := macaroon.Mint(rootKey, "cred-1", "did:web:localhost:orgs:acme")
	var err error
	m, err = macaroon.Attenuate(m, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "post.publish"})
	if err != nil {
		t.Fatal(err)
	}
	m, err = BindHolder(m, holder.Public())
	if err != nil {
		t.Fatalf("BindHolder: %v", err)
	}
	c, err := New(Options{
		Subject:   holder.DID(),
		Issuer:    "did:web:localhost:orgs:acme",
		Macaroon:  m,
		StatusRef: status.Reference{ListURL: "https://localhost/orgs/acme/status.json", Index: 42},
		HolderKey: holder.Public(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_ValidatesFields(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	good := macaroon.Mint(rootKey, "cred-1", "acme")

	cases := []struct {
		name string
		o    Options
	}{
		{"empty subject", Options{Issuer: "acme", Macaroon: good, HolderKey: holder.Public()}},
		{"empty issuer", Options{Subject: "worker", Macaroon: good, HolderKey: holder.Public()}},
		{"bad holder key", Options{Subject: "worker", Issuer: "acme", Macaroon: good, HolderKey: []byte("short")}},
		{"empty macaroon", Options{Subject: "worker", Issuer: "acme", HolderKey: holder.Public()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.o); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}

	if _, err := New(Options{Subject: "worker", Issuer: "acme", Macaroon: good, HolderKey: holder.Public()}); err != nil {
		t.Fatalf("valid options should construct: %v", err)
	}
}

func TestProofOfPossession_HolderControlsKey(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c := buildCredential(t, holder)

	nonce := []byte("fixed-challenge-nonce-0001")
	pop, err := c.ProvePossession(holder, nonce, testAction, 0, genesisPrev)
	if err != nil {
		t.Fatalf("ProvePossession: %v", err)
	}
	if err := c.VerifyPossession(pop, testAction, 0, genesisPrev); err != nil {
		t.Fatalf("legitimate holder should pass PoP: %v", err)
	}
}

// TestProofOfPossession_BoundToActionAndSeq is the credential-level F3/F4 check:
// a PoP minted for one (action, seq) does not verify against a different action
// or a different chain slot.
func TestProofOfPossession_BoundToActionAndSeq(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c := buildCredential(t, holder)
	nonce := []byte("fixed-challenge-nonce-000A")

	pop, err := c.ProvePossession(holder, nonce, testAction, 7, genesisPrev)
	if err != nil {
		t.Fatal(err)
	}
	// Right action + seq: passes.
	if err := c.VerifyPossession(pop, testAction, 7, genesisPrev); err != nil {
		t.Fatalf("PoP should verify against the action+seq it was signed for: %v", err)
	}
	// Different action (F3): fails.
	other := types.Action{Type: "post.publish", Target: "acct/attacker"}
	if err := c.VerifyPossession(pop, other, 7, genesisPrev); err == nil {
		t.Fatal("a PoP for one action must not verify against another (F3)")
	}
	// Different chain position (F4): fails.
	if err := c.VerifyPossession(pop, testAction, 8, genesisPrev); err == nil {
		t.Fatal("a PoP for seq 7 must not verify at seq 8 (F4)")
	}
	// Same Seq, DIFFERENT log (R2-04): fails. This is the case Seq alone could not
	// distinguish, a proxy restarted with a fresh in-memory log hands out the same
	// Seq values again, so without PrevHash a proof minted for the first run's slot
	// 7 replayed straight into the second run's slot 7.
	otherLog := bytes.Repeat([]byte{0xAB}, sha256.Size)
	if err := c.VerifyPossession(pop, testAction, 7, otherLog); err == nil {
		t.Fatal("a PoP bound to one log's slot 7 must not verify at another log's slot 7 (R2-04)")
	}
}

// TestTokenLoan_CopiedBlobFailsPoP is spec scenario 5: a copied credential in a
// process lacking the holder's private key cannot answer the challenge.
func TestTokenLoan_CopiedBlobFailsPoP(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c := buildCredential(t, holder)

	// The thief holds the copied blob but only their own (different) key.
	thief := newSigner(t, "did:web:localhost:agents:thief", 0x44)
	nonce := []byte("fixed-challenge-nonce-0002")
	pop, err := c.ProvePossession(thief, nonce, testAction, 0, genesisPrev)
	if err != nil {
		t.Fatalf("ProvePossession (thief): %v", err)
	}
	if err := c.VerifyPossession(pop, testAction, 0, genesisPrev); err == nil {
		t.Fatal("copied credential must fail proof of possession")
	}
}

func TestProofOfPossession_NotReplayableAcrossCredentials(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c1 := buildCredential(t, holder)

	// A second credential for the same holder but a different macaroon id.
	m2 := macaroon.Mint(rootKey, "cred-2", "acme")
	m2, _ = BindHolder(m2, holder.Public())
	c2, err := New(Options{Subject: holder.DID(), Issuer: "acme", Macaroon: m2, HolderKey: holder.Public()})
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("fixed-challenge-nonce-0003")
	pop, err := c1.ProvePossession(holder, nonce, testAction, 0, genesisPrev)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.VerifyPossession(pop, testAction, 0, genesisPrev); err == nil {
		t.Fatal("a PoP for credential 1 must not verify against credential 2")
	}
}

// TestHolderCaveat_CommittedInMacaroon shows the second, independent binding:
// the holder key lives inside the tamper-evident macaroon chain.
func TestHolderCaveat_CommittedInMacaroon(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c := buildCredential(t, holder)

	// The legitimately bound holder satisfies the macaroon's holder caveat.
	ctx := macaroon.Context{"action.type": "post.publish"}
	for k, v := range c.HolderContext() {
		ctx[k] = v
	}
	if err := macaroon.Verify(c.Macaroon, rootKey, ctx); err != nil {
		t.Fatalf("bound holder should satisfy the macaroon: %v", err)
	}

	// Swapping HolderKey in the blob does not change the committed caveat: the
	// attacker's HolderContext no longer matches the caveat value.
	thief := newSigner(t, "did:web:localhost:agents:thief", 0x44)
	c.HolderKey = thief.Public()
	tampered := macaroon.Context{"action.type": "post.publish"}
	for k, v := range c.HolderContext() {
		tampered[k] = v
	}
	if err := macaroon.Verify(c.Macaroon, rootKey, tampered); err == nil {
		t.Fatal("macaroon must not verify once HolderKey is swapped")
	}
}

func TestMarshalParse_RoundTrip(t *testing.T) {
	holder := newSigner(t, "did:web:localhost:agents:worker", 0x33)
	c := buildCredential(t, holder)

	// Attach a VC wrapper so the outermost-credential path is exercised too.
	acme := newSigner(t, "did:web:localhost:orgs:acme", 0x11)
	wrapper, err := vc.Issue(acme, c, vc.IssueOptions{ExtraTypes: []string{"KessaDelegationCredential"}})
	if err != nil {
		t.Fatalf("vc.Issue: %v", err)
	}
	c.VCWrapper = wrapper

	data, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got.Subject != c.Subject || got.Issuer != c.Issuer {
		t.Fatal("subject/issuer not preserved")
	}
	if got.StatusRef != c.StatusRef {
		t.Fatalf("status ref not preserved: %+v", got.StatusRef)
	}
	if !bytes.Equal(got.HolderKey, c.HolderKey) {
		t.Fatal("holder key not preserved")
	}
	// Macaroon still verifies after round trip.
	ctx := macaroon.Context{"action.type": "post.publish"}
	for k, v := range got.HolderContext() {
		ctx[k] = v
	}
	if err := macaroon.Verify(got.Macaroon, rootKey, ctx); err != nil {
		t.Fatalf("macaroon should verify after round trip: %v", err)
	}
	// VC wrapper still verifies after round trip.
	if got.VCWrapper == nil {
		t.Fatal("VC wrapper lost in round trip")
	}
	if err := got.VCWrapper.Verify(acme.Public()); err != nil {
		t.Fatalf("VC wrapper should verify after round trip: %v", err)
	}
	// PoP still works after round trip.
	nonce := []byte("fixed-challenge-nonce-0004")
	pop, err := got.ProvePossession(holder, nonce, testAction, 0, genesisPrev)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyPossession(pop, testAction, 0, genesisPrev); err != nil {
		t.Fatalf("PoP should work after round trip: %v", err)
	}
}
