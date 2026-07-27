// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// mapResolver is an in-memory did.Resolver built from the test principals, so
// the chain test needs no fixture files.
type mapResolver map[types.DID]*did.Document

func (r mapResolver) Resolve(d types.DID) (*did.Document, error) {
	doc, ok := r[d]
	if !ok {
		return nil, fmt.Errorf("no DID document for %s", d)
	}
	return doc, nil
}

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

var chainRootKey = []byte("chain-test-macaroon-root-key-0000")

// principal bundles a signer and is registered into the resolver.
type principal struct {
	signer signer.Signer
}

func newPrincipal(t *testing.T, r mapResolver, didStr string, seed byte) principal {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(types.DID(didStr), seed32(seed))
	if err != nil {
		t.Fatalf("signer %s: %v", didStr, err)
	}
	r[types.DID(didStr)] = did.NewDocument(types.DID(didStr), s.Public())
	return principal{signer: s}
}

// scenario holds a full valid human->org->agent->sub chain and its resolver.
type scenario struct {
	resolver mapResolver
	alice    principal // human (root issuer / trust anchor)
	acme     principal // org
	worker   principal // agent
	helper   principal // sub-agent
	chain    *Chain
}

func buildChain(t *testing.T) *scenario {
	t.Helper()
	r := mapResolver{}
	sc := &scenario{resolver: r}
	sc.alice = newPrincipal(t, r, "did:web:localhost:people:alice", 0x31)
	sc.acme = newPrincipal(t, r, "did:web:localhost:orgs:acme", 0x11)
	sc.worker = newPrincipal(t, r, "did:web:localhost:agents:worker", 0x33)
	sc.helper = newPrincipal(t, r, "did:web:localhost:agents:helper", 0x34)

	// One macaroon, progressively attenuated down the chain.
	base := macaroon.Mint(chainRootKey, "cred-chain-1", "did:web:localhost:people:alice")
	mOrg := mustAtt(t, base, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})
	mAgent := mustAtt(t, mOrg, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "1000"})
	mSub := mustAtt(t, mAgent, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "100"})

	sc.chain = &Chain{Links: []Link{
		mustLink(t, sc.alice.signer, "did:web:localhost:people:alice", "did:web:localhost:orgs:acme", mOrg, sc.acme.signer.Public()),
		mustLink(t, sc.acme.signer, "did:web:localhost:orgs:acme", "did:web:localhost:agents:worker", mAgent, sc.worker.signer.Public()),
		mustLink(t, sc.worker.signer, "did:web:localhost:agents:worker", "did:web:localhost:agents:helper", mSub, sc.helper.signer.Public()),
	}}
	return sc
}

func mustAtt(t *testing.T, m macaroon.Macaroon, c macaroon.Caveat) macaroon.Macaroon {
	t.Helper()
	out, err := macaroon.Attenuate(m, c)
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	return out
}

func mustLink(t *testing.T, issuer signer.Signer, issuerDID, subjectDID string, m macaroon.Macaroon, holderKey crypto.PublicKey) Link {
	t.Helper()
	c, err := credential.New(credential.Options{
		Subject:   types.DID(subjectDID),
		Issuer:    types.DID(issuerDID),
		Macaroon:  m,
		HolderKey: holderKey,
	})
	if err != nil {
		t.Fatalf("credential.New: %v", err)
	}
	proof, err := SignIssuance(issuer, c)
	if err != nil {
		t.Fatalf("SignIssuance: %v", err)
	}
	return Link{Credential: *c, IssuerProof: proof}
}

func TestVerify_ValidChain(t *testing.T) {
	sc := buildChain(t)
	if err := sc.chain.Verify(sc.resolver); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}

	// Human-readable reconstruction: anchor -> ... -> actor.
	want := []types.DID{
		"did:web:localhost:people:alice",
		"did:web:localhost:orgs:acme",
		"did:web:localhost:agents:worker",
		"did:web:localhost:agents:helper",
	}
	got := sc.chain.Principals()
	if len(got) != len(want) {
		t.Fatalf("Principals length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Principals[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if sc.chain.Root() != want[0] || sc.chain.Actor() != want[len(want)-1] {
		t.Fatalf("Root/Actor = %q/%q", sc.chain.Root(), sc.chain.Actor())
	}
}

func TestVerify_MarshalParseRoundTrip(t *testing.T) {
	sc := buildChain(t)
	data, err := sc.chain.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := got.Verify(sc.resolver); err != nil {
		t.Fatalf("chain should verify after round trip: %v", err)
	}
}

// TestVerify_BrokenHopFails: a tampered issuance signature fails at that hop.
func TestVerify_BrokenHopFails(t *testing.T) {
	sc := buildChain(t)
	sc.chain.Links[1].IssuerProof[0] ^= 0xff
	if err := sc.chain.Verify(sc.resolver); err == nil {
		t.Fatal("a tampered issuance signature must fail verification")
	}
}

// TestVerify_WrongIssuerFails: a credential signed by someone other than its
// stated issuer fails (the issuer's DID key won't verify it).
func TestVerify_WrongIssuerFails(t *testing.T) {
	sc := buildChain(t)
	// Re-sign hop 2's credential with the wrong principal (helper instead of
	// worker), then forcibly attach it despite the issuer mismatch.
	c := sc.chain.Links[2].Credential
	input, err := IssuanceInput(&c)
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := sc.helper.signer.Sign(input) // wrong signer
	if err != nil {
		t.Fatal(err)
	}
	sc.chain.Links[2].IssuerProof = badSig
	if err := sc.chain.Verify(sc.resolver); err == nil {
		t.Fatal("credential signed by the wrong issuer must fail")
	}
}

// TestVerify_ContinuityBrokenFails: a hop whose issuer is not the previous hop's
// subject fails, even if that issuer legitimately signed it.
func TestVerify_ContinuityBrokenFails(t *testing.T) {
	sc := buildChain(t)
	// Make hop 2 issued by acme (a real, resolvable principal) instead of worker
	// and re-sign with acme so the signature check passes, isolating continuity.
	c := sc.chain.Links[2].Credential
	c.Issuer = "did:web:localhost:orgs:acme"
	proof, err := SignIssuance(sc.acme.signer, &c)
	if err != nil {
		t.Fatal(err)
	}
	sc.chain.Links[2] = Link{Credential: c, IssuerProof: proof}
	if err := sc.chain.Verify(sc.resolver); err == nil {
		t.Fatal("broken continuity must fail even with a valid issuance signature")
	}
}

// TestVerify_NonSubsetAttenuationFails: a child macaroon that broadens the
// parent's authority fails the attenuation check, even with valid signatures.
func TestVerify_NonSubsetAttenuationFails(t *testing.T) {
	sc := buildChain(t)
	parentMac := sc.chain.Links[1].Credential.Macaroon

	// Hand-build a broadening child macaroon (Attenuate would refuse this):
	// append amount <= 5000 on top of the parent's amount <= 1000.
	bad := parentMac
	bad.Caveats = append(append([]macaroon.Caveat{}, parentMac.Caveats...),
		macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "5000"})

	c := sc.chain.Links[2].Credential
	c.Macaroon = bad
	proof, err := SignIssuance(sc.worker.signer, &c) // worker legitimately signs it
	if err != nil {
		t.Fatal(err)
	}
	sc.chain.Links[2] = Link{Credential: c, IssuerProof: proof}

	if err := sc.chain.Verify(sc.resolver); err == nil {
		t.Fatal("a non-subset (broadening) attenuation must fail verification")
	}
}

// TestVerify_SwappedHolderKeyFails: if the bound holder key is not the subject's
// published DID key, the hop fails.
func TestVerify_SwappedHolderKeyFails(t *testing.T) {
	sc := buildChain(t)
	// Swap hop 1's holder key to a stranger's, re-sign issuance so the signature
	// still matches the (tampered) credential, the DID-key mismatch must catch it.
	stranger, _ := signer.NewSoftwareSignerFromSeed("did:web:localhost:agents:stranger", seed32(0x77))
	c := sc.chain.Links[1].Credential
	c.HolderKey = did.PublicKeyToJWK(stranger.Public())
	proof, err := SignIssuance(sc.acme.signer, &c)
	if err != nil {
		t.Fatal(err)
	}
	sc.chain.Links[1] = Link{Credential: c, IssuerProof: proof}
	if err := sc.chain.Verify(sc.resolver); err == nil {
		t.Fatal("a holder key that is not the subject's DID key must fail")
	}
}

func TestVerify_EmptyChainFails(t *testing.T) {
	empty := &Chain{}
	if err := empty.Verify(mapResolver{}); err == nil {
		t.Fatal("empty chain should fail")
	}
}

// buildDeepChain builds a fully valid chain of exactly nHops (nHops+1
// principals): a root anchor delegating down a straight line of generated
// principals. Every hop carries the same macaroon, which trivially extends its
// parent, so the only property under test is depth.
func buildDeepChain(t *testing.T, nHops int) *scenario {
	t.Helper()
	r := mapResolver{}
	sc := &scenario{resolver: r}

	principals := make([]principal, nHops+1)
	dids := make([]string, nHops+1)
	for i := range principals {
		dids[i] = fmt.Sprintf("did:web:localhost:agents:p%d", i)
		principals[i] = newPrincipal(t, r, dids[i], byte(0x40+i))
	}

	// One macaroon with a single caveat, reused unchanged at every hop; an equal
	// caveat set extends the parent, so authority never broadens down the chain.
	m := mustAtt(t, macaroon.Mint(chainRootKey, "cred-deep-1", dids[0]),
		macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})

	links := make([]Link, nHops)
	for i := 0; i < nHops; i++ {
		links[i] = mustLink(t, principals[i].signer, dids[i], dids[i+1], m, principals[i+1].signer.Public())
	}
	sc.chain = &Chain{Links: links}
	return sc
}

// TestVerify_AtMaxDepthVerifies: a chain exactly at the cap is accepted, the
// cap rejects "one past", not the boundary itself.
func TestVerify_AtMaxDepthVerifies(t *testing.T) {
	sc := buildDeepChain(t, MaxDepth)
	if err := sc.chain.Verify(sc.resolver); err != nil {
		t.Fatalf("a chain of exactly MaxDepth (%d) hops must verify: %v", MaxDepth, err)
	}
}

// TestVerify_OverMaxDepthFails: a chain one hop past the cap is rejected at
// verification, even though every hop is individually valid. This is the
// verification half of the depth cap (the issuer enforces the other half).
func TestVerify_OverMaxDepthFails(t *testing.T) {
	sc := buildDeepChain(t, MaxDepth+1)
	err := sc.chain.Verify(sc.resolver)
	if err == nil {
		t.Fatalf("a chain of MaxDepth+1 (%d) hops must be rejected", MaxDepth+1)
	}
	if !strings.Contains(err.Error(), "max delegation depth") {
		t.Fatalf("rejection should name the depth cap, got: %v", err)
	}
}
