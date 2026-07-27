// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// newECDSAPrincipal registers a principal whose key is a P-256 (hardware-style)
// key, the shape the employee/device key takes. It reuses the shared mapResolver
// and principal scaffolding from chain_test.go.
func newECDSAPrincipal(t *testing.T, r mapResolver, didStr string) principal {
	t.Helper()
	s, err := signer.NewECDSASigner(types.DID(didStr))
	if err != nil {
		t.Fatalf("ecdsa signer %s: %v", didStr, err)
	}
	r[types.DID(didStr)] = did.NewDocument(types.DID(didStr), s.Public())
	return principal{signer: s}
}

// TestVerify_ScopedP256EmployeeKey is the end-to-end proof of the scoped-P-256
// decision: an all-Ed25519 issuance path (human -> org) delegates to an
// employee/agent whose device key is P-256. The role-blind verify loop must
// accept the mixed-algorithm chain, tie the P-256 holder key to the subject's
// P-256 DID key, and proof-of-possession must verify under P-256, all without any
// per-role or per-algorithm special-casing above signer.Verify.
func TestVerify_ScopedP256EmployeeKey(t *testing.T) {
	r := mapResolver{}
	alice := newPrincipal(t, r, "did:web:localhost:people:alice", 0x31)  // human, Ed25519
	acme := newPrincipal(t, r, "did:web:localhost:orgs:acme", 0x11)      // org, Ed25519
	worker := newECDSAPrincipal(t, r, "did:web:localhost:agents:worker") // employee/device, P-256

	base := macaroon.Mint(chainRootKey, "cred-p256-1", "did:web:localhost:people:alice")
	mOrg := mustAtt(t, base, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})
	mAgent := mustAtt(t, mOrg, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "1000"})

	ch := &Chain{Links: []Link{
		mustLink(t, alice.signer, "did:web:localhost:people:alice", "did:web:localhost:orgs:acme", mOrg, acme.signer.Public()),
		mustLink(t, acme.signer, "did:web:localhost:orgs:acme", "did:web:localhost:agents:worker", mAgent, worker.signer.Public()),
	}}

	if err := ch.Verify(r); err != nil {
		t.Fatalf("mixed Ed25519(org)/P-256(employee) chain must verify: %v", err)
	}

	// Proof-of-possession under the P-256 holder key, bound to a chain position.
	terminal := &ch.Links[len(ch.Links)-1].Credential
	action := types.Action{Type: "payment.transfer", Target: "acct/1", Timestamp: time.Unix(0, 0).UTC()}
	prevHash := make([]byte, 32)
	pop, err := terminal.ProvePossession(worker.signer, []byte("nonce-1"), action, 0, prevHash)
	if err != nil {
		t.Fatalf("ProvePossession (P-256): %v", err)
	}
	if err := terminal.VerifyPossession(pop, action, 0, prevHash); err != nil {
		t.Fatalf("VerifyPossession (P-256) must succeed for the true holder: %v", err)
	}

	// A different holder (even another P-256 key) must fail PoP: the credential is
	// bound to worker's key, and possession is the at-use-time check of that.
	impostor := newECDSAPrincipal(t, r, "did:web:localhost:agents:impostor")
	badPoP, err := terminal.ProvePossession(impostor.signer, []byte("nonce-1"), action, 0, prevHash)
	if err != nil {
		t.Fatalf("ProvePossession (impostor): %v", err)
	}
	if err := terminal.VerifyPossession(badPoP, action, 0, prevHash); err == nil {
		t.Fatal("PoP by a non-bound P-256 key must fail")
	}
}

// TestVerify_P256HolderKeyMustMatchSubjectDID guards the holder-binding check
// across algorithms: a credential presenting a P-256 holder key that differs
// from the subject's published (P-256) DID key must be rejected, the same way an
// Ed25519 mismatch is.
func TestVerify_P256HolderKeyMustMatchSubjectDID(t *testing.T) {
	r := mapResolver{}
	acme := newPrincipal(t, r, "did:web:localhost:orgs:acme", 0x11)
	worker := newECDSAPrincipal(t, r, "did:web:localhost:agents:worker")
	stranger, err := signer.NewECDSASigner("did:web:localhost:agents:stranger")
	if err != nil {
		t.Fatalf("stranger signer: %v", err)
	}

	base := macaroon.Mint(chainRootKey, "cred-p256-2", "did:web:localhost:orgs:acme")
	mAgent := mustAtt(t, base, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})

	// Mint a credential whose bound holder key is the stranger's, not worker's,
	// then re-sign issuance so only the DID-key mismatch (not a broken signature)
	// can catch it.
	c, err := credential.New(credential.Options{
		Subject:   "did:web:localhost:agents:worker",
		Issuer:    "did:web:localhost:orgs:acme",
		Macaroon:  mAgent,
		HolderKey: stranger.Public(),
	})
	if err != nil {
		t.Fatalf("credential.New: %v", err)
	}
	proof, err := SignIssuance(acme.signer, c)
	if err != nil {
		t.Fatalf("SignIssuance: %v", err)
	}
	_ = worker // worker's DID doc is what the subject resolves to; the holder key won't match it

	ch := &Chain{Links: []Link{{Credential: *c, IssuerProof: proof}}}
	if err := ch.Verify(r); err == nil {
		t.Fatal("a P-256 holder key that differs from the subject's DID key must be rejected")
	}
}
