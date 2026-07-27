// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"fmt"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// memResolver is an in-memory did.Resolver, so this end-to-end test needs no
// fixture files and can register P-256 principals the testdata fixtures do not
// carry.
type memResolver map[types.DID]*did.Document

func (m memResolver) Resolve(d types.DID) (*did.Document, error) {
	doc, ok := m[d]
	if !ok {
		return nil, fmt.Errorf("no DID document for %s", d)
	}
	return doc, nil
}

// TestP256EmployeeAndApprover_EndToEnd (R3-04) is the offline-verifier-level proof
// of the scoped-P-256 decision. It drives a full CONSEQUENTIAL allow through the
// real Proxy.Handle and then re-derives it with the independent verifier
// (export.Verify), with the human (root issuer AND approver) key and the
// employee/terminal key BOTH P-256 and every org/proxy/status key Ed25519. So one
// pass exercises, through the actual proxy->export->verifier pipeline:
//   - P-256 issuance signature (alice -> acme, root hop),
//   - P-256 proof-of-possession (worker terminal),
//   - P-256 human approval (alice),
//
// alongside the unchanged Ed25519 envelope and status-list signatures. The library
// paths are unit-tested elsewhere; this proves the binary's whole trust story
// re-derives for a P-256 employee, which is the gap the R3 review flagged.
func TestP256EmployeeAndApprover_EndToEnd(t *testing.T) {
	r := memResolver{}
	reg := func(s signer.Signer) { r[s.DID()] = did.NewDocument(s.DID(), s.Public()) }

	alice, err := signer.NewECDSASigner("did:web:localhost:people:alice") // human: P-256
	if err != nil {
		t.Fatal(err)
	}
	worker, err := signer.NewECDSASigner("did:web:localhost:agents:worker") // employee/device: P-256
	if err != nil {
		t.Fatal(err)
	}
	acme, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:orgs:acme", seed32(0x11)) // org: Ed25519
	if err != nil {
		t.Fatal(err)
	}
	proxyEP, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:proxies:gatekeeper", seed32(0x55)) // EP: Ed25519
	if err != nil {
		t.Fatal(err)
	}
	reg(alice)
	reg(worker)
	reg(acme)
	reg(proxyEP)

	// Delegation: alice (P-256) -> acme (Ed25519) -> worker (P-256).
	base := macaroon.Mint(seed32(0x01), "cred-p256-e2e", string(alice.DID()))
	mAcme := att(t, base, "action.type", "==", "payment.transfer")
	mWorker := att(t, mAcme, "amount", "<=", "100")

	mk := func(subject, issuer signer.Signer, m macaroon.Macaroon, ref status.Reference) chain.Link {
		c, err := credential.New(credential.Options{
			Subject: subject.DID(), Issuer: issuer.DID(), Macaroon: m, StatusRef: ref, HolderKey: subject.Public(),
		})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := chain.SignIssuance(issuer, c)
		if err != nil {
			t.Fatal(err)
		}
		return chain.Link{Credential: *c, IssuerProof: proof}
	}
	ch := &chain.Chain{Links: []chain.Link{
		mk(acme, alice, mAcme, status.Reference{}),
		mk(worker, acme, mWorker, status.Reference{ListURL: acmeListURL, Index: 42}),
	}}

	// Acme publishes an all-clear status list (Ed25519-signed, unchanged path).
	list := status.New(status.MinBits)
	if err := list.Sign(acme); err != nil {
		t.Fatal(err)
	}
	statuses := export.MapStatusResolver{acmeListURL: list}

	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{EnforcementPoint: proxyEP, Policy: pol, DIDs: r, Status: statuses})
	if err != nil {
		t.Fatal(err)
	}

	a := action("100") // at/above threshold -> consequential: needs status + human approval
	terminal := &ch.Links[len(ch.Links)-1].Credential

	tip := px.Tip()
	pop, err := terminal.ProvePossession(worker, []byte("nonce-e2e"), a, tip.Seq, tip.PrevHash) // P-256 PoP
	if err != nil {
		t.Fatal(err)
	}
	appr, err := audit.SignApproval(alice, terminal.Subject, a, tip.Seq, tip.PrevHash) // P-256 approval
	if err != nil {
		t.Fatal(err)
	}
	res, err := px.Handle(Request{Chain: ch, Action: a, PoP: pop, Approver: alice.DID(), Approval: appr})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential {
		t.Fatalf("expected consequential allow, got %+v", res.Decision)
	}

	// The independent verifier re-derives every P-256 signature and must PASS.
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	v, err := export.Verify(exp, export.Inputs{DIDs: r, Status: statuses})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Pass() {
		t.Fatalf("independent verifier rejected a valid all-P-256-human export: %s", v.Entries[0].Reason)
	}
	if v.Entries[0].Outcome != export.OutcomePass {
		t.Fatalf("entry outcome = %q, want %q", v.Entries[0].Outcome, export.OutcomePass)
	}

	// Negative, same pipeline: a PoP from a DIFFERENT P-256 key must be denied, so
	// the pass above is not the verifier accepting any P-256 signature vacuously.
	impostor, err := signer.NewECDSASigner("did:web:localhost:agents:impostor")
	if err != nil {
		t.Fatal(err)
	}
	tip2 := px.Tip()
	badPoP, err := terminal.ProvePossession(impostor, []byte("nonce-2"), a, tip2.Seq, tip2.PrevHash)
	if err != nil {
		t.Fatal(err)
	}
	badAppr, err := audit.SignApproval(alice, terminal.Subject, a, tip2.Seq, tip2.PrevHash)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := px.Handle(Request{Chain: ch, Action: a, PoP: badPoP, Approver: alice.DID(), Approval: badAppr})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Decision.Allowed {
		t.Fatal("a P-256 PoP from a non-bound key must be denied by the real pipeline")
	}
}
