// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

func sw(t *testing.T, d string, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(types.DID(d), seed32(seed))
	if err != nil {
		t.Fatalf("signer %s: %v", d, err)
	}
	return s
}

// startSignerDaemon runs a signerd daemon brokering the given signers over a
// short-path Unix socket and returns the socket path (torn down on cleanup).
func startSignerDaemon(t *testing.T, signers ...signer.Signer) string {
	t.Helper()
	m := map[types.DID]signer.Signer{}
	for _, s := range signers {
		m[s.DID()] = s
	}
	dir, err := os.MkdirTemp("/tmp", "ks")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = signerd.New(m).Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return sock
}

// TestDaemonBrokeredAgent_EndToEnd is B3's closing-the-loop proof: the actor's
// proof-of-possession AND the human's approval are both produced by keys the
// on-device daemon holds — the agent side only ever holds a socket-backed
// signer.Signer, never a private key — and the real proxy + independent verifier
// accept the result. This is §2a's "ensure agent requests are funnelled through
// it" demonstrated against the actual enforcement path.
func TestDaemonBrokeredAgent_EndToEnd(t *testing.T) {
	r := memResolver{}
	reg := func(s signer.Signer) { r[s.DID()] = did.NewDocument(s.DID(), s.Public()) }

	alice := sw(t, "did:web:localhost:people:alice", 0x31)   // human (root issuer + approver)
	acme := sw(t, "did:web:localhost:orgs:acme", 0x11)       // org
	worker := sw(t, "did:web:localhost:agents:worker", 0x33) // employee/agent (terminal)
	proxyEP := sw(t, "did:web:localhost:proxies:gatekeeper", 0x55)
	reg(alice)
	reg(acme)
	reg(worker)
	reg(proxyEP)

	// The daemon holds the two keys the agent needs at RUN time: the actor key
	// (PoP) and the human key (approval). Issuance is a setup step, done with the
	// raw signers directly.
	sock := startSignerDaemon(t, worker, alice)

	base := macaroon.Mint(seed32(0x01), "cred-daemon-e2e", string(alice.DID()))
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

	// The AGENT side: obtain the actor and approver signers from the daemon only —
	// no keystore, no private keys in this process.
	actor, err := signerd.Dial(sock, worker.DID())
	if err != nil {
		t.Fatalf("dial daemon (actor): %v", err)
	}
	approver, err := signerd.Dial(sock, alice.DID())
	if err != nil {
		t.Fatalf("dial daemon (approver): %v", err)
	}

	a := action("100") // consequential: needs status + human approval
	terminal := &ch.Links[len(ch.Links)-1].Credential
	tip := px.Tip()
	pop, err := terminal.ProvePossession(actor, []byte("nonce-daemon"), a, tip.Seq, tip.PrevHash)
	if err != nil {
		t.Fatalf("ProvePossession via daemon: %v", err)
	}
	appr, err := audit.SignApproval(approver, terminal.Subject, a, tip.Seq, tip.PrevHash)
	if err != nil {
		t.Fatalf("SignApproval via daemon: %v", err)
	}

	res, err := px.Handle(Request{Chain: ch, Action: a, PoP: pop, Approver: approver.DID(), Approval: appr})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential {
		t.Fatalf("expected consequential allow via daemon-brokered keys, got %+v", res.Decision)
	}

	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	v, err := export.Verify(exp, export.Inputs{DIDs: r, Status: statuses})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Pass() {
		t.Fatalf("independent verifier rejected a daemon-brokered export: %s", v.Entries[0].Reason)
	}
}
