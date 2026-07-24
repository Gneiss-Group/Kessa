// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"strings"
	"testing"
	"time"

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

const (
	didsRoot     = "../../testdata/dids"
	commercePol  = "../../examples/policies/commerce-security.json"
	acmeListURL  = "https://localhost/orgs/acme/status.json"
	macRootKeyHx = "00112233445566778899aabbccddeeff"

	didAlice  = "did:web:localhost:people:alice"
	didAcme   = "did:web:localhost:orgs:acme"
	didWorker = "did:web:localhost:agents:worker"
	didHelper = "did:web:localhost:agents:helper"
	didProxy  = "did:web:localhost:proxies:gatekeeper"
)

var (
	fixedTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	seeds     = map[types.DID]byte{
		didAlice: 0x31, didAcme: 0x11, didWorker: 0x33, didHelper: 0x34, didProxy: 0x55,
	}
)

func seed32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func sign(t *testing.T, d types.DID) signer.Signer {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(d, seed32(seeds[d]))
	if err != nil {
		t.Fatalf("signer %s: %v", d, err)
	}
	return s
}

// harness holds a built chain, a status list, and the pieces to drive the proxy.
type harness struct {
	chain    *chain.Chain
	list     *status.StatusList
	resolver did.Resolver
	statuses export.StatusResolver
	acme     signer.Signer
}

// build mints the alice->acme->worker->helper chain with amount<=100 at the
// worker hop and a StatusRef at index 42, matching the issuer example.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		resolver: did.FileResolver{Root: didsRoot},
		acme:     sign(t, didAcme),
	}

	base := macaroon.Mint(seed32(0x01), "cred-proxy-1", didAlice)
	mAcme := att(t, base, "action.type", "==", "payment.transfer")
	mWorker := att(t, mAcme, "amount", "<=", "100")
	mHelper := att(t, mWorker, "target", "==", "acct/999")

	mk := func(subject, issuer types.DID, m macaroon.Macaroon, ref status.Reference) chain.Link {
		holder := sign(t, subject)
		c, err := credential.New(credential.Options{Subject: subject, Issuer: issuer, Macaroon: m, StatusRef: ref, HolderKey: holder.Public()})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := chain.SignIssuance(sign(t, issuer), c)
		if err != nil {
			t.Fatal(err)
		}
		return chain.Link{Credential: *c, IssuerProof: proof}
	}

	h.chain = &chain.Chain{Links: []chain.Link{
		mk(didAcme, didAlice, mAcme, status.Reference{}),
		mk(didWorker, didAcme, mWorker, status.Reference{ListURL: acmeListURL, Index: 42}),
		mk(didHelper, didWorker, mHelper, status.Reference{}),
	}}

	h.list = status.New(status.MinBits)
	if err := h.list.Sign(h.acme); err != nil {
		t.Fatal(err)
	}
	h.statuses = export.MapStatusResolver{acmeListURL: h.list}
	return h
}

func att(t *testing.T, m macaroon.Macaroon, field, op, value string) macaroon.Macaroon {
	t.Helper()
	out, err := macaroon.Attenuate(m, macaroon.Caveat{Field: field, Op: macaroon.Op(op), Value: value})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *harness) proxy(t *testing.T) *Proxy {
	t.Helper()
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{
		EnforcementPoint: sign(t, didProxy),
		Policy:           pol,
		DIDs:             h.resolver,
		Status:           h.statuses,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return px
}

// tip0 is the position of the first entry in a fresh log: seq 0, linking to the
// genesis hash. Every test here appends a single entry, so this is the slot its
// evidence binds to.
var tip0 = Tip{Seq: 0, PrevHash: audit.GenesisHash}

// pop and approval bind to a tip: the Seq AND PrevHash of the position the entry
// being built will occupy (F4, R2-04). Taking a whole Tip rather than a bare seq
// is deliberate, it mirrors what cmd/agent does with GET /tip, so a test cannot
// accidentally bind to a slot the real client could not have bound to.
func (h *harness) pop(t *testing.T, tip Tip, action types.Action, nonce string) credential.PoP {
	t.Helper()
	terminal := &h.chain.Links[len(h.chain.Links)-1].Credential
	pop, err := terminal.ProvePossession(sign(t, terminal.Subject), []byte(nonce), action, tip.Seq, tip.PrevHash)
	if err != nil {
		t.Fatal(err)
	}
	return pop
}

func (h *harness) approval(t *testing.T, tip Tip, approver types.DID, action types.Action) []byte {
	t.Helper()
	terminal := &h.chain.Links[len(h.chain.Links)-1].Credential
	sig, err := audit.SignApproval(sign(t, approver), terminal.Subject, action, tip.Seq, tip.PrevHash)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func action(amount string) types.Action {
	return types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": amount}, Timestamp: fixedTime}
}

// verifyExport runs the independent verifier over a proxy's export.
func (h *harness) verify(t *testing.T, px *Proxy) *export.Result {
	t.Helper()
	exp, err := px.Export()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res, err := export.Verify(exp, export.Inputs{DIDs: h.resolver, Status: h.statuses})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// ---- the happy paths -------------------------------------------------------

func TestRoutineAllow(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("10") // below the $100 consequentiality threshold
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n1")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || res.Decision.Consequential {
		t.Fatalf("expected routine allow, got %+v", res.Decision)
	}
	// And the independent verifier agrees.
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed: %s", v.Entries[0].Reason)
	}
}

func TestConsequentialAllow_WithStatusAndApproval(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("100") // at the threshold -> consequential
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n2"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential || res.Decision.StatusCheckedHops != 1 {
		t.Fatalf("expected consequential allow with status checked, got %+v", res.Decision)
	}
	if res.Entry.ApprovedBy != didAlice || len(res.Entry.Approval) == 0 {
		t.Fatal("approval should be recorded in the entry")
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed: %s", v.Entries[0].Reason)
	}
}

// ---- the denials the proxy must produce ------------------------------------

func TestScopeViolationDenied(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("500") // exceeds the attenuated $100 ceiling
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n3"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("a $500 action against a $100 ceiling must be denied")
	}
	if !strings.Contains(res.Decision.Reason, "exceeds delegated authority") {
		t.Fatalf("unexpected reason: %q", res.Decision.Reason)
	}
	// The denial has intact evidence, so the verifier PASSes the entry as a deny.
	v := h.verify(t, px)
	if !v.Pass() || v.Entries[0].Outcome != export.OutcomePassDeny {
		t.Fatalf("deny should verify as PASS/DENY, got %q: %s", v.Entries[0].Outcome, v.Entries[0].Reason)
	}
}

func TestConsequentialWithoutApprovalDenied(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("100")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n4")}) // no approver
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("a consequential action without approval must be denied")
	}
	if !strings.Contains(res.Decision.Reason, "human approval") {
		t.Fatalf("reason should cite missing approval: %q", res.Decision.Reason)
	}
}

func TestForgedApprovalDenied(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("100")
	// helper (the actor) tries to self-approve instead of a human.
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n5"),
		Approver: didAlice, Approval: h.approval(t, tip0, didHelper, a), // signed by the wrong key
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("an approval not signed by the named approver must be denied")
	}
}

func TestTokenLoanDenied(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("10")
	// A thief holds the credential blob but signs the PoP with their own key.
	terminal := &h.chain.Links[len(h.chain.Links)-1].Credential
	stranger, _ := signer.NewSoftwareSignerFromSeed("did:web:localhost:agents:stranger", seed32(0x77))
	badPoP, err := terminal.ProvePossession(stranger, []byte("n6"), a, 0, audit.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: badPoP})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("a copied credential without the private key must fail PoP")
	}
	if !strings.Contains(res.Decision.Reason, "possession") {
		t.Fatalf("reason should cite possession: %q", res.Decision.Reason)
	}
}

func TestRevokedHopDenied(t *testing.T) {
	h := newHarness(t)
	if err := h.list.Set(42, true); err != nil { // revoke the worker hop
		t.Fatal(err)
	}
	if err := h.list.Sign(h.acme); err != nil {
		t.Fatal(err)
	}
	px := h.proxy(t)
	a := action("100")
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n7"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("a consequential action on a revoked credential must be denied")
	}
	if res.Decision.StatusCheckedHops != 1 || !strings.Contains(res.Decision.Reason, "revoked") {
		t.Fatalf("expected a status-checked revocation denial, got %+v", res.Decision)
	}
}

func TestPolicyHardDenyNeverConsultsAuthority(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	// forbidden-wire is a policy deny; the caveats would be irrelevant.
	a := types.Action{Type: "payment.wire", Target: "acct/999", Attributes: map[string]string{"amount": "1"}, Timestamp: fixedTime}
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n8")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed || res.Decision.RuleFired != "forbidden-wire" {
		t.Fatalf("expected a policy hard-deny, got %+v", res.Decision)
	}
}

// ---- unattributable requests are rejected, NOT logged ----------------------

func TestUnverifiableChainRejectedNotLogged(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	// Corrupt an issuance proof so the chain no longer verifies.
	bad := *h.chain
	bad.Links = append([]chain.Link(nil), h.chain.Links...)
	bad.Links[1].IssuerProof = append([]byte(nil), bad.Links[1].IssuerProof...)
	bad.Links[1].IssuerProof[0] ^= 0xff

	a := action("10")
	_, err := px.Handle(Request{Chain: &bad, Action: a, PoP: h.pop(t, tip0, a, "n9")})
	if err == nil {
		t.Fatal("an unverifiable chain must be rejected")
	}
	// Nothing was logged: the export has no entries.
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(exp.Entries); n != 0 {
		t.Fatalf("a rejected request must not be logged; got %d entries", n)
	}
}

func TestEmptyChainRejected(t *testing.T) {
	px := newHarness(t).proxy(t)
	if _, err := px.Handle(Request{Chain: &chain.Chain{}, Action: action("1")}); err == nil {
		t.Fatal("empty chain must be rejected")
	}
	if _, err := px.Handle(Request{Action: action("1")}); err == nil {
		t.Fatal("nil chain must be rejected")
	}
}

// ---- THE point of the verifier: a lying proxy is caught --------------------

// TestLyingProxyIsCaughtByVerifier builds, by hand, the entry a naive or
// malicious enforcement point would write: Allowed:true with no real check
// behind it. This is the exact thing the whole system exists to catch, and the
// independent verifier must REJECT the export it produces.
func TestLyingProxyIsCaughtByVerifier(t *testing.T) {
	cases := []struct {
		name   string
		action types.Action
		nonce  string
		// omit* simulate specific corner-cuts a broken proxy might take.
		withApproval bool
		badPoP       bool
		wantReason   string
	}{
		{
			name: "allowed a scope violation", action: action("5000"), nonce: "b1",
			withApproval: true, wantReason: "exceeds the delegated authority",
		},
		{
			name: "allowed a consequential action with no PoP", action: action("100"), nonce: "b2",
			withApproval: true, badPoP: true, wantReason: "possession",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			pol, err := policy.Load(commercePol)
			if err != nil {
				t.Fatal(err)
			}
			polID, err := export.PolicyID(pol)
			if err != nil {
				t.Fatal(err)
			}
			// Build the entry BY HAND with Allowed:true, bypassing decide(). It
			// carries a valid policy + PolicyID so it clears the F1 re-derivation
			// and is caught by the specific check the corner-cut broke.
			log := audit.NewLog(sign(t, didProxy))
			set := export.NewCredentialSet()
			var ids []string
			for _, l := range h.chain.Links {
				id, _ := set.Add(l.Credential, l.IssuerProof)
				ids = append(ids, id)
			}
			terminal := &h.chain.Links[len(h.chain.Links)-1].Credential

			pop := h.pop(t, tip0, tc.action, tc.nonce)
			if tc.badPoP {
				stranger, _ := signer.NewSoftwareSignerFromSeed("did:web:localhost:x:stranger", seed32(0x66))
				pop, _ = terminal.ProvePossession(stranger, []byte(tc.nonce), tc.action, 0, audit.GenesisHash)
			}
			// The lying proxy is careful: it stamps the attribution fields the
			// policy really would have produced, so the entry clears the F1
			// consequentiality re-derivation and the R2-07 rule/version
			// re-derivation, and is caught by the specific corner it cut.
			derived, err := pol.Evaluate(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			rec := audit.Record{
				Action: tc.action, ResolvedChain: h.chain.Principals(), ChainCredentialIDs: ids, PolicyID: polID,
				Decision: types.Decision{Allowed: true, Consequential: true, StatusCheckedHops: 1,
					RuleFired: derived.RuleFired, PolicyVersion: derived.PolicyVersion, Reason: "trust me"},
				PoPNonce: pop.Nonce, PoPSignature: pop.Signature, Timestamp: fixedTime,
			}
			if tc.withApproval {
				rec.ApprovedBy = didAlice
				rec.Approval = h.approval(t, tip0, didAlice, tc.action)
			}
			if _, err := log.Append(rec); err != nil {
				t.Fatal(err)
			}
			exp, err := export.Build(sign(t, didProxy), log.Entries(), set, pol)
			if err != nil {
				t.Fatal(err)
			}

			res, err := export.Verify(exp, export.Inputs{DIDs: h.resolver, Status: h.statuses})
			if err != nil {
				t.Fatal(err)
			}
			if res.Pass() {
				t.Fatal("the verifier must NOT pass a lying proxy's allow")
			}
			if r := res.Entries[0].Reason; !strings.Contains(r, tc.wantReason) {
				t.Fatalf("failure reason %q should mention %q", r, tc.wantReason)
			}
		})
	}
}

// ---- determinism -----------------------------------------------------------

func TestProxyExportIsDeterministic(t *testing.T) {
	run := func() []byte {
		h := newHarness(t)
		px := h.proxy(t)
		a := action("100")
		if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "d1"),
			Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a)}); err != nil {
			t.Fatal(err)
		}
		exp, err := px.Export()
		if err != nil {
			t.Fatal(err)
		}
		b, err := exp.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if string(run()) != string(run()) {
		t.Fatal("two identical proxy runs produced different exports")
	}
}
