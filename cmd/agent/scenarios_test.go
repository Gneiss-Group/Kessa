// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// These are spec §6 scenarios 1-5, driven end to end through the AGENT's path:
// buildRequest (proof-of-possession + approval) and enforce.Submit over a real
// localhost HTTP server. The enforcement engine underneath is the same one the
// proxy serves and the verifier mirrors.

const (
	didsRoot    = "../../testdata/dids"
	commercePol = "../../examples/policies/commerce-security.json"
	legalPol    = "../../examples/policies/legal-ediscovery.json"
	acmeListURL = "https://localhost/orgs/acme/status.json"

	didAlice  = "did:web:localhost:people:alice"
	didAcme   = "did:web:localhost:orgs:acme"  // Org A
	didBravo  = "did:web:localhost:orgs:bravo" // Org B (operates its own proxy)
	didWorker = "did:web:localhost:agents:worker"
	didHelper = "did:web:localhost:agents:helper"
	didProxy  = "did:web:localhost:proxies:gatekeeper"

	workerStatusIdx = 42
)

var (
	fixedTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	seeds     = map[types.DID]byte{
		didAlice: 0x31, didAcme: 0x11, didBravo: 0x22, didWorker: 0x33, didHelper: 0x34, didProxy: 0x55,
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

// world holds a live proxy behind an HTTP server, the credential chain the agent
// holds, and the status list (so a scenario can revoke).
type world struct {
	srv   *httptest.Server
	chain *chain.Chain
	list  *status.StatusList
	acme  signer.Signer
	dids  did.Resolver
	stat  export.StatusResolver
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{dids: did.FileResolver{Root: didsRoot}, acme: sign(t, didAcme)}

	att := func(m macaroon.Macaroon, field, op, val string) macaroon.Macaroon {
		out, err := macaroon.Attenuate(m, macaroon.Caveat{Field: field, Op: macaroon.Op(op), Value: val})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	base := macaroon.Mint(seed32(0x01), "cred-agent-1", didAlice)
	mAcme := att(base, "action.type", "==", "payment.transfer")
	mWorker := att(mAcme, "amount", "<=", "100")
	mHelper := att(mWorker, "target", "==", "acct/999")

	link := func(subject, issuer types.DID, m macaroon.Macaroon, ref status.Reference) chain.Link {
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
	w.chain = &chain.Chain{Links: []chain.Link{
		link(didAcme, didAlice, mAcme, status.Reference{}),
		link(didWorker, didAcme, mWorker, status.Reference{ListURL: acmeListURL, Index: workerStatusIdx}),
		link(didHelper, didWorker, mHelper, status.Reference{}),
	}}

	w.list = status.New(status.MinBits)
	if err := w.list.Sign(w.acme); err != nil {
		t.Fatal(err)
	}
	w.stat = export.MapStatusResolver{acmeListURL: w.list}

	// The default proxy: Org A's own, commerce policy, gatekeeper enforcement.
	w.srv = w.proxyServer(t, commercePol, didProxy)
	return w
}

// proxyServer stands up an enforcement proxy behind an HTTP server, with a given
// policy and enforcement-point DID, over the SAME chain/dids/status. Used to run
// a second org's proxy (a different vertical, a different enforcement key) with
// no shared configuration beyond the public DID documents.
func (w *world) proxyServer(t *testing.T, policyPath string, ep types.DID) *httptest.Server {
	t.Helper()
	pol, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	px, err := enforce.NewProxy(enforce.Config{
		EnforcementPoint: sign(t, ep),
		Policy:           pol,
		DIDs:             w.dids,
		Status:           w.stat,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(enforce.Handler(px))
	t.Cleanup(srv.Close)
	return srv
}

// revoke flips the worker credential's bit and re-signs the published list.
func (w *world) revoke(t *testing.T) {
	t.Helper()
	if err := w.list.Set(workerStatusIdx, true); err != nil {
		t.Fatal(err)
	}
	if err := w.list.Sign(w.acme); err != nil {
		t.Fatal(err)
	}
}

func act(amount string) types.Action {
	return types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": amount}, Timestamp: fixedTime}
}

// attempt is exactly what the CLI does: build a request as `actor` (optionally
// approved by `approver`) and submit it over HTTP to Org A's default proxy.
func (w *world) attempt(t *testing.T, actor types.DID, approver types.DID, a types.Action, nonce string) (*enforce.Result, error) {
	return w.attemptTo(t, w.srv, actor, approver, a, nonce)
}

func (w *world) attemptTo(t *testing.T, srv *httptest.Server, actor types.DID, approver types.DID, a types.Action, nonce string) (*enforce.Result, error) {
	t.Helper()
	var approverSigner signer.Signer
	if approver != "" {
		approverSigner = sign(t, approver)
	}
	// Fetch the slot this entry will occupy so the PoP/approval bind to it (F4).
	tip, err := enforce.FetchTip(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := buildRequest(w.chain, sign(t, actor), approverSigner, a, nonce, tip)
	if err != nil {
		t.Fatal(err)
	}
	return enforce.Submit(srv.Client(), srv.URL, req)
}

func mustAllow(t *testing.T, res *enforce.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected ALLOW, got transport error: %v", err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("expected ALLOW, got DENY: %s", res.Decision.Reason)
	}
}

func mustDeny(t *testing.T, res *enforce.Result, err error, wantReason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected a logged DENY, got transport error: %v", err)
	}
	if res.Decision.Allowed {
		t.Fatal("expected DENY, got ALLOW")
	}
	if wantReason != "" && !contains(res.Decision.Reason, wantReason) {
		t.Fatalf("deny reason %q should mention %q", res.Decision.Reason, wantReason)
	}
}

// Scenario 1, happy path: below-threshold action, allowed and logged.
func TestScenario1_HappyPath(t *testing.T) {
	w := newWorld(t)
	res, err := w.attempt(t, didHelper, "", act("10"), "s1")
	mustAllow(t, res, err)
	w.verifyClean(t)
}

// Scenario 2, scope violation: $500 against the attenuated $100 ceiling.
func TestScenario2_ScopeViolation(t *testing.T) {
	w := newWorld(t)
	res, err := w.attempt(t, didHelper, didAlice, act("500"), "s2")
	mustDeny(t, res, err, "exceeds delegated authority")
	w.verifyClean(t) // the deny is logged with intact evidence
}

// Scenario 3, consequential + HITL: above threshold needs human approval.
func TestScenario3_ConsequentialRequiresApproval(t *testing.T) {
	w := newWorld(t)
	// Without approval: denied.
	res, err := w.attempt(t, didHelper, "", act("100"), "s3a")
	mustDeny(t, res, err, "human approval")

	// With alice's approval: allowed, and the approval is in the entry.
	w2 := newWorld(t)
	res, err = w2.attempt(t, didHelper, didAlice, act("100"), "s3b")
	mustAllow(t, res, err)
	if res.Entry.ApprovedBy != didAlice || len(res.Entry.Approval) == 0 {
		t.Fatal("approval should be recorded in the audit entry")
	}
	w2.verifyClean(t)
}

// Scenario 4, revocation propagation: after revoking the worker credential, a
// routine action still rides its cached decision, but the next consequential
// action forces a live check and is blocked. The honest propagation boundary.
func TestScenario4_RevocationPropagation(t *testing.T) {
	w := newWorld(t)
	w.revoke(t)

	// Routine (non-consequential) action: no live status check, still allowed.
	res0, err0 := w.attempt(t, didHelper, "", act("10"), "s4-routine")
	mustAllow(t, res0, err0)

	// Consequential action: live check catches the revocation, blocked.
	res, err := w.attempt(t, didHelper, didAlice, act("100"), "s4-conseq")
	mustDeny(t, res, err, "revoked")
}

// Scenario 5, token loan: a copied credential blob in the hands of a principal
// without the holder's private key cannot answer the proof-of-possession
// challenge. The chain itself is valid; only the key is missing.
func TestScenario5_TokenLoan(t *testing.T) {
	w := newWorld(t)
	// A stranger holds the (valid) chain but signs PoP with their own key.
	stranger := types.DID("did:web:localhost:agents:stranger")
	seeds[stranger] = 0x77
	res, err := w.attempt(t, stranger, "", act("10"), "s5")
	mustDeny(t, res, err, "possession")
}

// Scenario 6, cross-org and cross-vertical trust. An agent credentialed by
// Org A presents its chain to a proxy operated by Org B, which has NO shared
// configuration with A: B trusts the chain solely by resolving A's published DID
// documents. And because B runs a different vertical's policy, the SAME action
// gets a different consequentiality verdict, the framework is vertical-neutral.
func TestScenario6_CrossOrgCrossVertical(t *testing.T) {
	w := newWorld(t)

	// Org B operates its own proxy: bravo enforcement key, the legal-ediscovery
	// policy, a different vertical from Org A's commerce policy.
	orgB := w.proxyServer(t, legalPol, didBravo)

	a := act("100") // $100 transfer

	// Org A (commerce): $100 is consequential -> requires human approval. Without
	// one, denied.
	resA, errA := w.attempt(t, didHelper, "", a, "s6-a")
	mustDeny(t, resA, errA, "human approval")

	// Org B (legal): the same action, same chain, NO shared config with A. B
	// resolves acme's published DID document to trust the chain, and under the
	// legal policy a payment.transfer matches no rule -> routine -> allowed
	// without approval. Cross-org trust AND cross-vertical neutrality in one shot.
	resB, errB := w.attemptTo(t, orgB, didHelper, "", a, "s6-b")
	mustAllow(t, resB, errB)
	if resB.Decision.Consequential {
		t.Fatal("under the legal vertical a payment.transfer should not be consequential")
	}
	if resB.Entry.ResolvedChain[1] != didAcme {
		t.Fatalf("Org B should have resolved the chain rooted at Org A: %v", resB.Entry.ResolvedChain)
	}

	// Org B's export verifies on its own terms, signed by B's enforcement key,
	// re-derived from A's public evidence.
	data := httpGetExport(t, orgB.URL)
	exp, err := export.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Signer != didBravo {
		t.Fatalf("Org B's export should be signed by bravo, got %q", exp.Signer)
	}
	res, err := export.Verify(exp, export.Inputs{DIDs: w.dids, Status: w.stat})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pass() {
		t.Fatalf("Org B's export must verify: %s", res.Entries[0].Reason)
	}
}

// Scenario 7, tamper. A post-hoc edit to one audit entry breaks the hash chain;
// the independent verifier fails at exactly that entry and treats nothing after
// it as trustworthy.
func TestScenario7_Tamper(t *testing.T) {
	w := newWorld(t)
	// Produce a small clean export: two allowed routine actions.
	for i, n := range []string{"s7-a", "s7-b"} {
		res, err := w.attempt(t, didHelper, "", act("10"), n)
		mustAllow(t, res, err)
		_ = i
	}
	data := httpGetExport(t, w.srv.URL)

	// Flip a byte inside the FIRST entry's action target.
	tampered := bytes.Replace(data, []byte(`"target": "acct/999"`), []byte(`"target": "acct/xxxxx"`), 1)
	if bytes.Equal(tampered, data) {
		// The proxy marshals compact-ish; fall back to the compact form.
		tampered = bytes.Replace(data, []byte(`"target":"acct/999"`), []byte(`"target":"acct/evil"`), 1)
	}
	if bytes.Equal(tampered, data) {
		t.Fatal("tamper target not found in export")
	}

	exp, err := export.Parse(tampered)
	if err != nil {
		t.Fatal(err)
	}
	res, err := export.Verify(exp, export.Inputs{DIDs: w.dids, Status: w.stat})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass() {
		t.Fatal("a tampered export must not verify")
	}
	if res.Entries[0].Outcome != export.OutcomeFail {
		t.Fatalf("the tampered entry (0) must FAIL, got %q", res.Entries[0].Outcome)
	}
	if len(res.Entries) > 1 && res.Entries[1].Outcome != export.OutcomeUnverified {
		t.Fatalf("entries after a broken hash link must be UNVERIFIED, got %q", res.Entries[1].Outcome)
	}
}

// verifyClean fetches the accumulated export from the running proxy and runs the
// independent verifier over it, proving the agent's activity is re-derivable.
func (w *world) verifyClean(t *testing.T) {
	t.Helper()
	data := httpGetExport(t, w.srv.URL)
	exp, err := export.Parse(data)
	if err != nil {
		t.Fatalf("parse export: %v", err)
	}
	res, err := export.Verify(exp, export.Inputs{DIDs: w.dids, Status: w.stat})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Pass() {
		for _, e := range res.Entries {
			t.Logf("  entry %d: %s — %s", e.Seq, e.Outcome, e.Reason)
		}
		t.Fatal("the agent's export must verify clean")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func httpGetExport(t *testing.T, baseURL string) []byte {
	t.Helper()
	resp, err := http.Get(baseURL + "/export")
	if err != nil {
		t.Fatalf("GET /export: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
