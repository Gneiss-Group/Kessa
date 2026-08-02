// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

var update = flag.Bool("update", false, "update golden files")

const (
	didsRoot         = "../../testdata/dids"
	v2GoldenPath     = "../../testdata/audit_export_v2.golden.json"
	v1GoldenPath     = "../../testdata/audit_export.golden.json"
	statusGoldenPath = "../../testdata/status/acme_status.json"
	commercePolPath  = "../../examples/policies/commerce-security.json"

	acmeListURL = "https://localhost/orgs/acme/status.json"

	// Status-list bit positions. 42 = the live acme->worker credential;
	// 43 = the ROTATED, revoked acme->worker credential; 44 unused.
	idxWorkerLive    = 42
	idxWorkerRevoked = 43
)

var (
	macRootKey = []byte("kessa-v2-golden-macaroon-rootkey")
	baseTime   = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
)

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

func mustSigner(t *testing.T, didStr string, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(types.DID(didStr), seed32(seed))
	if err != nil {
		t.Fatalf("signer %s: %v", didStr, err)
	}
	return s
}

func mustAtt(t *testing.T, m macaroon.Macaroon, c macaroon.Caveat) macaroon.Macaroon {
	t.Helper()
	out, err := macaroon.Attenuate(m, c)
	if err != nil {
		t.Fatalf("Attenuate %v: %v", c, err)
	}
	return out
}

// principals in the golden chain. Seeds match testdata/dids fixtures.
const (
	didAlice  = "did:web:localhost:people:alice"
	didAcme   = "did:web:localhost:orgs:acme"
	didWorker = "did:web:localhost:agents:worker"
	didHelper = "did:web:localhost:agents:helper"
	didProxy  = "did:web:localhost:proxies:gatekeeper"
)

// fixture holds the deterministic evidence used to build the v2 golden.
type fixture struct {
	alice, acme, worker, helper, proxy signer.Signer

	credA  credential.Credential // alice -> acme
	credB  credential.Credential // acme  -> worker   (amount <= 100)  LIVE     idx 42
	credB2 credential.Credential // acme  -> worker   (amount <= 200)  REVOKED  idx 43  (rotation)
	credC  credential.Credential // worker-> helper   (target == acct/999), no StatusRef

	idA, idB, idB2, idC string
	set                 *CredentialSet
	list                *status.StatusList

	pol   *policy.Policy // carried in the export so the verifier re-derives consequentiality (F1)
	polID string
}

// newFixture builds the credentials, issuance proofs, and status list.
//
// The rotation (credB / credB2) is deliberate. Entry 3 must exercise a
// mid-chain revocation, but the ALLOWED entries share the alice->acme->worker
// chain. If the single acme->worker credential were revoked, current-list
// semantics would (correctly) fail the allowed consequential entry too, that is
// the deferred S1 case, not the S2 case we want to pin. So the revoked credential
// is a *rotated* acme->worker credential used only by entry 3. Its actor
// credential (worker->helper) carries no StatusRef at all: a verifier that
// checked only the actor's credential would find nothing to check and wrongly
// pass. That is exactly the S2 bug this fixture exists to catch.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		alice:  mustSigner(t, didAlice, 0x31),
		acme:   mustSigner(t, didAcme, 0x11),
		worker: mustSigner(t, didWorker, 0x33),
		helper: mustSigner(t, didHelper, 0x34),
		proxy:  mustSigner(t, didProxy, 0x55),
	}

	// The commerce policy travels in the export so the verifier re-derives
	// consequentiality from it (F1). The golden entries' asserted `consequential`
	// bits are exactly what this policy classifies for their actions.
	pol, err := policy.Load(commercePolPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	f.pol = pol
	if f.polID, err = PolicyID(pol); err != nil {
		t.Fatalf("PolicyID: %v", err)
	}

	base := macaroon.Mint(macRootKey, "cred-chain-1", didAlice)
	mAcme := mustAtt(t, base, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})
	mWorker := mustAtt(t, mAcme, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "100"})
	mWorker2 := mustAtt(t, mAcme, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "200"})
	mHelper := mustAtt(t, mWorker2, macaroon.Caveat{Field: "target", Op: macaroon.OpEq, Value: "acct/999"})

	mk := func(subject, issuer types.DID, m macaroon.Macaroon, ref status.Reference, holder crypto.PublicKey) credential.Credential {
		c, err := credential.New(credential.Options{
			Subject: subject, Issuer: issuer, Macaroon: m, StatusRef: ref, HolderKey: holder,
		})
		if err != nil {
			t.Fatalf("credential.New(%s): %v", subject, err)
		}
		return *c
	}

	f.credA = mk(didAcme, didAlice, mAcme, status.Reference{}, f.acme.Public())
	f.credB = mk(didWorker, didAcme, mWorker, status.Reference{ListURL: acmeListURL, Index: idxWorkerLive}, f.worker.Public())
	f.credB2 = mk(didWorker, didAcme, mWorker2, status.Reference{ListURL: acmeListURL, Index: idxWorkerRevoked}, f.worker.Public())
	f.credC = mk(didHelper, didWorker, mHelper, status.Reference{}, f.helper.Public())

	proof := func(issuer signer.Signer, c *credential.Credential) []byte {
		p, err := chain.SignIssuance(issuer, c)
		if err != nil {
			t.Fatalf("SignIssuance: %v", err)
		}
		return p
	}

	f.set = NewCredentialSet()
	if f.idA, err = f.set.Add(f.credA, proof(f.alice, &f.credA)); err != nil {
		t.Fatal(err)
	}
	if f.idB, err = f.set.Add(f.credB, proof(f.acme, &f.credB)); err != nil {
		t.Fatal(err)
	}
	if f.idB2, err = f.set.Add(f.credB2, proof(f.acme, &f.credB2)); err != nil {
		t.Fatal(err)
	}
	if f.idC, err = f.set.Add(f.credC, proof(f.worker, &f.credC)); err != nil {
		t.Fatal(err)
	}

	// The published status list: only the ROTATED acme->worker credential is revoked.
	f.list = status.New(status.MinBits)
	if err := f.list.Set(idxWorkerRevoked, true); err != nil {
		t.Fatal(err)
	}
	if err := f.list.Sign(f.acme); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) pop(t *testing.T, c *credential.Credential, holder signer.Signer, nonce string, action types.Action, seq uint64, prevHash []byte) ([]byte, []byte) {
	t.Helper()
	p, err := c.ProvePossession(holder, []byte(nonce), action, seq, prevHash)
	if err != nil {
		t.Fatalf("ProvePossession: %v", err)
	}
	return p.Nonce, p.Signature
}

// posOf reports the position record i will occupy once recs is sealed: its Seq
// and the PrevHash it links to. Tests that hand-craft evidence for a specific
// entry need this, because evidence now binds to PrevHash as well as Seq
// (R2-04) and PrevHash is only knowable by replaying the log up to that point.
func (f *fixture) posOf(t *testing.T, recs []audit.EntryDraft, i int) (uint64, []byte) {
	t.Helper()
	scratch := audit.NewLog(f.proxy)
	for j := 0; j < i; j++ {
		if _, err := scratch.Append(recs[j]); err != nil {
			t.Fatalf("replay entry %d: %v", j, err)
		}
	}
	return scratch.Tip()
}

// records builds the four golden entries.
func (f *fixture) records(t *testing.T) []audit.EntryDraft { return f.recordsWith(t, nil) }

// recordsWith builds the four golden entries, giving mutate a chance to adjust
// each one BEFORE it is sealed into the hash chain.
//
// The "before" matters (R2-04). Mutating a record after the fact changes its
// hash, which changes the PrevHash of every entry after it, which invalidates
// the evidence those entries bound to the old position, so a test that edits a
// sealed record gets a cascade of failures rather than the one it meant to
// provoke. Mutating inside the seal keeps the log internally consistent, which
// is the right model for an adversary who controls the whole log.
func (f *fixture) recordsWith(t *testing.T, mutate func(i int, r *audit.EntryDraft)) []audit.EntryDraft {
	t.Helper()
	shortChain := []types.DID{didAlice, didAcme, didWorker}
	deepChain := []types.DID{didAlice, didAcme, didWorker, didHelper}

	act := func(amount string, ts time.Time) types.Action {
		return types.Action{
			Type: "payment.transfer", Target: "acct/999",
			Attributes: map[string]string{"amount": amount, "currency": "USD"},
			Timestamp:  ts,
		}
	}

	act0 := act("10", baseTime)
	act1 := act("100", baseTime.Add(time.Minute))
	act2 := act("5000", baseTime.Add(2*time.Minute))
	act3 := act("150", baseTime.Add(3*time.Minute))

	// Each entry's evidence is bound to the POSITION it will occupy: its Seq and
	// its PrevHash (F3/F4, R2-04). PrevHash is the previous entry's hash, which is
	// only knowable by walking the log forward, so these records are built exactly
	// the way a real proxy builds them, read the tip, sign against it, append,
	// repeat, against a scratch log. Building them all up front against bare
	// indices, as this fixture used to, is no longer possible, and that is the
	// point: the fixture can no longer express evidence a real proxy could not
	// have produced.
	scratch := audit.NewLog(f.proxy)
	out := make([]audit.EntryDraft, 0, 4)
	seal := func(mk func(seq uint64, prev []byte) audit.EntryDraft) {
		seq, prev := scratch.Tip()
		r := mk(seq, prev)
		if mutate != nil {
			mutate(len(out), &r)
		}
		if _, err := scratch.Append(r); err != nil {
			t.Fatalf("seal entry %d: %v", seq, err)
		}
		out = append(out, r)
	}

	// 0: routine allow, below the consequentiality threshold, within scope.
	seal(func(seq uint64, prev []byte) audit.EntryDraft {
		n, s := f.pop(t, &f.credB, f.worker, "nonce-0001", act0, seq, prev)
		return audit.EntryDraft{
			Action: act0, ResolvedChain: shortChain,
			ChainCredentialIDs: []string{f.idA, f.idB}, PolicyID: f.polID,
			Decision: types.Decision{Allowed: true, Consequential: false, RuleFired: "default",
				PolicyVersion: "commerce-security-v1", StatusCheckedHops: 0,
				Reason: "routine action below all consequentiality thresholds"},
			PoPNonce: n, PoPSignature: s, Timestamp: baseTime,
		}
	})
	// 1: consequential allow, live status check, no hop revoked, human-approved.
	//    Reuses credA and credB: the dedup proof. Exactly one of its two hops
	//    (acme->worker) carries a StatusRef, so statusCheckedHops is 1 and the
	//    verifier re-derives that same 1 from the evidence.
	seal(func(seq uint64, prev []byte) audit.EntryDraft {
		n, s := f.pop(t, &f.credB, f.worker, "nonce-0002", act1, seq, prev)
		approval, err := audit.SignApproval(f.alice, didWorker, act1, seq, prev)
		if err != nil {
			t.Fatalf("sign approval: %v", err)
		}
		return audit.EntryDraft{
			Action: act1, ResolvedChain: shortChain,
			ChainCredentialIDs: []string{f.idA, f.idB}, PolicyID: f.polID,
			Decision: types.Decision{Allowed: true, Consequential: true, RuleFired: "high-value-transfer",
				PolicyVersion: "commerce-security-v1", StatusCheckedHops: 1,
				Reason: "status live-checked; no hop revoked; human-approved"},
			PoPNonce: n, PoPSignature: s,
			ApprovedBy: didAlice, Approval: approval,
			Timestamp: baseTime.Add(time.Minute),
		}
	})
	// 2: scope-exceeded deny, $5000 against an attenuated $100 ceiling.
	seal(func(seq uint64, prev []byte) audit.EntryDraft {
		n, s := f.pop(t, &f.credB, f.worker, "nonce-0003", act2, seq, prev)
		return audit.EntryDraft{
			Action: act2, ResolvedChain: shortChain,
			ChainCredentialIDs: []string{f.idA, f.idB}, PolicyID: f.polID,
			Decision: types.Decision{Allowed: false, Consequential: true, RuleFired: "high-value-transfer",
				PolicyVersion: "commerce-security-v1", StatusCheckedHops: 1,
				Reason: "exceeds attenuated ceiling (amount <= 100)"},
			PoPNonce: n, PoPSignature: s, Timestamp: baseTime.Add(2 * time.Minute),
		}
	})
	// 3: mid-chain-revoked deny, the action is within scope and PoP is good;
	//    the only defect is that the acme->worker hop was revoked at runtime.
	seal(func(seq uint64, prev []byte) audit.EntryDraft {
		n, s := f.pop(t, &f.credC, f.helper, "nonce-0004", act3, seq, prev)
		return audit.EntryDraft{
			Action: act3, ResolvedChain: deepChain,
			ChainCredentialIDs: []string{f.idA, f.idB2, f.idC}, PolicyID: f.polID,
			Decision: types.Decision{Allowed: false, Consequential: true, RuleFired: "high-value-transfer",
				PolicyVersion: "commerce-security-v1", StatusCheckedHops: 1,
				Reason: "delegation credential revoked mid-chain (acme -> worker)"},
			PoPNonce: n, PoPSignature: s, Timestamp: baseTime.Add(3 * time.Minute),
		}
	})
	return out
}

// build seals records into a signed log and wraps them in a v2 envelope, carrying
// the policy and signing the envelope header.
func (f *fixture) build(t *testing.T, recs []audit.EntryDraft) *Export {
	t.Helper()
	log := audit.NewLog(f.proxy)
	for i, r := range recs {
		if _, err := log.Append(r); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	exp, err := Build(f.proxy, log.Entries(), f.set, f.pol)
	if err != nil {
		t.Fatalf("build export: %v", err)
	}
	return exp
}

func (f *fixture) inputs() Inputs {
	return Inputs{
		DIDs:   did.FileResolver{Root: didsRoot},
		Status: MapStatusResolver{acmeListURL: f.list},
	}
}

// ---- the freeze ----------------------------------------------------------

// TestGoldenV2Export freezes the v2 evidence export format and its companion
// status list. Regenerate deliberately: go test ./internal/export -run TestGoldenV2Export -update
func TestGoldenV2Export(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	got, err := exp.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if *update {
		if err := os.MkdirAll(filepath.Dir(statusGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := status.Save(f.list, statusGoldenPath); err != nil {
			t.Fatalf("save status list: %v", err)
		}
		if err := os.WriteFile(v2GoldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s and %s", v2GoldenPath, statusGoldenPath)
		return
	}

	want, err := os.ReadFile(v2GoldenPath)
	if err != nil {
		t.Fatalf("read v2 golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("v2 export does not match golden %s", v2GoldenPath)
	}
}

func TestV2Export_IsDeterministic(t *testing.T) {
	a, err := newFixture(t).build(t, newFixture(t).records(t)).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	b, err := f.build(t, f.records(t)).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two identical builds produced different v2 exports")
	}
}

// ---- the four entries verify as designed ---------------------------------

func TestV2Golden_Verifies(t *testing.T) {
	data, err := os.ReadFile(v2GoldenPath)
	if err != nil {
		t.Fatalf("read v2 golden: %v", err)
	}
	exp, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	list, err := status.Load(statusGoldenPath)
	if err != nil {
		t.Fatalf("load status: %v", err)
	}
	in := Inputs{DIDs: did.FileResolver{Root: didsRoot}, Status: MapStatusResolver{acmeListURL: list}}

	res, err := Verify(exp, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.EvidenceCarried {
		t.Fatal("v2 export should carry evidence")
	}
	want := []Outcome{OutcomePass, OutcomePass, OutcomePassDeny, OutcomePassDeny}
	if len(res.Entries) != len(want) {
		t.Fatalf("got %d entry results, want %d", len(res.Entries), len(want))
	}
	for i, w := range want {
		if res.Entries[i].Outcome != w {
			t.Fatalf("entry %d: outcome %q (%s), want %q", i, res.Entries[i].Outcome, res.Entries[i].Reason, w)
		}
	}
	if !res.Pass() {
		t.Fatal("valid golden should pass overall")
	}
	// Entry 3's chain is fully reconstructed from evidence.
	if got := res.Entries[3].Chain; len(got) != 4 || got[3] != didHelper {
		t.Fatalf("entry 3 chain reconstruction = %v", got)
	}
}

// ---- dedup ---------------------------------------------------------------

// TestCredentialsAreDeduplicated: credA is referenced by all four entries and
// credB by three, yet each is stored exactly once.
func TestCredentialsAreDeduplicated(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))

	refs := 0
	for _, e := range exp.Entries {
		refs += len(e.ChainCredentialIDs)
	}
	if refs != 9 { // 2 + 2 + 2 + 3
		t.Fatalf("expected 9 hop references across entries, got %d", refs)
	}
	if len(exp.Credentials) != 4 {
		t.Fatalf("expected 4 distinct credentials stored, got %d", len(exp.Credentials))
	}
	// Adding an identical credential again must not grow the set.
	before := f.set.Len()
	if _, err := f.set.Add(f.credA, []byte("ignored")); err != nil {
		t.Fatal(err)
	}
	if f.set.Len() != before {
		t.Fatal("re-adding an identical credential grew the set")
	}
}

func TestCredentialID_IsStableAcrossRoundTrip(t *testing.T) {
	f := newFixture(t)
	want, err := CredentialID(&f.credB)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := f.credB.Marshal() // indented on disk
	if err != nil {
		t.Fatal(err)
	}
	back, err := credential.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CredentialID(back)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("credential ID changed across a marshal/parse round trip: %q vs %q", got, want)
	}
}

// ---- S2: mid-chain revocation ---------------------------------------------

// TestS2_MidChainRevocationFailsAnAllowedEntry is the reason entry 3 exists.
// If the enforcement point had ALLOWED the action despite the mid-chain hop being
// revoked, the verifier must catch it, even though the ACTOR's own credential
// carries no StatusRef and would look clean to a verifier that checked only the
// terminal credential.
func TestS2_MidChainRevocationFailsAnAllowedEntry(t *testing.T) {
	f := newFixture(t)

	// Sanity: the actor's credential really has nothing to check.
	if f.credC.StatusRef.ListURL != "" {
		t.Fatal("fixture broken: actor credential should carry no StatusRef")
	}

	recs := f.records(t)
	recs[3].Decision.Allowed = true // a proxy that failed to honour the revocation
	recs[3].Decision.Reason = "allowed despite revoked delegation"
	exp := f.build(t, recs)

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := res.Entries[3]
	if got.Outcome != OutcomeFail {
		t.Fatalf("entry 3 outcome = %q (%s); want FAIL", got.Outcome, got.Reason)
	}
	if !strings.Contains(got.Reason, "revoked") {
		t.Fatalf("failure reason should name the revocation: %q", got.Reason)
	}
	// It must be attributed to the MID-CHAIN hop (hop 1: acme -> worker), not the actor.
	if !strings.Contains(got.Reason, "hop 1") || !strings.Contains(got.Reason, didWorker) {
		t.Fatalf("failure should name the mid-chain hop: %q", got.Reason)
	}
	if res.Pass() {
		t.Fatal("overall verdict must not pass")
	}
	// Entries 0-2 remain unaffected.
	for i := range 3 {
		if res.Entries[i].Outcome == OutcomeFail {
			t.Fatalf("entry %d should be unaffected, got FAIL: %s", i, res.Entries[i].Reason)
		}
	}
}

// ---- evidence tampering / withholding -------------------------------------

func TestVerify_MissingCredentialFails(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	delete(exp.Credentials, f.idB) // withhold the evidence for hop 1

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "missing") {
		t.Fatalf("entry 0 should fail on the missing credential: %q", res.Entries[0].Reason)
	}
}

// TestVerify_SubstitutedCredentialFails: swap the stored credential's content
// while keeping the map key. The content-address self-check must catch it.
func TestVerify_SubstitutedCredentialFails(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))

	rec := exp.Credentials[f.idB]
	rec.Credential = f.credB2 // broader authority, same map key
	exp.Credentials[f.idB] = rec

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "content hash") {
		t.Fatalf("substituted credential should fail the content-address check: %q", res.Entries[0].Reason)
	}
}

func TestVerify_BadIssuerProofFails(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	rec := exp.Credentials[f.idB]
	rec.IssuerProof = bytes.Clone(rec.IssuerProof)
	rec.IssuerProof[0] ^= 0xff
	exp.Credentials[f.idB] = rec

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "chain does not verify") {
		t.Fatalf("bad issuance proof should fail chain re-resolution: %q", res.Entries[0].Reason)
	}
}

func TestVerify_ResolvedChainMismatchFails(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	// Claim a chain of principals the evidence does not produce.
	recs[0].ResolvedChain = []types.DID{didAlice, didAcme, didHelper}
	exp := f.build(t, recs)

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "differs at position") {
		t.Fatalf("chain mismatch should fail: %q", res.Entries[0].Reason)
	}
}

// TestVerify_WithheldEvidenceOnAllowedEntryFails closes the omitempty bypass: a
// producer that simply omits evidence must not get a free PASS.
func TestVerify_WithheldEvidenceOnAllowedEntryFails(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *audit.EntryDraft)
		want   string
	}{
		{"no credential IDs", func(r *audit.EntryDraft) { r.ChainCredentialIDs = nil }, "evidence withheld"},
		{"no PoP signature", func(r *audit.EntryDraft) { r.PoPSignature = nil }, "no proof of possession"},
		{"no PoP nonce", func(r *audit.EntryDraft) { r.PoPNonce = nil }, "no proof of possession"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			recs := f.records(t)
			tc.mutate(&recs[0]) // entry 0 is an ALLOW
			exp := f.build(t, recs)

			res, err := Verify(exp, f.inputs())
			if err != nil {
				t.Fatal(err)
			}
			if res.Entries[0].Outcome != OutcomeFail {
				t.Fatalf("withheld evidence must FAIL, got %q (%s)", res.Entries[0].Outcome, res.Entries[0].Reason)
			}
			if !strings.Contains(res.Entries[0].Reason, tc.want) {
				t.Fatalf("reason %q should mention %q", res.Entries[0].Reason, tc.want)
			}
		})
	}
}

// TestVerify_AllowedButOutOfScopeFails: a proxy that allowed an action exceeding
// the attenuated ceiling is caught by caveat re-satisfaction.
func TestVerify_AllowedButOutOfScopeFails(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	recs[2].Decision.Allowed = true // the $5000 action, wrongly allowed
	exp := f.build(t, recs)

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[2].Outcome != OutcomeFail || !strings.Contains(res.Entries[2].Reason, "exceeds the delegated authority") {
		t.Fatalf("out-of-scope allow should fail: %q", res.Entries[2].Reason)
	}
}

// TestVerify_ConsequentialAllowWithoutApprovalFails: a consequential allow must
// carry a valid human approval. Withholding it (or forging it) fails the entry,
// symmetric with the status and PoP requirements.
func TestVerify_ConsequentialAllowWithoutApprovalFails(t *testing.T) {
	t.Run("withheld", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		recs[1].ApprovedBy = ""
		recs[1].Approval = nil
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[1].Outcome != OutcomeFail || !strings.Contains(res.Entries[1].Reason, "no human approval") {
			t.Fatalf("missing approval on a consequential allow should fail: %q", res.Entries[1].Reason)
		}
	})

	t.Run("forged", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// helper (not a human) signs the approval instead of alice.
		seq1, prev1 := f.posOf(t, recs, 1)
		bad, err := audit.SignApproval(f.helper, didWorker, recs[1].Action, seq1, prev1)
		if err != nil {
			t.Fatal(err)
		}
		recs[1].Approval = bad // ApprovedBy still claims alice
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[1].Outcome != OutcomeFail || !strings.Contains(res.Entries[1].Reason, "approval does not verify") {
			t.Fatalf("forged approval should fail: %q", res.Entries[1].Reason)
		}
	})

	t.Run("approval bound to a different action", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// alice approves a DIFFERENT action; it must not authorize this one.
		other := recs[1].Action
		other.Attributes = map[string]string{"amount": "1", "currency": "USD"}
		seq1, prev1 := f.posOf(t, recs, 1)
		bad, err := audit.SignApproval(f.alice, didWorker, other, seq1, prev1)
		if err != nil {
			t.Fatal(err)
		}
		recs[1].Approval = bad
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[1].Outcome != OutcomeFail || !strings.Contains(res.Entries[1].Reason, "approval does not verify") {
			t.Fatalf("misbound approval should fail: %q", res.Entries[1].Reason)
		}
	})
}

// TestVerify_AllowedConsequentialWithoutStatusCheckFails
func TestVerify_AllowedConsequentialWithoutStatusCheckFails(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	recs[1].Decision.StatusCheckedHops = 0
	exp := f.build(t, recs)

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[1].Outcome != OutcomeFail || !strings.Contains(res.Entries[1].Reason, "status-checked hop") {
		t.Fatalf("consequential allow without a status check should fail: %q", res.Entries[1].Reason)
	}
}

// TestVerify_ForgedPoPFails: the recorded nonce signed by the wrong key.
func TestVerify_ForgedPoPFails(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	thief := mustSigner(t, "did:web:localhost:agents:thief", 0x77)
	seq0, prev0 := f.posOf(t, recs, 0)
	_, sig := f.pop(t, &f.credB, thief, "nonce-0001", recs[0].Action, seq0, prev0) // thief signs, not worker
	recs[0].PoPSignature = sig
	exp := f.build(t, recs)

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "possession") {
		t.Fatalf("forged PoP should fail: %q", res.Entries[0].Reason)
	}
}

// ---- hash-chain tampering is still terminal --------------------------------

func TestVerify_TamperedEntryFailsExactlyThereAndVoidsTheRest(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	exp.Entries[1].Action.Target = "acct/attacker"

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomePass {
		t.Fatalf("entry 0 (before the tamper) should still pass: %q", res.Entries[0].Reason)
	}
	if res.Entries[1].Outcome != OutcomeFail {
		t.Fatal("entry 1 (the tampered one) should fail")
	}
	for i := 2; i < 4; i++ {
		if res.Entries[i].Outcome != OutcomeUnverified {
			t.Fatalf("entry %d after a broken hash chain should be UNVERIFIED, got %q", i, res.Entries[i].Outcome)
		}
	}
	if res.Pass() {
		t.Fatal("tampered export must not pass")
	}
}

// ---- version dispatch ------------------------------------------------------

func TestParse_VersionDispatch(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	good, err := exp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("v2 should parse: %v", err)
	}

	// The accepted set is exactly {v1 integrity-only, v2 evidence}. Anything else,
	// a future v3, or a v1 still carrying evidence, is refused at the door.
	t.Run("unknown v3 rejected", func(t *testing.T) {
		bad := bytes.Replace(good, []byte(`"kessa-audit-export/v2"`), []byte(`"kessa-audit-export/v3"`), 1)
		if _, err := Parse(bad); err == nil {
			t.Fatal("a future v3 envelope must be rejected, not silently verified")
		}
	})

	t.Run("v1 carrying credentials rejected", func(t *testing.T) {
		bad := bytes.Replace(good, []byte(`"kessa-audit-export/v2"`), []byte(`"kessa-audit-export/v1"`), 1)
		if _, err := Parse(bad); err == nil {
			t.Fatal("a v1 envelope carrying a credential set must be rejected")
		}
	})
}

// TestV1Export_IsIntegrityOnly: the frozen v1 golden still parses and its
// integrity still checks out, but it must NOT present as a clean evidence-backed
// pass, that downgrade is exactly what F2 closes. The verdict is a distinct
// integrity-only outcome, Pass() is false, and the reason discloses the limit.
func TestV1Export_IsIntegrityOnly(t *testing.T) {
	data, err := os.ReadFile(v1GoldenPath)
	if err != nil {
		t.Fatalf("read v1 golden: %v", err)
	}
	exp, err := Parse(data)
	if err != nil {
		t.Fatalf("v1 golden should still parse: %v", err)
	}
	if !exp.IsV1() {
		t.Fatal("expected a v1 envelope")
	}
	res, err := Verify(exp, Inputs{DIDs: did.FileResolver{Root: didsRoot}})
	if err != nil {
		t.Fatalf("Verify v1: %v", err)
	}
	if res.EvidenceCarried {
		t.Fatal("v1 export must not claim to carry evidence")
	}
	if res.Pass() {
		t.Fatal("a v1 (integrity-only) export must NOT return a clean evidence-backed pass (F2 downgrade)")
	}
	for _, e := range res.Entries {
		if e.Outcome != OutcomeIntegrityOnly {
			t.Fatalf("v1 entry outcome should be integrity-only, got %q", e.Outcome)
		}
		if !strings.Contains(e.Reason, "authority NOT re-derived") {
			t.Fatalf("v1 entry verdict must disclose the limit: %q", e.Reason)
		}
	}
}

// ---- F2: version relabel + envelope binding --------------------------------

// TestF2_versionRelabel is the primary F2 negative test. A valid v2 export that
// PASSes is relabelled v1; the verifier must NOT return a clean pass.
func TestF2_versionRelabel(t *testing.T) {
	f := newFixture(t)
	good, err := f.build(t, f.records(t)).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the honest v2 export passes.
	exp, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := Verify(exp, f.inputs()); !res.Pass() {
		t.Fatal("the honest v2 export should pass before we tamper")
	}

	t.Run("relabel to v1, stripping v2 fields", func(t *testing.T) {
		// The realistic attack: strip the v2-only fields and relabel, so it looks
		// like a genuine v1 export with byte-identical entries and signatures.
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		m["version"] = "kessa-audit-export/v1"
		delete(m, "credentials")
		delete(m, "policy")
		delete(m, "envelopeSignature")
		relabeled, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		exp, err := Parse(relabeled)
		if err != nil {
			t.Fatalf("a stripped v1 export should still parse: %v", err)
		}
		res, err := Verify(exp, f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Pass() {
			t.Fatal("a v2 export relabelled v1 must NOT return a clean pass (F2)")
		}
		if res.EvidenceCarried {
			t.Fatal("the relabelled export must not claim to carry evidence")
		}
		for _, e := range res.Entries {
			if e.Outcome != OutcomeIntegrityOnly {
				t.Fatalf("relabelled entry should be integrity-only, got %q", e.Outcome)
			}
		}
	})

	t.Run("relabel to v1 without stripping is rejected at parse", func(t *testing.T) {
		bad := bytes.Replace(good, []byte(`"kessa-audit-export/v2"`), []byte(`"kessa-audit-export/v1"`), 1)
		if _, err := Parse(bad); err == nil {
			t.Fatal("a v1 envelope still carrying evidence must be rejected at parse")
		}
	})

	t.Run("tampering the envelope signature is fatal", func(t *testing.T) {
		exp, err := Parse(good)
		if err != nil {
			t.Fatal(err)
		}
		exp.EnvelopeSignature[0] ^= 0xff
		res, err := Verify(exp, f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.FatalReason == "" || res.Pass() {
			t.Fatalf("a tampered envelope signature must be a fatal, non-passing verdict: %+v", res.FatalReason)
		}
	})
}

// ---- F1: consequentiality suppression, mismatch, policy swap ----------------

func TestF1_consequentialitySuppression(t *testing.T) {
	t.Run("suppression: genuinely consequential marked non-consequential", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// Entry 3's action ($150) is consequential under the carried policy, its
		// acme->worker hop is revoked, and it carries no approval. A lying proxy
		// marks it consequential:false, allowed:true to skip the revocation sweep
		// AND the approval requirement.
		recs[3].Decision.Allowed = true
		recs[3].Decision.Consequential = false
		recs[3].Decision.Reason = "allowed; consequentiality suppressed"
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[3].Outcome != OutcomeFail {
			t.Fatalf("suppressed consequentiality must FAIL, got %q (%s)", res.Entries[3].Outcome, res.Entries[3].Reason)
		}
		if !strings.Contains(res.Entries[3].Reason, "consequential") {
			t.Fatalf("failure should cite the re-derived consequentiality: %q", res.Entries[3].Reason)
		}
		if res.Pass() {
			t.Fatal("overall verdict must not pass")
		}
	})

	t.Run("mismatch: routine action marked consequential", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// Entry 0 ($10) is non-consequential under the policy; asserting true is a
		// misclassification the verifier must reject in either direction.
		recs[0].Decision.Consequential = true
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "mismatch") {
			t.Fatalf("consequentiality mismatch must FAIL: %q (%s)", res.Entries[0].Outcome, res.Entries[0].Reason)
		}
	})

	t.Run("swapped policy is caught by the pin", func(t *testing.T) {
		f := newFixture(t)
		exp := f.build(t, f.records(t))
		// Substitute a different (permissive-in-a-different-vertical) policy after
		// the fact. Its content address no longer matches the envelope signature or
		// the entries' pinned PolicyID.
		other, err := policy.Load("../../examples/policies/legal-ediscovery.json")
		if err != nil {
			t.Fatal(err)
		}
		exp.Policy = other
		res, err := Verify(exp, f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.FatalReason == "" || res.Pass() {
			t.Fatalf("a swapped policy must be caught (envelope pin): %q", res.FatalReason)
		}
	})
}

// ---- F3: PoP replay across actions -----------------------------------------

func TestF3_popReplayAcrossActions(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	// Entry 0's PoP was signed for action $10 at seq 0. Reuse it verbatim on an
	// entry recording a DIFFERENT action (still within scope, still routine) at
	// the same seq. The action-bound PoP must no longer verify.
	recs[0].Action = types.Action{
		Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "20", "currency": "USD"},
		Timestamp:  baseTime,
	}
	res, err := Verify(f.build(t, recs), f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries[0].Outcome != OutcomeFail || !strings.Contains(res.Entries[0].Reason, "possession") {
		t.Fatalf("a PoP reused across actions must FAIL: %q (%s)", res.Entries[0].Outcome, res.Entries[0].Reason)
	}
}

// ---- F4: evidence replay across entries ------------------------------------

func TestF4_evidenceReplayAcrossEntries(t *testing.T) {
	shortChain := []types.DID{didAlice, didAcme, didWorker}

	t.Run("PoP lifted from entry 1 onto entry 2", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// Reuse entry 1's whole (action, approval, PoP) tuple at seq 2, the "one
		// approval, N executions" attack. entry 1's PoP was signed for seq 1.
		recs[2] = audit.EntryDraft{
			Action: recs[1].Action, ResolvedChain: shortChain,
			ChainCredentialIDs: []string{f.idA, f.idB}, PolicyID: f.polID,
			Decision: recs[1].Decision,
			PoPNonce: recs[1].PoPNonce, PoPSignature: recs[1].PoPSignature,
			ApprovedBy: recs[1].ApprovedBy, Approval: recs[1].Approval,
			Timestamp: baseTime.Add(2 * time.Minute),
		}
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[2].Outcome != OutcomeFail || !strings.Contains(res.Entries[2].Reason, "possession") {
			t.Fatalf("a PoP replayed onto another entry must FAIL: %q (%s)", res.Entries[2].Outcome, res.Entries[2].Reason)
		}
	})

	t.Run("approval lifted from entry 1 onto entry 2", func(t *testing.T) {
		f := newFixture(t)
		recs := f.records(t)
		// A fresh, VALID PoP for seq 2 (the attacker cannot forge this without the
		// holder key, but the honest holder might legitimately act twice) paired
		// with entry 1's approval, which was bound to seq 1. The approval must not
		// authorize seq 2.
		seq2, prev2 := f.posOf(t, recs, 2)
		n, s := f.pop(t, &f.credB, f.worker, "nonce-replay", recs[1].Action, seq2, prev2)
		recs[2] = audit.EntryDraft{
			Action: recs[1].Action, ResolvedChain: shortChain,
			ChainCredentialIDs: []string{f.idA, f.idB}, PolicyID: f.polID,
			Decision: recs[1].Decision,
			PoPNonce: n, PoPSignature: s,
			ApprovedBy: recs[1].ApprovedBy, Approval: recs[1].Approval, // seq-1 approval
			Timestamp: baseTime.Add(2 * time.Minute),
		}
		res, err := Verify(f.build(t, recs), f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries[2].Outcome != OutcomeFail || !strings.Contains(res.Entries[2].Reason, "approval does not verify") {
			t.Fatalf("an approval replayed onto another entry must FAIL: %q (%s)", res.Entries[2].Outcome, res.Entries[2].Reason)
		}
	})
}

// ---- round 2 -----------------------------------------------------------------

// TestR2_07_RuleAndPolicyVersionAreReDerived: both fields are hash-covered and
// signed, so they cannot be edited after the fact, but signed is not the same as
// true, and nothing stopped the enforcement point from recording a decision
// attributed to a rule that never fired. That cannot produce an unjustified allow
// (consequentiality is separately re-derived), but it can produce an audit trail
// whose stated REASON is false while the verdict verifies clean.
func TestR2_07_RuleAndPolicyVersionAreReDerived(t *testing.T) {
	cases := map[string]struct {
		mutate func(d *types.Decision)
		want   string
	}{
		"rule attributed to a rule that did not fire": {
			mutate: func(d *types.Decision) { d.RuleFired = "some-other-rule" },
			want:   "rule attribution mismatch",
		},
		"rule attribution blanked": {
			mutate: func(d *types.Decision) { d.RuleFired = "" },
			want:   "rule attribution mismatch",
		},
		"policy version misstated": {
			mutate: func(d *types.Decision) { d.PolicyVersion = "commerce-security-v99" },
			want:   "policy version mismatch",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			// Mutate inside the seal, so the log is internally consistent and the
			// entry is a LIE rather than a tamper, otherwise the hash chain catches
			// it first and this never reaches the check it exists to test.
			recs := f.recordsWith(t, func(i int, r *audit.EntryDraft) {
				if i == 1 {
					tc.mutate(&r.Decision)
				}
			})
			res, err := Verify(f.build(t, recs), f.inputs())
			if err != nil {
				t.Fatal(err)
			}
			if res.Entries[1].Outcome != OutcomeFail {
				t.Fatalf("a false attribution on an allowed entry must FAIL, got %q", res.Entries[1].Outcome)
			}
			if !strings.Contains(res.Entries[1].Reason, tc.want) {
				t.Fatalf("failure should name the mismatch (%q), got %q", tc.want, res.Entries[1].Reason)
			}
		})
	}
}

// TestR2_02_EnvelopeCoversLengthAndTip pins the signing input directly, so a
// future refactor that drops a field from it fails here rather than silently
// reopening truncation.
func TestR2_02_EnvelopeCoversLengthAndTip(t *testing.T) {
	f := newFixture(t)
	recs := f.records(t)
	exp := f.build(t, recs)

	base := envelopeSigningInput(exp.Version, exp.Signer, f.polID, uint64(len(exp.Entries)), logTip(exp.Entries))
	shorter := envelopeSigningInput(exp.Version, exp.Signer, f.polID, uint64(len(exp.Entries)-1), logTip(exp.Entries))
	otherTip := envelopeSigningInput(exp.Version, exp.Signer, f.polID, uint64(len(exp.Entries)), exp.Entries[0].EntryHash)
	if bytes.Equal(base, shorter) {
		t.Fatal("the envelope signing input does not distinguish log length — truncation is reopened")
	}
	if bytes.Equal(base, otherTip) {
		t.Fatal("the envelope signing input does not distinguish the log tip")
	}

	// An empty log commits to the genesis hash, not to nothing.
	empty, err := Build(f.proxy, nil, NewCredentialSet(), f.pol)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logTip(empty.Entries), audit.GenesisHash) {
		t.Fatal("an empty log's tip should be the genesis hash")
	}
	res, err := Verify(empty, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.FatalReason != "" {
		t.Fatalf("an honestly empty export should have a valid envelope, got %q", res.FatalReason)
	}
}
