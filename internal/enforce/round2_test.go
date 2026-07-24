// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/auditsink"
	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/internal/vc"
)

// Round-2 regression suite.
//
// Every test here is a security review round-2 proof-of-concept, inverted: the
// PoC asserted that the break reproduced, and this asserts that it does not. They
// are kept as tests rather than deleted because a fix without a test is a fix
// with an expiry date.
//
// The review's coverage note called out that the existing suite had two adversary
// models (a lying enforcement point, and a post-hoc export tamperer) and that
// every round-2 finding lived outside both. This file adds the missing ones:
//
//   - A DISHONEST CREDENTIAL HOLDER, editing its own credential blob before
//     presenting it. This is where R2-01 lived, in the seam between the issuance
//     signature (which covered only some fields) and the content address (which
//     covers everything but is computed after the proxy has already accepted).
//   - A HOSTILE OR BUGGY SINK IMPLEMENTER. auditsink is a designated plugin
//     interface with no tests for what a non-cooperative implementer can do.
//   - CONCURRENT CALLERS of the exported Proxy.Handle.

// ---- R2-01: the dishonest holder -------------------------------------------

// TestR2_01_HolderCannotEditAnyCredentialField is the GENERAL case, and it is
// deliberately general: the finding demonstrated one editable field, but a fix
// that only defeats that one edit is not a fix, it is a patch on a class.
//
// The issuance signature now covers the whole credential, so every field below
// must break it. New fields added to credential.Credential are covered
// automatically; if one ever is not, this test is where that shows up.
func TestR2_01_HolderCannotEditAnyCredentialField(t *testing.T) {
	edits := map[string]func(c *credential.Credential){
		// The finding's own case: drop the revocation pointer so the sweep has
		// nothing to check.
		"statusRef stripped": func(c *credential.Credential) { c.StatusRef = status.Reference{} },
		// The weaker variant: keep the pointer, aim it at an un-revoked bit in the
		// same genuinely-signed list, so the check runs and reports all clear.
		"statusRef index repointed": func(c *credential.Credential) { c.StatusRef.Index = 44 },
		"statusRef URL repointed":   func(c *credential.Credential) { c.StatusRef.ListURL = "https://localhost/orgs/bravo/status.json" },
		// The rest are the class, not the instance.
		"subject swapped":         func(c *credential.Credential) { c.Subject = didHelper },
		"issuer swapped":          func(c *credential.Credential) { c.Issuer = didAlice },
		"holder key swapped":      func(c *credential.Credential) { c.HolderKey = sign(t, didHelper).Public() },
		"macaroon caveat dropped": func(c *credential.Credential) { c.Macaroon.Caveats = c.Macaroon.Caveats[:len(c.Macaroon.Caveats)-1] },
		"macaroon caveat widened": func(c *credential.Credential) { c.Macaroon.Caveats[len(c.Macaroon.Caveats)-1].Value = "999999" },
		"macaroon identifier":     func(c *credential.Credential) { c.Macaroon.Identifier = "cred-proxy-2" },
		"macaroon HMAC signature": func(c *credential.Credential) { c.Macaroon.Signature[0] ^= 0xff },
		// VCWrapper is documented as NOT load-bearing (F7), and it is still not:
		// nothing verifies it. It is covered anyway, because the issuance signature
		// covers the credential rather than a list of the fields someone judged
		// important. That is the property worth pinning.
		"vc wrapper attached after issuance": func(c *credential.Credential) {
			c.VCWrapper = &vc.VerifiableCredential{Issuer: didAlice}
		},
	}

	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			tampered := &chain.Chain{Links: append([]chain.Link(nil), h.chain.Links...)}
			before, err := json.Marshal(&tampered.Links[1].Credential)
			if err != nil {
				t.Fatal(err)
			}
			// Edit the hop's credential and leave IssuerProof EXACTLY as issued,
			// the attacker cannot re-sign it, which is the whole point.
			edit(&tampered.Links[1].Credential)
			after, err := json.Marshal(&tampered.Links[1].Credential)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) == string(after) {
				t.Skip("this edit is a no-op on the fixture credential; nothing to assert")
			}

			// chain.Verify must reject it outright. Before R2-01 the edited chain
			// verified cleanly and the bypass flowed from there.
			if err := tampered.Verify(h.resolver); err == nil {
				t.Fatal("SECURITY: an edited credential still passes chain.Verify — the issuance signature does not cover this field")
			}

			// And so the proxy refuses to attribute the request at all: it never
			// becomes an audit entry, because an unverifiable chain in the log would
			// read to the verifier as verifier failure rather than as a decision.
			a := action("100")
			px := h.proxy(t)
			if _, err := px.Handle(Request{
				Chain: tampered, Action: a, PoP: h.pop(t, tip0, a, "n1"),
				Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
			}); err == nil {
				t.Fatal("SECURITY: the proxy accepted a request carrying an edited credential")
			}
		})
	}
}

// TestR2_01_RevocationSurvivesAStatusRefEdit is the finding's end-to-end
// reproduction, inverted. The PoC ran: mint the chain with a StatusRef at index
// 42, revoke it, confirm the honest chain DENIES, then strip statusRef and watch
// the same request turn into an ALLOW that the independent verifier PASSED.
func TestR2_01_RevocationSurvivesAStatusRefEdit(t *testing.T) {
	h := newHarness(t)
	if err := h.list.Set(42, true); err != nil {
		t.Fatal(err)
	}
	if err := h.list.Sign(h.acme); err != nil {
		t.Fatal(err)
	}
	a := action("100") // consequential: demands a live status check

	// Baseline: the honest chain is denied, because the hop really is revoked.
	px := h.proxy(t)
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n1"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed || !strings.Contains(res.Decision.Reason, "revoked") {
		t.Fatalf("baseline: a revoked hop must be denied for revocation, got %+v", res.Decision)
	}

	// The bypass: strip the revocation pointer, leave IssuerProof untouched.
	tampered := &chain.Chain{Links: append([]chain.Link(nil), h.chain.Links...)}
	tampered.Links[1].Credential.StatusRef = status.Reference{}

	px2 := h.proxy(t)
	if _, err := px2.Handle(Request{
		Chain: tampered, Action: a, PoP: h.pop(t, tip0, a, "n1"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	}); err == nil {
		t.Fatal("SECURITY: revocation bypassed — the proxy accepted a credential with statusRef stripped")
	}
}

// TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted covers the second half of
// R2-01, which was not about a missing binding at all: Decision.StatusChecked was
// set unconditionally after the revocation sweep returned, so it was true even
// when the sweep examined zero hops, and the verifier accepted that assertion as
// satisfying "a status check was recorded".
//
// The field is now a count the verifier re-derives from the credential evidence,
// so an entry claiming more or fewer checks than the evidence supports fails.
func TestR2_01_StatusCheckedHopsIsReDerivedNotAsserted(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("100")
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n1"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one hop of the three carries a StatusRef, so exactly one was checked.
	if !res.Decision.Allowed || res.Decision.StatusCheckedHops != 1 {
		t.Fatalf("expected an allow with 1 status-checked hop, got %+v", res.Decision)
	}

	// Now a lying proxy inflates the count. The verifier re-derives 1 from the
	// evidence and must reject the claim of 2.
	for _, claim := range []int{0, 2, 99} {
		exp, err := px.Export()
		if err != nil {
			t.Fatal(err)
		}
		exp.Entries[0].Decision.StatusCheckedHops = claim
		// Re-seal so the hash chain is internally consistent: this is a lying
		// producer, not a clumsy tamperer, and it must still be caught.
		reseal(t, exp)

		v, err := export.Verify(exp, export.Inputs{DIDs: h.resolver, Status: h.statuses})
		if err != nil {
			t.Fatal(err)
		}
		if v.Pass() {
			t.Fatalf("SECURITY: the verifier accepted an asserted statusCheckedHops=%d against evidence for 1", claim)
		}
		if !strings.Contains(v.Entries[0].Reason, "status-checked hop") {
			t.Fatalf("failure should name the re-derived count, got %q", v.Entries[0].Reason)
		}
	}
}

// TestR2_01_UnrevocableHopIsStatedNotSkipped: a hop whose issuer published no
// status list is permanently unrevocable. That is the issuer's choice and not a
// verification failure, but before round 2 it was a SILENT skip, the verifier
// returned a clean PASS whose revocation claim covered nothing, with no signal.
func TestR2_01_UnrevocableHopIsStatedNotSkipped(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("100")
	if _, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n1"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	}); err != nil {
		t.Fatal(err)
	}
	v := h.verify(t, px)
	if !v.Pass() {
		t.Fatalf("an honest consequential allow should pass: %+v", v.Entries)
	}
	// Two of the three hops carry no StatusRef, and the verdict must say so.
	if len(v.Entries[0].Limitations) == 0 {
		t.Fatal("a PASS covering unrevocable hops must state that limit, not swallow it")
	}
	if !strings.Contains(v.Entries[0].Limitations[0], "2 of 3 hops") {
		t.Fatalf("the limitation should count the unrevocable hops, got %q", v.Entries[0].Limitations[0])
	}
}

// ---- R2-02: truncation ------------------------------------------------------

// TestR2_02_TruncatedExportIsRejected inverts the truncation PoC: two entries,
// the second a DENY the operator would rather an auditor did not see, deleted by
// editing the JSON with no key material at all. Every surviving signature is
// still valid; the envelope signature is untouched. It used to verify clean.
func TestR2_02_TruncatedExportIsRejected(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)

	a0 := action("10") // routine allow
	if _, err := px.Handle(Request{Chain: h.chain, Action: a0, PoP: h.pop(t, px.Tip(), a0, "n0")}); err != nil {
		t.Fatal(err)
	}
	a1 := action("100") // consequential with no approval presented -> DENY
	if _, err := px.Handle(Request{Chain: h.chain, Action: a1, PoP: h.pop(t, px.Tip(), a1, "n1")}); err != nil {
		t.Fatal(err)
	}

	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	full, err := exp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if v := h.verifyBytes(t, full); !v.Pass() || len(v.Entries) != 2 {
		t.Fatalf("baseline: want a clean 2-entry pass, got pass=%v n=%d", v.Pass(), len(v.Entries))
	}

	v := h.verifyBytes(t, dropEntries(t, full, func(i int) bool { return i < 1 }))
	if v.Pass() {
		t.Fatal("SECURITY: a truncated export still verifies clean — the deny vanished without a trace")
	}
	if !strings.Contains(v.FatalReason, "entries may have been removed") {
		t.Fatalf("truncation should fail at the envelope and say so, got fatal %q", v.FatalReason)
	}
}

// TestR2_02_MiddleDeletionIsRejected checks the general case the finding asked
// about explicitly: deleting from the MIDDLE and re-linking around the gap.
//
// This is closed by a different mechanism than trailing truncation, and it is
// worth pinning both. Removing entry k leaves entry k+1 with the wrong Seq and a
// PrevHash pointing at a hash that is no longer present, and audit.VerifyEntries
// rejects either on its own. Re-linking the survivors would require re-signing
// every one of them, which needs the enforcement point's key.
func TestR2_02_MiddleDeletionIsRejected(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	for i, amt := range []string{"10", "20", "30"} {
		a := action(amt)
		if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, string(rune('a'+i)))}); err != nil {
			t.Fatal(err)
		}
	}
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	full, err := exp.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Keep entries 0 and 2, drop 1.
	v := h.verifyBytes(t, dropEntries(t, full, func(i int) bool { return i != 1 }))
	if v.Pass() {
		t.Fatal("SECURITY: an export with a middle entry deleted still verifies clean")
	}
}

// TestR2_02_EnvelopeBindsCountAndTip pins the mechanism rather than the symptom:
// the envelope signature must cover the log's length and final hash, so a
// signature minted over a different-length log cannot be lifted onto this one.
func TestR2_02_EnvelopeBindsCountAndTip(t *testing.T) {
	h := newHarness(t)

	build := func(n int) *export.Export {
		px := h.proxy(t)
		for i := 0; i < n; i++ {
			a := action("10")
			if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, string(rune('a'+i)))}); err != nil {
				t.Fatal(err)
			}
		}
		exp, err := px.Export()
		if err != nil {
			t.Fatal(err)
		}
		return exp
	}

	two, one := build(2), build(1)
	// A genuine envelope signature from the same enforcement point, over a log of
	// a different length. Before R2-02 the two were interchangeable.
	two.EnvelopeSignature = one.EnvelopeSignature
	v, err := export.Verify(two, export.Inputs{DIDs: h.resolver, Status: h.statuses})
	if err != nil {
		t.Fatal(err)
	}
	if v.FatalReason == "" {
		t.Fatal("SECURITY: an envelope signature over a 1-entry log verified a 2-entry export")
	}
}

// ---- R2-03: the hostile sink ------------------------------------------------

type panickingSink struct{}

func (panickingSink) Write(auditsink.AuditRecord) error { panic("sink blew up") }

// erroringSink both fails and reports that it was called. Sink dispatch is
// asynchronous (R2-03), so the signal is a channel rather than a counter a test
// could read too early.
type erroringSink struct{ called chan auditsink.AuditRecord }

func (e *erroringSink) Write(r auditsink.AuditRecord) error {
	e.called <- r
	return errAlwaysFails
}

type errString string

func (e errString) Error() string { return string(e) }

const errAlwaysFails = errString("sink is broken")

type blockingSink struct{ ch chan struct{} }

func (b blockingSink) Write(auditsink.AuditRecord) error { <-b.ch; return nil }

func (h *harness) proxyWithSink(t *testing.T, s auditsink.AuditSink) *Proxy {
	t.Helper()
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{
		EnforcementPoint: sign(t, didProxy), Policy: pol, DIDs: h.resolver,
		Status: h.statuses, Now: func() time.Time { return fixedTime }, Sink: s,
	})
	if err != nil {
		t.Fatal(err)
	}
	return px
}

// TestR2_03_PanickingSinkCannotWedgeTheProxy inverts the PoC that took the
// enforcement path offline with one line of third-party code. The mutex lived in
// enforce.Handler with no deferred unlock, so a panic escaping Handle, which
// net/http recovers per connection, keeping the process alive, left the lock
// held forever and every later /enforce, /tip and /export blocked.
func TestR2_03_PanickingSinkCannotWedgeTheProxy(t *testing.T) {
	h := newHarness(t)
	px := h.proxyWithSink(t, panickingSink{})
	srv := httptest.NewServer(Handler(px))
	defer srv.Close()

	a := action("10")
	body, err := json.Marshal(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n0")})
	if err != nil {
		t.Fatal(err)
	}

	// The sink panics, and the request it is attached to still succeeds: the seam
	// is best-effort and ADDITIVE, so a broken observability plugin must not be
	// able to fail a decision that was already made and sealed. The panic happens
	// on the sink's own goroutine and is recovered there.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(srv.URL+"/enforce", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("a panicking sink must not fail the request it is attached to: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 despite the sink panic, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// And the proxy is still alive for everyone else. This is the assertion the
	// PoC could not make: it timed out here.
	r, err := client.Get(srv.URL + "/tip")
	if err != nil {
		t.Fatalf("SECURITY: the proxy is wedged after one sink panic: %v", err)
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET /tip after a sink panic: want 200, got %d", r.StatusCode)
	}
}

// TestR2_03_BlockingSinkDoesNotBlockOtherRequests: a sink that merely stalls (a
// full pipe, a stalled network share) used to hold the enforcement chokepoint for
// exactly as long as it blocked, because Write ran synchronously inside Handle
// inside the transport's lock. It now runs outside the enforcement lock, so it
// delays only its own request.
func TestR2_03_BlockingSinkDoesNotBlockEnforcement(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	px := h.proxyWithSink(t, blockingSink{ch: release})
	defer close(release)

	// Every one of these will leave a write parked in the sink forever. Not one
	// of them may be delayed by it: dispatch is asynchronous and bounded, so the
	// decision path never touches the sink's goroutine.
	done := make(chan error, 1)
	go func() {
		for i := range 3 {
			a := action("10")
			if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, "n"+string(rune('0'+i)))}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("enforcement failed while the sink was blocked: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SECURITY: a blocking sink stalled the enforcement path")
	}

	if got := px.Tip().Seq; got != 3 {
		t.Fatalf("all three decisions should be sealed, tip is at seq %d", got)
	}
	// FlushSink must report the truth about a sink that will never drain, rather
	// than hanging shutdown on it.
	if px.FlushSink(200 * time.Millisecond) {
		t.Fatal("FlushSink claimed a permanently blocked sink had drained")
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("the log written while the sink was blocked must verify: %+v", v.Entries)
	}
}

// TestR2_03_SaturatedSinkDropsRatherThanBlocks pins the "bounded" half: past
// sinkMaxInFlight parked writes, records are dropped. Dropping observability is
// survivable; queueing without limit on the enforcement path is not.
func TestR2_03_SaturatedSinkDropsRatherThanBlocks(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	px := h.proxyWithSink(t, blockingSink{ch: release})
	defer close(release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range sinkMaxInFlight + 10 {
			a := action("10")
			if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, fmt.Sprintf("n%d", i))}); err != nil {
				t.Errorf("request %d: %v", i, err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SECURITY: enforcement blocked once the sink pool saturated")
	}
	if got := px.Tip().Seq; got != uint64(sinkMaxInFlight+10) {
		t.Fatalf("every decision should be sealed regardless of sink saturation, tip is at seq %d", got)
	}
}

// TestR2_03_ErroringSinkChangesNothing pins the authority direction that already
// held, so it stays held: a sink's return value is discarded, and no decision,
// entry, or export depends on it.
func TestR2_03_ErroringSinkChangesNothing(t *testing.T) {
	h := newHarness(t)
	sink := &erroringSink{called: make(chan auditsink.AuditRecord, 1)}
	px := h.proxyWithSink(t, sink)
	a := action("10")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n0")})
	if err != nil {
		t.Fatalf("a failing sink must not fail the request: %v", err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("a failing sink must not change the decision: %+v", res.Decision)
	}
	select {
	case rec := <-sink.called:
		if rec.Seq != 0 || len(rec.EntryHash) == 0 {
			t.Fatalf("the forwarded record should mirror the sealed entry, got %+v", rec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sink was never called")
	}
	if !px.FlushSink(5 * time.Second) {
		t.Fatal("FlushSink should drain a sink that returns promptly")
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("the sealed entry must verify regardless of sink outcome: %+v", v.Entries)
	}
}

// ---- R2-04: concurrency ------------------------------------------------------

// TestR2_04_OneApprovalAuthorizesOneAction is the finding's core, and the reason
// the lock moved from the HTTP shell into Proxy. Two concurrent requests carrying
// the SAME single-use human approval, minted for slot 0, must not both execute.
//
// Run this under -race. Interleaving A gave two allows off one approval (caught
// later by the verifier, but the actions had already happened). Interleaving B
// was worse: both entries landed at seq 0, the second overwrote the first, and
// the export verified clean over a log that had silently lost an entry.
func TestR2_04_OneApprovalAuthorizesOneAction(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)

	a := action("100") // consequential: needs an approval bound to the entry position
	tip := px.Tip()
	approval := h.approval(t, tip, didAlice, a)
	pop := h.pop(t, tip, a, "n-race")

	const goroutines = 8
	var wg sync.WaitGroup
	results := make([]*Result, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = px.Handle(Request{
				Chain: h.chain, Action: a, PoP: pop,
				Approver: didAlice, Approval: approval,
			})
		}(i)
	}
	close(start)
	wg.Wait()

	allowed := 0
	for i := range results {
		if errs[i] == nil && results[i] != nil && results[i].Decision.Allowed {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("SECURITY: %d actions executed against ONE human approval bound to one slot; want exactly 1", allowed)
	}

	// Interleaving B: no entry may be lost. Every request that got far enough to
	// be attributable produced exactly one entry, at its own Seq.
	entries := px.Entries()
	if len(entries) != goroutines {
		t.Fatalf("SECURITY: %d requests produced %d audit entries — the log lost one", goroutines, len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i) {
			t.Fatalf("entry %d landed at seq %d: appends are not serialized", i, e.Seq)
		}
	}

	// And the whole log verifies: the seven denials are honest denials, not damage.
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("the log written under concurrency must verify: %+v", v.Entries)
	}
}

// TestR2_04_ConcurrentHandleIsRaceFree drives the two structures the finding
// named (the audit log's entry slice and the credential set's map) from many
// goroutines at once. Interleaving C was a concurrent map write, which Go does
// not make recoverable: it kills the process outright.
func TestR2_04_ConcurrentHandleIsRaceFree(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)

	const goroutines = 16
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := action("10")
			// Each goroutine binds to whatever tip it observes. Some will lose the
			// race for that slot and be denied; none may corrupt the log.
			tip := px.Tip()
			pop := h.pop(t, tip, a, "n-"+string(rune('a'+i)))
			_, _ = px.Handle(Request{Chain: h.chain, Action: a, PoP: pop})
		}(i)
	}
	wg.Wait()

	entries := px.Entries()
	if len(entries) != goroutines {
		t.Fatalf("want %d entries, got %d", goroutines, len(entries))
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("a log written concurrently must still verify: %+v", v.Entries)
	}
}

// TestR2_04_TipCarriesPrevHash pins the documentation defect the finding found:
// audit.go and http.go both claimed evidence committed to Seq+PrevHash while only
// Seq was bound, and /tip did not even carry a PrevHash to bind to.
func TestR2_04_TipCarriesPrevHash(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)

	tip := px.Tip()
	if tip.Seq != 0 || len(tip.PrevHash) == 0 {
		t.Fatalf("a fresh log's tip should be seq 0 linking to the genesis hash, got %+v", tip)
	}
	a := action("10")
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n0")}); err != nil {
		t.Fatal(err)
	}
	next := px.Tip()
	if next.Seq != 1 {
		t.Fatalf("tip should advance to seq 1, got %d", next.Seq)
	}
	if string(next.PrevHash) == string(tip.PrevHash) {
		t.Fatal("tip's PrevHash must advance with the log, not stay at genesis")
	}

	// Evidence bound to the OLD position must not authorize the new one. Without
	// PrevHash this held only because the Seq differed; with it, the same Seq in a
	// different log is also distinguishable.
	a2 := action("10")
	stale := h.pop(t, Tip{Seq: next.Seq, PrevHash: tip.PrevHash}, a2, "n1")
	res, err := px.Handle(Request{Chain: h.chain, Action: a2, PoP: stale})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("SECURITY: a PoP bound to the wrong PrevHash was accepted")
	}
}

// ---- helpers ----------------------------------------------------------------

// verifyBytes parses and verifies raw export bytes, exactly as `kessa verify`
// does, through the same door, so a test cannot accidentally bypass Parse.
func (h *harness) verifyBytes(t *testing.T, data []byte) *export.Result {
	t.Helper()
	exp, err := export.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := export.Verify(exp, export.Inputs{DIDs: h.resolver, Status: h.statuses})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// dropEntries re-encodes an export keeping only the entries keep() selects,
// touching nothing else, the file-holder's attack, needing no key material.
func dropEntries(t *testing.T, data []byte, keep func(i int) bool) []byte {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	kept := make([]json.RawMessage, 0, len(entries))
	for i := range entries {
		if keep(i) {
			kept = append(kept, entries[i])
		}
	}
	trimmed, err := json.Marshal(kept)
	if err != nil {
		t.Fatal(err)
	}
	raw["entries"] = trimmed
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reseal re-signs an edited export end to end, as a LYING PRODUCER would: entry
// hashes, entry signatures, and the envelope signature are all recomputed, so the
// result is internally consistent and the only thing wrong with it is that it is
// not true. A test that skipped this would be caught by the hash chain and would
// never reach the check it means to exercise.
func reseal(t *testing.T, exp *export.Export) {
	t.Helper()
	ep := sign(t, didProxy)
	log := audit.NewLog(ep)
	for i := range exp.Entries {
		e := exp.Entries[i]
		sealed, err := log.Append(audit.Record{
			Action: e.Action, ResolvedChain: e.ResolvedChain, ChainCredentialIDs: e.ChainCredentialIDs,
			Decision: e.Decision, PolicyID: e.PolicyID, PoPNonce: e.PoPNonce, PoPSignature: e.PoPSignature,
			ApprovedBy: e.ApprovedBy, Approval: e.Approval, Timestamp: e.Timestamp,
		})
		if err != nil {
			t.Fatal(err)
		}
		exp.Entries[i] = sealed
	}
	set := export.NewCredentialSet()
	for _, rec := range exp.Credentials {
		if _, err := set.Add(rec.Credential, rec.IssuerProof); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt, err := export.Build(ep, exp.Entries, set, exp.Policy)
	if err != nil {
		t.Fatal(err)
	}
	*exp = *rebuilt
}
