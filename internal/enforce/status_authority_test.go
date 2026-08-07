// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// R6-01. A status list is a self-asserting artifact: it carries the DID of its
// own signer. Both trust paths used to resolve the verification key from THAT
// field, so the check confirmed that whoever a list claimed had signed it had in
// fact signed it, and established nothing about authority to revoke.
//
// The attack these pin is the sharpest form of it: the list is signed by the
// SUBJECT OF THE CREDENTIAL BEING REVOKED. If a party can vouch for its own
// non-revocation, revocation is not a control.

// consequentialAttempt drives one consequential request (which is what forces the
// live revocation sweep) against a proxy built over the harness's CURRENT status
// resolver, so a caller can swap the resolver before calling.
func (h *harness) consequentialAttempt(t *testing.T) *Result {
	t.Helper()
	px := h.proxy(t)
	tip := px.Tip()
	a := action("100")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0"),
		Approver: didAlice, Approval: h.approval(t, tip, didAlice, a)})
	if err != nil {
		t.Fatalf("request was not attributable: %v", err)
	}
	return res
}

// newHarnessWithWorkerIssuedStatusHop builds the alice->acme->worker->helper
// chain with the status reference moved onto the LAST hop, the one WORKER issues,
// pointing at ACME's list. That is the cross-issuer shape the shipped issuer spec
// produces and the one a naive "list issuer must equal credential issuer" rule
// would forbid.
//
// authority is written into that hop's reference; passing "" leaves it undeclared
// so the default (the hop's own issuer, worker) applies.
func newHarnessWithWorkerIssuedStatusHop(t *testing.T, authority types.DID) *harness {
	t.Helper()
	h := &harness{resolver: did.FileResolver{Root: didsRoot}, acme: sign(t, didAcme)}

	base := macaroon.Mint(seed32(0x01), "cred-proxy-1", didAlice)
	mAcme := att(t, base, "action.type", "==", "payment.transfer")
	mWorker := att(t, mAcme, "amount", "<=", "100")
	mHelper := att(t, mWorker, "target", "==", "acct/999")

	mk := func(subject, issuer types.DID, m macaroon.Macaroon, ref status.Reference) chain.Link {
		c, err := credential.New(credential.Options{Subject: subject, Issuer: issuer,
			Macaroon: m, StatusRef: ref, HolderKey: sign(t, subject).Public()})
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
		mk(didWorker, didAcme, mWorker, status.Reference{}),
		// Issued by worker, revocable through acme's list.
		mk(didHelper, didWorker, mHelper, status.Reference{
			ListURL: acmeListURL, Index: 42, Issuer: authority,
		}),
	}}
	return h
}

// listSignedBy publishes a status list signed by whichever principal is named.
// revokeIndex < 0 means an all-clear list.
func (h *harness) listSignedBy(t *testing.T, who types.DID, revokeIndex int) *status.StatusList {
	t.Helper()
	l := status.New(status.MinBits)
	if revokeIndex >= 0 {
		if err := l.Set(revokeIndex, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Sign(sign(t, who)); err != nil {
		t.Fatal(err)
	}
	return l
}

// The baseline the attack has to beat: acme genuinely revokes, and the
// consequential action is denied. Without this, a test asserting the forged list
// is refused could pass on a proxy that denied everything.
func TestR6_01_GenuineRevocationDenies(t *testing.T) {
	h := newHarness(t)
	h.statuses = export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didAcme, 42)}

	res := h.consequentialAttempt(t)
	if res.Decision.Allowed {
		t.Fatal("a genuinely revoked credential was allowed")
	}
	if !strings.Contains(res.Decision.Reason, "revoked") {
		t.Fatalf("denied for the wrong reason: %q", res.Decision.Reason)
	}
}

// The attack. helper is the terminal subject of the harness chain: the very
// principal whose authority the sweep is checking. It signs an all-clear list and
// serves it at the URL the credential names.
func TestR6_01_ListSignedByTheRevokedPartyIsRefused(t *testing.T) {
	h := newHarness(t)
	h.statuses = export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didHelper, -1)}

	res := h.consequentialAttempt(t)
	if res.Decision.Allowed {
		t.Fatal("a status list signed by the credential's own subject was accepted: " +
			"any resolvable principal can defeat revocation")
	}
	// It must fail as an AUTHORITY refusal, not incidentally. A generic "status
	// check failed" would also be produced by a resolver error, and would leave
	// the test passing if the binding were removed but something else broke.
	if !strings.Contains(res.Decision.Reason, "revocation authority") {
		t.Fatalf("refused, but not on the authority binding: %q", res.Decision.Reason)
	}
}

// The same substitution, put to the independent verifier rather than the proxy.
// This is the path that actually matters: an auditor is routinely handed the
// export AND its status lists by the party being audited, so the verifier is
// where an attacker-supplied list is a realistic input rather than a hypothetical
// one.
func TestR6_01_VerifierRefusesAListSignedByTheRevokedParty(t *testing.T) {
	h := newHarness(t)

	// Produce a genuine, clean export first: acme's real list, nothing revoked.
	h.statuses = export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didAcme, -1)}
	px := h.proxy(t)
	tip := px.Tip()
	a := action("100")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0"),
		Approver: didAlice, Approval: h.approval(t, tip, didAlice, a)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("setup: expected a clean consequential allow, got %+v", res.Decision)
	}
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}

	// It verifies against acme's list, as it must.
	clean, err := export.Verify(exp, export.Inputs{DIDs: h.resolver,
		Status: export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didAcme, -1)}})
	if err != nil {
		t.Fatal(err)
	}
	if !clean.Pass() {
		t.Fatalf("setup: honest export does not verify: %+v", clean.Entries)
	}

	// Now the audited party swaps in an all-clear list signed by its own agent,
	// and the credential really is revoked in acme's genuine one. Before the
	// binding, this returned a clean evidence-backed PASS.
	forged, err := export.Verify(exp, export.Inputs{DIDs: h.resolver,
		Status: export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didHelper, -1)}})
	if err != nil {
		t.Fatal(err)
	}
	if forged.Pass() {
		t.Fatal("verifier returned a clean PASS for an export whose revocation evidence " +
			"was signed by the credential's own subject")
	}
	if !strings.Contains(forged.Entries[0].Reason, "revocation authority") {
		t.Fatalf("failed, but not on the authority binding: %q", forged.Entries[0].Reason)
	}
}

// The legitimate cross-issuer case must keep working, or the binding is just a
// break dressed as a fix. One org publishes ONE list covering its whole
// delegation subtree (this is what the 16 KiB herd-privacy floor is for, and what
// the shipped issuer spec does), so a hop issued by an agent can point at its
// org's list, PROVIDED the credential names that org as its authority.
func TestR6_01_CrossIssuerListIsAcceptedWhenTheCredentialNamesIt(t *testing.T) {
	h := newHarnessWithWorkerIssuedStatusHop(t, didAcme)
	h.statuses = export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didAcme, -1)}

	res := h.consequentialAttempt(t)
	if !res.Decision.Allowed {
		t.Fatalf("a hop that names its org as revocation authority was refused: %q", res.Decision.Reason)
	}
	if res.Decision.StatusCheckedHops != 1 {
		t.Fatalf("expected the cross-issuer hop to be status-checked, got %d hops", res.Decision.StatusCheckedHops)
	}
}

// And the same chain WITHOUT the declaration must fail closed, because the
// default is the credential's own issuer (worker), who signs no list. This is the
// half that proves omission narrows rather than widens: a credential that says
// nothing accepts revocations from one key, not from any key.
func TestR6_01_CrossIssuerListRefusedWhenTheCredentialNamesNobody(t *testing.T) {
	h := newHarnessWithWorkerIssuedStatusHop(t, "") // no declared authority
	h.statuses = export.MapStatusResolver{acmeListURL: h.listSignedBy(t, didAcme, -1)}

	res := h.consequentialAttempt(t)
	if res.Decision.Allowed {
		t.Fatal("a hop with no declared authority accepted a list signed by someone " +
			"other than its issuer: omission is widening the accepted key set")
	}
	if !strings.Contains(res.Decision.Reason, "revocation authority") {
		t.Fatalf("refused, but not on the authority binding: %q", res.Decision.Reason)
	}
}
