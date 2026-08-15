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

// newHarnessNoAmountCaveat builds the usual chain with the amount caveat REMOVED,
// so the terminal credential is scoped by action type, target and currency but
// says nothing about how large a transfer may be.
//
// That is the shape this file exists to cover, and it is the intended division of
// labour rather than a misconfiguration: caveats bound what authority was
// delegated, and policy decides what needs a human. A credential that caps the
// amount itself is covered by newHarness and is not the interesting case, because
// macaroon satisfaction refuses an uncomparable value on its own (asserted at the
// bottom of this file). Where the credential does not cap the field, the policy
// rule is the only thing standing between an action and the approval gate.
func newHarnessNoAmountCaveat(t *testing.T) *harness {
	t.Helper()
	h := &harness{resolver: did.FileResolver{Root: didsRoot}, acme: sign(t, didAcme)}

	base := macaroon.Mint(seed32(0x01), "cred-proxy-1", didAlice)
	mAcme := att(t, base, "action.type", "==", "payment.transfer")
	mWorker := att(t, mAcme, "target", "==", "acct/999")
	mHelper := att(t, mWorker, "currency", "==", "USD")

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

func (h *harness) transfer(t *testing.T, amount string) *Result {
	t.Helper()
	px := h.proxy(t)
	tip := px.Tip()
	a := types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": amount, "currency": "USD"}, Timestamp: fixedTime}
	// No Approver and no Approval: what an agent submits with no human in the loop.
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0")})
	if err != nil {
		t.Fatalf("amount=%q was not attributable: %v", amount, err)
	}
	return res
}

// TestIndeterminateAmountCannotSkipApproval pins the end of the path the
// classifier's indeterminate outcome exists to close, against the shipped
// commerce policy rather than a synthetic one.
//
// commerce-security.json declares a routine default and uses high-value-transfer
// (amount >= 100) to say which transfers need a human. So the rule firing is what
// gates, and anything that stops it firing is what does not. An operand the rule
// cannot compare must therefore not be answered by the default.
func TestIndeterminateAmountCannotSkipApproval(t *testing.T) {
	h := newHarnessNoAmountCaveat(t)

	// The control, and it is not optional. Every assertion below passes if
	// high-value-transfer simply stopped firing, which would be a far worse
	// regression wearing this test as a green light. So the gate is shown working
	// for an amount that genuinely is over the threshold, denied for the RIGHT
	// reason: it is consequential and no approval was presented.
	t.Run("control: a genuine large amount is gated", func(t *testing.T) {
		res := h.transfer(t, "1000")
		if res.Decision.Allowed {
			t.Fatalf("a consequential transfer was allowed without approval: %+v", res.Decision)
		}
		if !res.Decision.Consequential || res.Decision.RuleFired != "high-value-transfer" {
			t.Fatalf("the gating rule no longer fires for a real amount, so the cases below prove nothing: %+v", res.Decision)
		}
		if !strings.Contains(res.Decision.Reason, "approval") {
			t.Fatalf("denied, but not for want of approval: %+v", res.Decision)
		}
	})

	// Every route to an operand the rule cannot compare. They are one situation
	// reached many ways, and catching some of them would read as fixed.
	for _, amount := range []string{"Inf", "+Inf", "-Inf", "Infinity", "1e400", "-1e400", "abc", "", "0x10"} {
		t.Run("amount="+amount, func(t *testing.T) {
			res := h.transfer(t, amount)
			if res.Decision.Allowed {
				t.Errorf("amount=%q was ALLOWED with no human approval: %+v", amount, res.Decision)
			}
			if !res.Decision.Consequential {
				t.Errorf("amount=%q was recorded as routine: %+v", amount, res.Decision)
			}
			if res.Decision.RuleFired != "high-value-transfer" {
				t.Errorf("amount=%q was answered by %q rather than by the rule that could not evaluate it: %+v",
					amount, res.Decision.RuleFired, res.Decision)
			}
		})
	}
}

// TestIndeterminateDenialVerifies checks the other half: a denial the proxy
// recorded for this reason is one the independent verifier accepts as evidence.
//
// The verifier re-derives consequentiality from the carried policy through the
// same Evaluate the proxy used, so a denial it could not reproduce would fail the
// export. Asserting it here is what makes the two paths agreeing a tested property
// rather than an assumption about shared code.
func TestIndeterminateDenialVerifies(t *testing.T) {
	h := newHarnessNoAmountCaveat(t)
	px := h.proxy(t)
	tip := px.Tip()
	a := types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "Inf", "currency": "USD"}, Timestamp: fixedTime}
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0")}); err != nil {
		t.Fatal(err)
	}
	res := h.verify(t, px)
	if !res.Pass() {
		t.Fatalf("the verifier rejected an export whose only entry is an indeterminate denial: %+v", res)
	}
}

// TestCaveatAlsoRefusesAnUncomparableAmount records the bound, so that the
// coverage above is not mistaken for the whole of it.
//
// Where a credential DOES cap the field by caveat, caveat satisfaction refuses an
// uncomparable operand on its own, and did so before the classifier had an
// indeterminate outcome at all. The policy path was the one that needed closing;
// this asserts the other path is still shut, so a later change to one cannot
// quietly become the only thing holding.
//
// Asserted against macaroon.Satisfies DIRECTLY rather than through the proxy, and
// that is the point rather than a convenience. Handle evaluates policy before
// caveats and returns on a hard deny, so an indeterminate operand is now answered
// by the classifier and never reaches satisfaction at all. A test driven through
// the proxy would pass while proving nothing about the caveat, which is the shape
// this repository has learned to distrust: the request no longer reaches the path
// it claims to be testing.
func TestCaveatAlsoRefusesAnUncomparableAmount(t *testing.T) {
	h := newHarness(t) // terminal chain carries amount <= 100
	terminal := &h.chain.Links[len(h.chain.Links)-1].Credential

	ctx := macaroon.Context(action("Inf").Context())
	for k, v := range terminal.HolderContext() {
		ctx[k] = v
	}
	err := macaroon.Satisfies(terminal.Macaroon, ctx)
	if err == nil {
		t.Fatal("caveat satisfaction accepted an uncomparable amount against a finite bound")
	}
	if !strings.Contains(err.Error(), "not a scalar") {
		t.Fatalf("refused, but not for being uncomparable: %v", err)
	}

	// The control: the same caveat still admits an amount that genuinely satisfies
	// it, so the assertion above is not passing because satisfaction broke.
	okCtx := macaroon.Context(action("50").Context())
	for k, v := range terminal.HolderContext() {
		okCtx[k] = v
	}
	if err := macaroon.Satisfies(terminal.Macaroon, okCtx); err != nil {
		t.Fatalf("the caveat no longer admits a valid amount, so the case above proves nothing: %v", err)
	}
}
