// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Allow-list posture driven through the REAL proxy and the REAL verifier.
//
// These are the automated form of the manual end-to-end verification done during
// the 2026-07-22 feasibility review. The point is not that the classifier returns
// the right bit (internal/policy's own tests cover that) but that the posture
// composes correctly with everything downstream of the classifier: the approval
// requirement, the live status check, and the verifier's independent
// re-derivation from the carried policy.
const allowlistPol = "../../examples/policies/commerce-security-allowlist.json"

// proxyWithPolicy is h.proxy with the policy file as a parameter.
func (h *harness) proxyWithPolicy(t *testing.T, path string) *Proxy {
	t.Helper()
	pol, err := policy.Load(path)
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

// A matched routine rule allows WITHOUT approval, even though the deployment's
// default is consequential.
func TestAllowList_RoutineRuleAllowsWithoutApproval(t *testing.T) {
	h := newHarness(t)
	px := h.proxyWithPolicy(t, allowlistPol)

	a := action("10") // <= $25 -> the micro-transfer routine rule fires
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n1")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("expected allow, got %+v", res.Decision)
	}
	if res.Decision.Consequential {
		t.Fatalf("a matched routine rule must not be consequential: %+v", res.Decision)
	}
	if res.Decision.RuleFired != "micro-transfer" {
		t.Fatalf("expected micro-transfer to fire, got %q", res.Decision.RuleFired)
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed: %+v", v.Entries[0])
	}
}

// An action matching NO rule falls to the consequential default, and is therefore
// gated exactly as a rule-matched consequential action would be: it needs a live
// status check and a human approval.
func TestAllowList_UnmatchedActionIsGatedByDefault(t *testing.T) {
	h := newHarness(t)
	px := h.proxyWithPolicy(t, allowlistPol)

	a := action("50") // above the $25 routine ceiling, within the $100 caveat
	res, err := px.Handle(Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n2"),
		Approver: didAlice, Approval: h.approval(t, tip0, didAlice, a),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential || res.Decision.StatusCheckedHops != 1 {
		t.Fatalf("expected a consequential allow with a status check, got %+v", res.Decision)
	}
	if res.Decision.RuleFired != policy.DefaultRule {
		t.Fatalf("expected the default to fire, got %q", res.Decision.RuleFired)
	}
	if res.Entry.ApprovedBy != didAlice || len(res.Entry.Approval) == 0 {
		t.Fatal("approval should be recorded in the entry")
	}
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed: %+v", v.Entries[0])
	}
}

// The same unmatched action, with no approval presented, is DENIED. This is the
// gate that allow-list posture exists to create.
func TestAllowList_UnmatchedActionDeniedWithoutApproval(t *testing.T) {
	h := newHarness(t)
	px := h.proxyWithPolicy(t, allowlistPol)

	a := action("50")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "n3")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatalf("expected denial without approval, got %+v", res.Decision)
	}
	if !strings.Contains(res.Decision.Reason, "human approval") {
		t.Fatalf("denial should name the missing approval, got %q", res.Decision.Reason)
	}
	// A denial is still a faithful, verifiable log entry.
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed: %+v", v.Entries[0])
	}
}

// The SAME action, same chain, same proxy machinery, only the policy file
// differs, is routine under deny-list posture and gated under allow-list
// posture. This is the product claim, tested end to end.
func TestPostureIsTheOnlyDifference(t *testing.T) {
	a := action("50")

	// Deny-list: $50 is below the $100 threshold -> routine, no approval needed.
	hDeny := newHarness(t)
	pxDeny := hDeny.proxyWithPolicy(t, commercePol)
	resDeny, err := pxDeny.Handle(Request{Chain: hDeny.chain, Action: a, PoP: hDeny.pop(t, tip0, a, "n4")})
	if err != nil {
		t.Fatal(err)
	}
	if !resDeny.Decision.Allowed || resDeny.Decision.Consequential {
		t.Fatalf("deny-list: expected routine allow, got %+v", resDeny.Decision)
	}

	// Allow-list: the identical request, with no approval, is denied.
	hAllow := newHarness(t)
	pxAllow := hAllow.proxyWithPolicy(t, allowlistPol)
	resAllow, err := pxAllow.Handle(Request{Chain: hAllow.chain, Action: a, PoP: hAllow.pop(t, tip0, a, "n4")})
	if err != nil {
		t.Fatal(err)
	}
	if resAllow.Decision.Allowed {
		t.Fatalf("allow-list: expected denial, got %+v", resAllow.Decision)
	}
}

// Under allow-list posture, an action missing the attribute a routine rule needs
// cannot match that rule, so it falls to the consequential default, fail-CLOSED.
// Under deny-list posture the identical gap falls through to routine, fail-OPEN.
// This asymmetry is the documented robustness argument for allow-list posture.
func TestAllowList_MissingAttributeFailsClosed(t *testing.T) {
	// No "amount" attribute at all: the micro-transfer rule needs it and an absent
	// field never matches (fail-closed at the condition level).
	a := types.Action{Type: "payment.transfer", Target: "acct/999", Timestamp: fixedTime}

	allowList, err := policy.Load(allowlistPol)
	if err != nil {
		t.Fatal(err)
	}
	denyList, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}

	dAllow, err := allowList.Evaluate(a)
	if err != nil {
		t.Fatal(err)
	}
	if !dAllow.Consequential {
		t.Fatalf("allow-list must fail CLOSED on a missing attribute, got %+v", dAllow)
	}

	dDeny, err := denyList.Evaluate(a)
	if err != nil {
		t.Fatal(err)
	}
	if dDeny.Consequential {
		t.Fatalf("deny-list is expected to fail OPEN here (documented); got %+v", dDeny)
	}
}
