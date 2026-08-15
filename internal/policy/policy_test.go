// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	commercePath  = "../../examples/policies/commerce-security.json"
	legalPath     = "../../examples/policies/legal-ediscovery.json"
	allowlistPath = "../../examples/policies/commerce-security-allowlist.json"
)

func loadPolicy(t *testing.T, path string) *Policy {
	t.Helper()
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	return p
}

// action is a small builder for test actions.
func action(typ string, attrs map[string]string) types.Action {
	return types.Action{Type: typ, Attributes: attrs}
}

func TestLoad_ExamplePolicies(t *testing.T) {
	if v := loadPolicy(t, commercePath).Version(); v != "commerce-security-v1" {
		t.Fatalf("commerce version = %q", v)
	}
	if v := loadPolicy(t, legalPath).Version(); v != "legal-ediscovery-v1" {
		t.Fatalf("legal version = %q", v)
	}
}

func TestCommercePolicy_Rules(t *testing.T) {
	p := loadPolicy(t, commercePath)
	cases := []struct {
		name          string
		action        types.Action
		wantAllowed   bool
		wantConseq    bool
		wantRuleFired string
	}{
		{"below threshold", action("payment.transfer", map[string]string{"amount": "50"}), true, false, DefaultRule},
		{"at threshold", action("payment.transfer", map[string]string{"amount": "100"}), true, true, "high-value-transfer"},
		{"above threshold", action("payment.transfer", map[string]string{"amount": "500"}), true, true, "high-value-transfer"},
		{"forbidden wire (deny)", action("payment.wire", map[string]string{"amount": "10"}), false, false, "forbidden-wire"},
		{"prod deploy", action("code.deploy", map[string]string{"environment": "production"}), true, true, "production-deploy"},
		{"staging deploy routine", action("code.deploy", map[string]string{"environment": "staging"}), true, false, DefaultRule},
		{"external audience", action("post.publish", map[string]string{"audience": "external"}), true, true, "external-audience"},
		{"routine", action("post.publish", map[string]string{"audience": "internal"}), true, false, DefaultRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := p.Evaluate(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed != tc.wantAllowed || d.Consequential != tc.wantConseq || d.RuleFired != tc.wantRuleFired {
				t.Fatalf("got {allowed:%v conseq:%v rule:%q} want {allowed:%v conseq:%v rule:%q}",
					d.Allowed, d.Consequential, d.RuleFired, tc.wantAllowed, tc.wantConseq, tc.wantRuleFired)
			}
			if d.PolicyVersion != "commerce-security-v1" {
				t.Fatalf("policy version not recorded: %q", d.PolicyVersion)
			}
			if d.Reason == "" {
				t.Fatal("decision should carry a reason")
			}
		})
	}
}

func TestLegalPolicy_Rules(t *testing.T) {
	p := loadPolicy(t, legalPath)
	cases := []struct {
		name          string
		action        types.Action
		wantConseq    bool
		wantRuleFired string
	}{
		{"privileged access", action("document.review", map[string]string{"privileged": "true"}), true, "privileged-material"},
		{"bulk export", action("document.export", map[string]string{"docCount": "2000"}), true, "bulk-export"},
		{"small export routine", action("document.export", map[string]string{"docCount": "500"}), false, DefaultRule},
		{"production to opposing counsel", action("document.produce", map[string]string{"audience": "opposing-counsel"}), true, "external-production"},
		{"routine review", action("document.review", map[string]string{"privileged": "false"}), false, DefaultRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := p.Evaluate(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if d.Consequential != tc.wantConseq || d.RuleFired != tc.wantRuleFired {
				t.Fatalf("got {conseq:%v rule:%q} want {conseq:%v rule:%q}",
					d.Consequential, d.RuleFired, tc.wantConseq, tc.wantRuleFired)
			}
			if d.PolicyVersion != "legal-ediscovery-v1" {
				t.Fatalf("policy version not recorded: %q", d.PolicyVersion)
			}
		})
	}
}

// TestConsequentialityIsEnvironmentDefined is the whole point of §5: the SAME
// action is consequential in one environment and routine in the other.
func TestConsequentialityIsEnvironmentDefined(t *testing.T) {
	commerce := loadPolicy(t, commercePath)
	legal := loadPolicy(t, legalPath)

	// A $500 transfer: consequential under commerce, routine under legal.
	transfer := action("payment.transfer", map[string]string{"amount": "500"})
	if d, _ := commerce.Evaluate(transfer); !d.Consequential {
		t.Fatal("commerce should classify a $500 transfer as consequential")
	}
	if d, _ := legal.Evaluate(transfer); d.Consequential {
		t.Fatal("legal has no amount rule; a $500 transfer should be routine")
	}

	// A 2000-doc export: consequential under legal, routine under commerce.
	export := action("document.export", map[string]string{"docCount": "2000"})
	if d, _ := legal.Evaluate(export); !d.Consequential {
		t.Fatal("legal should classify a 2000-doc export as consequential")
	}
	if d, _ := commerce.Evaluate(export); d.Consequential {
		t.Fatal("commerce has no export rule; a 2000-doc export should be routine")
	}
}

// TestFirstMatchWins: when multiple rules match, the earliest listed rule fires.
func TestFirstMatchWins(t *testing.T) {
	p := loadPolicy(t, commercePath)
	// Matches both high-value-transfer (listed first) and external-audience.
	a := action("payment.transfer", map[string]string{"amount": "500", "audience": "external"})
	d, _ := p.Evaluate(a)
	if d.RuleFired != "high-value-transfer" {
		t.Fatalf("expected first matching rule to win, got %q", d.RuleFired)
	}
}

// TestEvaluate_OrdersTimestampsToTheNanosecond exercises the real expiry path:
// Action.Context() renders the action's instant at RFC3339Nano precision, so a
// rule bounded on expiry is comparing full-precision timestamps.
//
// It used to compare them as float64(t.UnixNano()), which at a 2026 epoch has
// only 256ns of resolution, so an action inside that window of the bound was
// classified as if it sat exactly on it. The comparison now happens on integer
// nanoseconds in internal/scalar, shared with macaroon caveat satisfaction so
// the proxy and the independent verifier cannot answer this differently.
func TestEvaluate_OrdersTimestampsToTheNanosecond(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	bound := base.Add(100 * time.Nanosecond)

	// Confirm the premise: without it this test passes without testing anything.
	if float64(base.UnixNano()) != float64(bound.UnixNano()) {
		t.Fatal("premise no longer holds: float64 now distinguishes a 100ns delta at this epoch")
	}

	p, err := Parse([]byte(`{"version":"nano-v1","rules":[{"name":"before-bound","when":[{"field":"` +
		FieldExpiry + `","op":"<","value":"` + bound.Format(time.RFC3339Nano) +
		`"}],"consequential":true,"reason":"before the bound"}]` + okDefault + `}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	d, err := p.Evaluate(types.Action{Type: "document.export", Target: "res-1", Timestamp: base})
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleFired != "before-bound" {
		t.Fatalf("an action 100ns before the bound must satisfy the bound, got RuleFired=%q", d.RuleFired)
	}

	// And the instant ON the bound still must not, which is what distinguishes
	// ordering the nanoseconds from ignoring them in the other direction.
	d, err = p.Evaluate(types.Action{Type: "document.export", Target: "res-1", Timestamp: bound})
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleFired != DefaultRule {
		t.Fatalf("an action exactly on an exclusive bound must not satisfy it, got RuleFired=%q", d.RuleFired)
	}
}

// okDefault is a well-formed default block, spliced into the rule-validation
// fixtures below so each one fails for the reason it is named for rather than
// tripping the default-block requirement first.
const okDefault = `,"default":{"allowed":true,"consequential":false,"reason":"routine"}`

func TestParse_Validation(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string // substring the error must contain
	}{
		{"missing version", `{"rules":[]` + okDefault + `}`, "missing version"},
		{"rule without name", `{"version":"v1","rules":[{"when":[{"field":"amount","op":"==","value":"1"}]}]` + okDefault + `}`, "has no name"},
		{"rule without conditions", `{"version":"v1","rules":[{"name":"r"}]` + okDefault + `}`, "no conditions"},
		{"unknown operator", `{"version":"v1","rules":[{"name":"r","when":[{"field":"amount","op":"~=","value":"1"}]}]` + okDefault + `}`, "unknown operator"},
		{"non-scalar bound", `{"version":"v1","rules":[{"name":"r","when":[{"field":"amount","op":">=","value":"lots"}]}]` + okDefault + `}`, "not a scalar"},
		// The far-future instant a policy author reaches for to mean "never".
		// It is a well-formed RFC3339 timestamp, but it is past the range
		// time.Time can express as Unix nanoseconds, where the conversion wraps
		// rather than saturating: the bound would silently become some arbitrary
		// instant, possibly one already in the past. Rejected at load, which is
		// before anything is classified against it (internal/scalar).
		{"bound past the representable instant range", `{"version":"v1","rules":[{"name":"r","when":[{"field":"expiry","op":"<","value":"9999-12-31T23:59:59Z"}]}]` + okDefault + `}`, "not a scalar"},
		{"empty eq value", `{"version":"v1","rules":[{"name":"r","when":[{"field":"x","op":"==","value":""}]}]` + okDefault + `}`, "empty value"},

		// A RULE's reason, which is the same requirement as the default block's
		// one level down. When a rule fires, Evaluate copies its reason into the
		// Decision and the Decision is written verbatim into a signed audit
		// entry, so a rule with no reason produces an entry that verifies
		// perfectly and explains nothing. These two are otherwise entirely
		// well-formed policies: name, conditions and operator are all valid, so
		// the reason is the only thing left to reject them for. Found by this
		// package's FuzzParse.
		{"rule without reason", `{"version":"v1","rules":[{"name":"big transfers","when":[{"field":"amount","op":">=","value":"50"}]}]` + okDefault + `}`, `rule "big transfers" has no reason`},
		{"whitespace rule reason", `{"version":"v1","rules":[{"name":"r","when":[{"field":"amount","op":">=","value":"50"}],"reason":"   "}]` + okDefault + `}`, `rule "r" has no reason`},
		// Ordering: a rule that is wrong in two ways is reported by the more
		// specific complaint. Without this, tightening the reason rule would have
		// silently changed what every malformed-condition case above reports.
		{"bad operator outranks missing reason", `{"version":"v1","rules":[{"name":"r","when":[{"field":"amount","op":"~=","value":"1"}]}]` + okDefault + `}`, "unknown operator"},

		// The default block itself (§2.1). An omitted default is not a neutral
		// omission, Evaluate would deny every unmatched action with a blank reason.
		{"missing default block", `{"version":"v1","rules":[]}`, `missing required "default" block`},
		{"empty default reason", `{"version":"v1","rules":[],"default":{"allowed":true,"consequential":false,"reason":""}}`, "default.reason must not be empty"},
		{"whitespace default reason", `{"version":"v1","rules":[],"default":{"allowed":true,"consequential":false,"reason":"   "}}`, "default.reason must not be empty"},

		// THE SEAM between the two rules above. The presence check alone would let
		// the original footgun back in through a narrower door: a policy that spells
		// out the blank-reason deny-all explicitly, and is accepted because the block
		// is "present". The reason check must fire regardless of the block's contents,
		// so these cases are rejected for the reason, not the presence.
		{"explicit blank-reason deny-all", `{"version":"v1","rules":[],"default":{"allowed":false,"consequential":false,"reason":""}}`, "default.reason must not be empty"},
		{"present but wholly empty default block", `{"version":"v1","rules":[],"default":{}}`, "default.reason must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// An explicitly zero-valued default is a STATED posture and must be accepted,
// only an omitted one is rejected. This is the distinction defaultPresent exists
// to draw, so it gets its own test.
//
// Read this together with the "explicit blank-reason deny-all" case above: what
// makes a zero-valued default acceptable is not that it was written down, it is
// that it was written down WITH A REASON. Presence and reason are two independent
// requirements, and deny-all is only reachable by saying so and saying why.
func TestParse_ExplicitZeroDefaultIsAccepted(t *testing.T) {
	p, err := Parse([]byte(`{"version":"v1","rules":[],"default":{"allowed":false,"consequential":false,"reason":"closed world: deny anything unmatched"}}`))
	if err != nil {
		t.Fatalf("an explicit zero-value default must be accepted: %v", err)
	}
	d, err := p.Evaluate(action("anything", nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || d.Reason == "" {
		t.Fatalf("expected a stated deny with a reason, got %+v", d)
	}
}

// ---- allow-list posture (§1.2.2) -------------------------------------------

// Allow-list posture is the SAME mechanism as deny-list, configured differently:
// default-consequential, with rules asserting routine. These tests pin that the
// evaluation semantics are identical regardless of posture.
func TestAllowListPolicy_Rules(t *testing.T) {
	p := loadPolicy(t, allowlistPath)
	cases := []struct {
		name          string
		action        types.Action
		wantAllowed   bool
		wantConseq    bool
		wantRuleFired string
	}{
		// Explicit routine rules override the consequential default.
		{"read-only lookup", action("account.read", nil), true, false, "read-only-lookup"},
		{"payment status", action("payment.status", nil), true, false, "read-only-lookup"},
		{"micro transfer", action("payment.transfer", map[string]string{"amount": "10"}), true, false, "micro-transfer"},
		{"at micro ceiling", action("payment.transfer", map[string]string{"amount": "25"}), true, false, "micro-transfer"},
		{"internal post", action("post.publish", map[string]string{"audience": "internal"}), true, false, "internal-post"},

		// Nothing matched -> the default-consequential fallback fires.
		{"above micro ceiling", action("payment.transfer", map[string]string{"amount": "26"}), true, true, DefaultRule},
		{"unknown action type", action("database.drop", nil), true, true, DefaultRule},
		{"external post", action("post.publish", map[string]string{"audience": "external"}), true, true, DefaultRule},
		// An action whose attribute is absent cannot match a rule that needs it, so
		// it falls to the default, which under allow-list posture is fail-CLOSED.
		{"transfer with no amount", action("payment.transfer", nil), true, true, DefaultRule},

		// A hard deny still short-circuits regardless of posture.
		{"forbidden wire", action("payment.wire", map[string]string{"amount": "1"}), false, false, "forbidden-wire"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := p.Evaluate(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed != tc.wantAllowed || d.Consequential != tc.wantConseq || d.RuleFired != tc.wantRuleFired {
				t.Fatalf("got {allowed:%v conseq:%v rule:%q} want {allowed:%v conseq:%v rule:%q}",
					d.Allowed, d.Consequential, d.RuleFired, tc.wantAllowed, tc.wantConseq, tc.wantRuleFired)
			}
			if d.PolicyVersion != "commerce-security-allowlist-v1" {
				t.Fatalf("policy version not recorded: %q", d.PolicyVersion)
			}
			if d.Reason == "" {
				t.Fatal("decision should carry a reason")
			}
		})
	}
}

// First-match-wins is a property of the evaluator, not of a posture. Under
// allow-list posture the deny rule still precedes the routine rules, so a wire
// transfer under $25 is DENIED rather than being let through as routine.
func TestAllowList_FirstMatchWinsStillHolds(t *testing.T) {
	p := loadPolicy(t, allowlistPath)
	d, err := p.Evaluate(action("payment.wire", map[string]string{"amount": "5"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleFired != "forbidden-wire" || d.Allowed {
		t.Fatalf("earlier deny rule must win over a later routine rule, got %+v", d)
	}
}

// The posture is the ONLY difference between the two commerce policies: the same
// action classifies differently under each. This is §5's "consequentiality is
// environment-defined" claim, restated for posture.
func TestPostureChangesClassificationOfTheSameAction(t *testing.T) {
	denyList := loadPolicy(t, commercePath)
	allowList := loadPolicy(t, allowlistPath)

	// A $50 transfer: routine under deny-list (below the $100 threshold),
	// consequential under allow-list (above the $25 routine ceiling).
	a := action("payment.transfer", map[string]string{"amount": "50"})

	dDeny, err := denyList.Evaluate(a)
	if err != nil {
		t.Fatal(err)
	}
	dAllow, err := allowList.Evaluate(a)
	if err != nil {
		t.Fatal(err)
	}
	if dDeny.Consequential {
		t.Fatalf("deny-list should classify $50 as routine, got %+v", dDeny)
	}
	if !dAllow.Consequential {
		t.Fatalf("allow-list should classify $50 as consequential, got %+v", dAllow)
	}
}

// TestEvaluate_InfinityCannotBypassARoutineRule is the fail-open closed in
// internal/scalar, asserted where it was reachable rather than only where it was
// caused.
//
// Under allow-list posture the default is approval-gated and a rule's job is to
// declare something ROUTINE, so matching a rule is the permissive outcome. The
// allow-list example's micro-transfer rule is `amount <= 25`. An infinity orders
// below every finite bound, so an action carrying amount="-Inf" matched it and
// came back not consequential, skipping the approval gate that a plain 26
// correctly triggers. Attributes arrive on the proxied request and the agent is
// the untrusted party, which is what made this reachable input rather than a
// curiosity about float syntax.
//
// Every spelling is checked, including the overflow route, because the defect
// was never that one literal was mishandled: it was that infinity could be
// reached at all, and a fix that caught "-Inf" while missing "-1e400" or
// "-infinity" would read as fixed while leaving the gate open.
//
// What is asserted here is now stronger than it was. An operand the rule cannot
// compare no longer means "this rule does not apply", it means the rule cannot be
// evaluated, and a rule that cannot be evaluated denies. So these cases assert a
// DENIAL rather than a fall-through to the approval-gated default.
func TestEvaluate_InfinityCannotBypassARoutineRule(t *testing.T) {
	p := loadPolicy(t, allowlistPath)

	for _, amount := range []string{"-Inf", "-inf", "-Infinity", "-infinity", "-1e400"} {
		t.Run(amount, func(t *testing.T) {
			d, err := p.Evaluate(action("payment.transfer", map[string]string{"amount": amount}))
			if err != nil {
				t.Fatal(err)
			}
			// The rule is now REPORTED rather than skipped: an operand the rule
			// cannot compare makes the rule indeterminate, and an indeterminate rule
			// denies. So RuleFired names micro-transfer while Allowed is false, which
			// is a different statement from micro-transfer having classified this
			// routine.
			if d.Allowed {
				t.Errorf("amount=%q was allowed; an operand no rule can compare must not be: %+v", amount, d)
			}
			if !d.Consequential {
				t.Errorf("amount=%q came back routine, so it skips human approval: %+v", amount, d)
			}
		})
	}

	// The control, and it is not optional. Everything above passes if
	// micro-transfer simply stopped firing, which would be a far worse
	// regression wearing this test as a green light. So the rule is shown still
	// working for an amount that genuinely is below the ceiling.
	d, err := p.Evaluate(action("payment.transfer", map[string]string{"amount": "10"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleFired != "micro-transfer" || d.Consequential {
		t.Fatalf("the routine rule no longer fires for a real amount, so the cases above prove nothing: %+v", d)
	}
}

// TestEvaluate_UncomparableOperandDoesNotReachTheDefault is the same property as
// the test above under the OTHER posture, against the shipped policies that have
// it.
//
// Both of these declare a routine default and use one ordering rule to say which
// actions need a human, so here the rule FIRING is what gates and a rule that does
// not fire is the permissive outcome. That is the reverse of the allow-list case,
// and it is why an operand a rule cannot compare must not be answered by falling
// through: the fall-through lands somewhere different depending on how the policy
// is written, and an uncomparable operand is not a classification either way.
//
// Asserted against the shipped examples rather than a synthetic policy because
// these are the files an operator starts from, and commerce-security.json in
// particular is what the example config, the demo and the enforcement tests all
// load.
func TestEvaluate_UncomparableOperandDoesNotReachTheDefault(t *testing.T) {
	for _, tc := range []struct {
		path, typ, field, gate, ok string
	}{
		{commercePath, "payment.transfer", "amount", "high-value-transfer", "1000"},
		{legalPath, "document.export", "docCount", "bulk-export", "5000"},
	} {
		t.Run(tc.gate, func(t *testing.T) {
			p := loadPolicy(t, tc.path)

			for _, v := range []string{"Inf", "+Inf", "-Inf", "Infinity", "1e400", "abc", "", "0x10"} {
				d, err := p.Evaluate(action(tc.typ, map[string]string{tc.field: v}))
				if err != nil {
					t.Fatal(err)
				}
				if d.Allowed {
					t.Errorf("%s=%q was allowed: %+v", tc.field, v, d)
				}
				if d.RuleFired != tc.gate {
					t.Errorf("%s=%q was answered by %q rather than by the rule that could not evaluate it: %+v",
						tc.field, v, d.RuleFired, d)
				}
			}

			// The control. Everything above passes if the gating rule stopped firing
			// altogether, so it is shown still classifying a real value that is over
			// the threshold.
			d, err := p.Evaluate(action(tc.typ, map[string]string{tc.field: tc.ok}))
			if err != nil {
				t.Fatal(err)
			}
			if d.RuleFired != tc.gate || !d.Consequential || !d.Allowed {
				t.Fatalf("the gating rule no longer classifies a real value, so the cases above prove nothing: %+v", d)
			}
		})
	}
}

// Confirm Policy satisfies the Evaluator interface (swap seam for OPA later).
func TestPolicyImplementsEvaluator(t *testing.T) {
	var _ Evaluator = loadPolicy(t, commercePath)
}
