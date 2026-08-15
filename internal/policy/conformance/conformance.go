// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package conformance is the semantic contract every policy.Evaluator
// implementation must satisfy, written once and run against each of them.
//
// It exists because of what a single implementation can and cannot prove. The
// hand-rolled classifier in internal/policy has an extensive test suite, but
// every one of those tests calls *Policy directly, so they pin the classifier's
// behavior rather than the interface's meaning. That is enough to show the
// boundary is not obviously wrong; it is not enough to show it is right. A
// second, independently built implementation running these same cases is what
// turns "Evaluator compiles for two types" into "Evaluator means the same thing
// to two types".
//
// The cases below are therefore written against the INTERFACE, never against a
// concrete evaluator, and deliberately cover the parts of the semantics that are
// easy to reimplement subtly differently: first-match-wins ordering, the
// fail-closed treatment of an absent field (including under "!=", where the
// natural reading of "not equal" gets it backwards), scalar coercion of both
// numbers and timestamps, and the default block as the statement of posture.
//
// What this suite does NOT cover is policy PARSING and validation, which is not
// part of Evaluator. Both implementations reuse policy.Parse, and should: a
// backend that accepted policies the proxy would reject is the divergence the
// exported Validate already exists to prevent. The contract here is about how a
// validated policy evaluates an action.
//
// This package imports "testing" and is consumed only by tests. It is a normal
// (non _test.go) package for one reason: a _test.go file cannot be imported
// across a module boundary, and experimental/policy-opa is a separate module.
package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// NewEvaluator builds the implementation under test from policy JSON.
//
// It takes bytes rather than a *policy.Policy so an implementation is free to
// compile the policy into whatever form it evaluates (a Rego module, say), and
// so the suite cannot accidentally hand an implementation a half-built policy
// that never went through validation.
type NewEvaluator func(t *testing.T, policyJSON []byte) policy.Evaluator

// Want is the part of a types.Decision that policy evaluation is responsible
// for. StatusCheckedHops is deliberately absent: the interface's own doc comment
// assigns it to the enforcement point, so a conformance suite that asserted on
// it would be testing a promise Evaluator does not make.
type Want struct {
	Allowed       bool
	Consequential bool
	RuleFired     string
	Reason        string
}

// Case is one policy, one action, and the decision every conformant evaluator
// must return for them.
type Case struct {
	Name   string
	Policy string
	Action types.Action
	Want   Want
}

// fixedTime is the timestamp every case's action carries, so that the "expiry"
// reserved field is a known value the ordering cases can compare against. It is
// fixed rather than time.Now() because a conformance case whose result depends
// on the wall clock is a conformance case that eventually fails on its own.
var fixedTime = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// Posture fixtures. These two default blocks are the whole of a deployment's
// posture (see the policy package README), and every synthetic case below picks
// one of them, so the suite states which posture it is asserting under rather
// than leaving it implicit.
const (
	denyListDefault  = `"default":{"allowed":true,"consequential":false,"reason":"routine by default"}`
	allowListDefault = `"default":{"allowed":true,"consequential":true,"reason":"approval-gated by default"}`
)

// oneRule renders a single-rule policy so an operator can be exercised in
// isolation. Isolation is the point: with first-match-wins, a policy carrying
// one rule per operator would only ever exercise the first one that matched.
func oneRule(field, op, value string) string {
	return fmt.Sprintf(
		`{"version":"conformance-v1","rules":[{"name":"r","when":[{"field":%q,"op":%q,"value":%q}],"consequential":true,"reason":"rule fired"}],%s}`,
		field, op, value, denyListDefault)
}

// matched and unmatched are the two outcomes of every oneRule case: the rule
// fired, or the deny-list default did.
var (
	matched   = Want{Allowed: true, Consequential: true, RuleFired: "r", Reason: "rule fired"}
	unmatched = Want{Allowed: true, Consequential: false, RuleFired: policy.DefaultRule, Reason: "routine by default"}
)

// act builds an action carrying the given attributes at fixedTime.
func act(typ string, attrs map[string]string) types.Action {
	return types.Action{Type: typ, Target: "res-1", Attributes: attrs, Timestamp: fixedTime}
}

// Cases is the full synthetic surface. Exported so an implementation can report
// which case failed without re-deriving the list.
func Cases() []Case {
	return []Case{
		// ---- equality ----
		{"eq matches", oneRule("amount", "==", "100"), act("payment.transfer", map[string]string{"amount": "100"}), matched},
		{"eq is exact string comparison, not numeric", oneRule("amount", "==", "100"), act("payment.transfer", map[string]string{"amount": "100.0"}), unmatched},
		{"eq on absent field", oneRule("amount", "==", "100"), act("payment.transfer", nil), unmatched},

		// "!=" against an ABSENT field is the case most likely to be reimplemented
		// backwards, because "the field is not equal to 100" reads as true when the
		// field does not exist. The hand-rolled classifier returns false for any
		// absent field BEFORE it looks at the operator, so absence fails closed
		// under every operator including this one. An implementation that gets this
		// wrong turns a missing attribute into a rule match, which under a deny rule
		// is a denial nobody wrote and under a routine rule is a bypass.
		{"ne matches on a different value", oneRule("audience", "!=", "internal"), act("post.publish", map[string]string{"audience": "external"}), matched},
		{"ne does not match on an equal value", oneRule("audience", "!=", "internal"), act("post.publish", map[string]string{"audience": "internal"}), unmatched},
		{"ne on absent field fails closed", oneRule("audience", "!=", "internal"), act("post.publish", nil), unmatched},

		// ---- ordering, numeric ----
		{"ge above bound", oneRule("amount", ">=", "100"), act("payment.transfer", map[string]string{"amount": "500"}), matched},
		{"ge at bound", oneRule("amount", ">=", "100"), act("payment.transfer", map[string]string{"amount": "100"}), matched},
		{"ge below bound", oneRule("amount", ">=", "100"), act("payment.transfer", map[string]string{"amount": "99"}), unmatched},
		{"gt at bound does not match", oneRule("amount", ">", "100"), act("payment.transfer", map[string]string{"amount": "100"}), unmatched},
		{"gt above bound", oneRule("amount", ">", "100"), act("payment.transfer", map[string]string{"amount": "100.01"}), matched},
		{"le at bound", oneRule("amount", "<=", "25"), act("payment.transfer", map[string]string{"amount": "25"}), matched},
		{"le above bound", oneRule("amount", "<=", "25"), act("payment.transfer", map[string]string{"amount": "26"}), unmatched},
		{"lt below bound", oneRule("amount", "<", "25"), act("payment.transfer", map[string]string{"amount": "24.9"}), matched},
		{"ordering handles a negative value", oneRule("delta", "<", "0"), act("ledger.adjust", map[string]string{"delta": "-5"}), matched},

		// A field the policy compares numerically but the action supplies as prose
		// cannot be ordered, and an unorderable comparison must fail closed rather
		// than sort lexically or coerce to zero.
		{"ordering against a non-scalar field fails closed", oneRule("amount", ">=", "100"), act("payment.transfer", map[string]string{"amount": "lots"}), unmatched},
		{"ordering on absent field fails closed", oneRule("amount", ">=", "100"), act("payment.transfer", nil), unmatched},

		// An infinity must not satisfy a finite bound, in either direction.
		//
		// This case could not be written until both implementations agreed on it,
		// which is the useful part of its history. The OPA backend refused these
		// from the start, because Rego's to_number does; the classifier accepted
		// them, because strconv.ParseFloat does, and "-Inf" therefore satisfied
		// every upper bound. Under allow-list posture that matched a ROUTINE rule
		// and skipped the approval gate. A conformance case has to pass for both
		// backends, so the divergence had to be fixed before the contract could
		// state the rule; the differential test is what surfaced it in the first
		// place.
		//
		// Both spellings are covered, the literal and the overflow, since they are
		// one value reached two ways and were once treated differently.
		{"an infinity does not satisfy an upper bound", oneRule("amount", "<=", "25"), act("payment.transfer", map[string]string{"amount": "-Inf"}), unmatched},
		{"an infinity does not satisfy a lower bound", oneRule("amount", ">=", "100"), act("payment.transfer", map[string]string{"amount": "Inf"}), unmatched},
		{"an overflowing literal is refused the same way", oneRule("amount", "<=", "25"), act("payment.transfer", map[string]string{"amount": "-1e400"}), unmatched},

		// ---- ordering, timestamps ----
		// asScalar parses RFC3339 as Unix nanoseconds, so the ordering operators
		// work on instants as well as amounts. "expiry" is always present, since
		// Action.Context writes it from the action's own timestamp.
		{"expiry before a later bound", oneRule(types.FieldExpiry, "<", "2027-01-01T00:00:00Z"), act("document.export", nil), matched},
		{"expiry after an earlier bound", oneRule(types.FieldExpiry, ">", "2025-01-01T00:00:00Z"), act("document.export", nil), matched},
		{"expiry not before an earlier bound", oneRule(types.FieldExpiry, "<", "2025-01-01T00:00:00Z"), act("document.export", nil), unmatched},
		{"an attribute timestamp orders the same way", oneRule("deadline", ">=", "2026-01-01T00:00:00Z"), act("task.close", map[string]string{"deadline": "2026-09-09T00:00:00Z"}), matched},

		// ---- set membership ----
		{"in matches a member", oneRule("region", "in", "us,eu,apac"), act("data.move", map[string]string{"region": "eu"}), matched},
		{"in does not match a non-member", oneRule("region", "in", "us,eu,apac"), act("data.move", map[string]string{"region": "cn"}), unmatched},
		{"in trims whitespace around members", oneRule("region", "in", "us, eu , apac"), act("data.move", map[string]string{"region": "eu"}), matched},
		{"in does not trim the action's value", oneRule("region", "in", "us,eu"), act("data.move", map[string]string{"region": " eu"}), unmatched},
		{"in with a single member behaves as equality", oneRule("region", "in", "us"), act("data.move", map[string]string{"region": "us"}), matched},
		{"in on absent field", oneRule("region", "in", "us,eu"), act("data.move", nil), unmatched},

		// ---- reserved fields ----
		// The reserved names are written into the context AFTER attributes
		// precisely so a hostile attribute cannot shadow them. An evaluator that
		// resolved fields against Attributes first would pass every other case here
		// and silently let "action.type" be spoofed.
		{"action.type is matchable", oneRule(types.FieldActionType, "==", "payment.wire"), act("payment.wire", nil), matched},
		{"target is matchable", oneRule(types.FieldTarget, "==", "res-1"), act("payment.wire", nil), matched},
		{
			"an attribute cannot shadow a reserved field",
			oneRule(types.FieldActionType, "==", "payment.wire"),
			act("post.publish", map[string]string{types.FieldActionType: "payment.wire"}),
			unmatched,
		},

		// ---- conjunction ----
		{
			"all conditions must hold",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[{"name":"r","when":[{"field":"amount","op":">=","value":"100"},{"field":"currency","op":"==","value":"USD"}],"consequential":true,"reason":"rule fired"}],%s}`, denyListDefault),
			act("payment.transfer", map[string]string{"amount": "500", "currency": "USD"}),
			matched,
		},
		{
			"one failing condition sinks the rule",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[{"name":"r","when":[{"field":"amount","op":">=","value":"100"},{"field":"currency","op":"==","value":"USD"}],"consequential":true,"reason":"rule fired"}],%s}`, denyListDefault),
			act("payment.transfer", map[string]string{"amount": "500", "currency": "EUR"}),
			unmatched,
		},
		{
			"a rule with no conditions on the action's fields still needs them present",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[{"name":"r","when":[{"field":"amount","op":">=","value":"100"},{"field":"currency","op":"==","value":"USD"}],"consequential":true,"reason":"rule fired"}],%s}`, denyListDefault),
			act("payment.transfer", map[string]string{"amount": "500"}),
			unmatched,
		},

		// ---- ordering between rules ----
		// First-match-wins is the property most at risk from a declarative backend,
		// where rule order carries no meaning unless the translation puts it back.
		{
			"the earlier of two matching rules wins",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[
				{"name":"first","when":[{"field":"amount","op":">=","value":"100"}],"consequential":true,"reason":"first fired"},
				{"name":"second","when":[{"field":"audience","op":"==","value":"external"}],"deny":true,"reason":"second fired"}
			],%s}`, denyListDefault),
			act("payment.transfer", map[string]string{"amount": "500", "audience": "external"}),
			Want{Allowed: true, Consequential: true, RuleFired: "first", Reason: "first fired"},
		},
		{
			"order is the policy's order, not the order of severity",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[
				{"name":"routine","when":[{"field":"amount","op":"<=","value":"25"}],"reason":"micro transfer"},
				{"name":"forbidden","when":[{"field":"action.type","op":"==","value":"payment.wire"}],"deny":true,"reason":"wires are forbidden"}
			],%s}`, denyListDefault),
			act("payment.wire", map[string]string{"amount": "5"}),
			Want{Allowed: true, Consequential: false, RuleFired: "routine", Reason: "micro transfer"},
		},
		{
			"a deny rule listed first wins over a later routine rule",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[
				{"name":"forbidden","when":[{"field":"action.type","op":"==","value":"payment.wire"}],"deny":true,"reason":"wires are forbidden"},
				{"name":"routine","when":[{"field":"amount","op":"<=","value":"25"}],"reason":"micro transfer"}
			],%s}`, denyListDefault),
			act("payment.wire", map[string]string{"amount": "5"}),
			Want{Allowed: false, Consequential: false, RuleFired: "forbidden", Reason: "wires are forbidden"},
		},

		// ---- the default block as posture ----
		{
			"deny-list posture: unmatched is routine",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[],%s}`, denyListDefault),
			act("anything.at.all", nil),
			unmatched,
		},
		{
			"allow-list posture: unmatched is consequential",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[],%s}`, allowListDefault),
			act("anything.at.all", nil),
			Want{Allowed: true, Consequential: true, RuleFired: policy.DefaultRule, Reason: "approval-gated by default"},
		},
		{
			"a stated closed world denies with its stated reason",
			`{"version":"conformance-v1","rules":[],"default":{"allowed":false,"consequential":false,"reason":"closed world: deny anything unmatched"}}`,
			act("anything.at.all", nil),
			Want{Allowed: false, Consequential: false, RuleFired: policy.DefaultRule, Reason: "closed world: deny anything unmatched"},
		},
		{
			"a deny rule and a deny default are distinguishable by RuleFired",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[{"name":"forbidden","when":[{"field":"action.type","op":"==","value":"payment.wire"}],"deny":true,"reason":"wires are forbidden"}],%s}`, denyListDefault),
			act("payment.wire", nil),
			Want{Allowed: false, Consequential: false, RuleFired: "forbidden", Reason: "wires are forbidden"},
		},

		// A rule may be BOTH denied and consequential. Nothing in the schema
		// prevents it and the classifier carries both bits through independently,
		// so an implementation that treated deny as implying not-consequential
		// (or collapsed the pair into one enum) would fail here and nowhere else.
		{
			"deny and consequential are independent bits",
			fmt.Sprintf(`{"version":"conformance-v1","rules":[{"name":"both","when":[{"field":"action.type","op":"==","value":"db.drop"}],"deny":true,"consequential":true,"reason":"denied and consequential"}],%s}`, denyListDefault),
			act("db.drop", nil),
			Want{Allowed: false, Consequential: true, RuleFired: "both", Reason: "denied and consequential"},
		},
	}
}

// Run executes the whole contract against evaluators built by newEval.
//
// examplesDir is the path to examples/policies relative to the CALLING test's
// working directory, because the two modules that run this suite sit at
// different depths and a package cannot embed files outside its own tree. The
// shipped example policies are run rather than copied for the usual reason: a
// copy is a second place to remember, and one of the two goes stale quietly.
func Run(t *testing.T, examplesDir string, newEval NewEvaluator) {
	t.Helper()
	t.Run("Synthetic", func(t *testing.T) { runCases(t, Cases(), newEval) })
	t.Run("ExamplePolicies", func(t *testing.T) { runExamples(t, examplesDir, newEval) })
	t.Run("VersionIsReported", func(t *testing.T) {
		e := newEval(t, []byte(fmt.Sprintf(`{"version":"a-particular-version","rules":[],%s}`, denyListDefault)))
		if got := e.Version(); got != "a-particular-version" {
			t.Fatalf("Version() = %q, want %q", got, "a-particular-version")
		}
	})
}

func runCases(t *testing.T, cases []Case, newEval NewEvaluator) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			e := newEval(t, []byte(tc.Policy))
			got, err := e.Evaluate(tc.Action)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			assertDecision(t, got, tc.Want, "conformance-v1")
		})
	}
}

// assertDecision compares every field policy evaluation owns. Reason is compared
// exactly, not merely for non-emptiness: the reason is copied verbatim into a
// signed, hash-chained audit entry, so "some reason" is not the contract, "the
// reason the policy stated" is.
func assertDecision(t *testing.T, got types.Decision, want Want, version string) {
	t.Helper()
	if got.Allowed != want.Allowed {
		t.Errorf("Allowed = %v, want %v", got.Allowed, want.Allowed)
	}
	if got.Consequential != want.Consequential {
		t.Errorf("Consequential = %v, want %v", got.Consequential, want.Consequential)
	}
	if got.RuleFired != want.RuleFired {
		t.Errorf("RuleFired = %q, want %q", got.RuleFired, want.RuleFired)
	}
	if got.Reason != want.Reason {
		t.Errorf("Reason = %q, want %q", got.Reason, want.Reason)
	}
	if version != "" && got.PolicyVersion != version {
		t.Errorf("PolicyVersion = %q, want %q", got.PolicyVersion, version)
	}
	// StatusCheckedHops belongs to the enforcement point, and the interface says
	// so. An evaluator that set it would be making a claim about a revocation
	// sweep it never performed, which is exactly the assertion R2-01 removed from
	// the evidence format.
	if got.StatusCheckedHops != 0 {
		t.Errorf("StatusCheckedHops = %d, want 0: policy does not check status", got.StatusCheckedHops)
	}
}

// exampleCase is an expectation against one of the shipped example policies.
type exampleCase struct {
	name      string
	action    types.Action
	allowed   bool
	conseq    bool
	ruleFired string
}

// runExamples drives the policies that ship in examples/policies, which are the
// closest thing the project has to policies written by a user rather than by a
// test. They also carry the property the synthetic cases cannot: the same action
// classifies differently under different environments.
func runExamples(t *testing.T, dir string, newEval NewEvaluator) {
	t.Helper()
	files := []struct {
		file    string
		version string
		cases   []exampleCase
	}{
		{
			file:    "commerce-security.json",
			version: "commerce-security-v1",
			cases: []exampleCase{
				{"below threshold", act("payment.transfer", map[string]string{"amount": "50"}), true, false, policy.DefaultRule},
				{"at threshold", act("payment.transfer", map[string]string{"amount": "100"}), true, true, "high-value-transfer"},
				{"above threshold", act("payment.transfer", map[string]string{"amount": "500"}), true, true, "high-value-transfer"},
				{"forbidden wire", act("payment.wire", map[string]string{"amount": "10"}), false, false, "forbidden-wire"},
				{"production deploy", act("code.deploy", map[string]string{"environment": "production"}), true, true, "production-deploy"},
				{"staging deploy", act("code.deploy", map[string]string{"environment": "staging"}), true, false, policy.DefaultRule},
				{"external audience", act("post.publish", map[string]string{"audience": "external"}), true, true, "external-audience"},
				{"internal audience", act("post.publish", map[string]string{"audience": "internal"}), true, false, policy.DefaultRule},
				// Matches high-value-transfer and external-audience both; the
				// earlier one must win.
				{"two matching rules", act("payment.transfer", map[string]string{"amount": "500", "audience": "external"}), true, true, "high-value-transfer"},
				// Consequentiality is environment-defined: this is routine here and
				// consequential under the legal policy below.
				{"bulk export is routine here", act("document.export", map[string]string{"docCount": "2000"}), true, false, policy.DefaultRule},
			},
		},
		{
			file:    "legal-ediscovery.json",
			version: "legal-ediscovery-v1",
			cases: []exampleCase{
				{"privileged material", act("document.review", map[string]string{"privileged": "true"}), true, true, "privileged-material"},
				{"routine review", act("document.review", map[string]string{"privileged": "false"}), true, false, policy.DefaultRule},
				{"bulk export", act("document.export", map[string]string{"docCount": "2000"}), true, true, "bulk-export"},
				{"small export", act("document.export", map[string]string{"docCount": "500"}), true, false, policy.DefaultRule},
				{"opposing counsel", act("document.produce", map[string]string{"audience": "opposing-counsel"}), true, true, "external-production"},
				// The mirror of the commerce case above.
				{"a large transfer is routine here", act("payment.transfer", map[string]string{"amount": "500"}), true, false, policy.DefaultRule},
			},
		},
		{
			file:    "commerce-security-allowlist.json",
			version: "commerce-security-allowlist-v1",
			cases: []exampleCase{
				{"read-only lookup", act("account.read", nil), true, false, "read-only-lookup"},
				{"payment status", act("payment.status", nil), true, false, "read-only-lookup"},
				{"micro transfer", act("payment.transfer", map[string]string{"amount": "10"}), true, false, "micro-transfer"},
				{"at micro ceiling", act("payment.transfer", map[string]string{"amount": "25"}), true, false, "micro-transfer"},
				{"internal post", act("post.publish", map[string]string{"audience": "internal"}), true, false, "internal-post"},
				// Under allow-list posture an unmatched action is approval-gated,
				// and an action missing the attribute a rule needs is unmatched.
				{"above micro ceiling", act("payment.transfer", map[string]string{"amount": "26"}), true, true, policy.DefaultRule},
				{"unknown action type", act("database.drop", nil), true, true, policy.DefaultRule},
				{"external post", act("post.publish", map[string]string{"audience": "external"}), true, true, policy.DefaultRule},
				{"transfer with no amount fails closed", act("payment.transfer", nil), true, true, policy.DefaultRule},
				{"forbidden wire still denies", act("payment.wire", map[string]string{"amount": "1"}), false, false, "forbidden-wire"},
				// The deny rule precedes the routine rules, so a small wire is
				// denied rather than let through as routine.
				{"deny outranks a later routine rule", act("payment.wire", map[string]string{"amount": "5"}), false, false, "forbidden-wire"},
			},
		},
	}

	for _, f := range files {
		t.Run(f.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, f.file))
			if err != nil {
				t.Fatalf("read example policy: %v", err)
			}
			e := newEval(t, raw)
			if got := e.Version(); got != f.version {
				t.Fatalf("Version() = %q, want %q", got, f.version)
			}
			for _, tc := range f.cases {
				t.Run(tc.name, func(t *testing.T) {
					got, err := e.Evaluate(tc.action)
					if err != nil {
						t.Fatalf("Evaluate: %v", err)
					}
					if got.Allowed != tc.allowed || got.Consequential != tc.conseq || got.RuleFired != tc.ruleFired {
						t.Fatalf("got {allowed:%v conseq:%v rule:%q}, want {allowed:%v conseq:%v rule:%q}",
							got.Allowed, got.Consequential, got.RuleFired, tc.allowed, tc.conseq, tc.ruleFired)
					}
					if got.PolicyVersion != f.version {
						t.Errorf("PolicyVersion = %q, want %q", got.PolicyVersion, f.version)
					}
					if got.Reason == "" {
						t.Error("decision carries no reason")
					}
				})
			}
		})
	}
}
