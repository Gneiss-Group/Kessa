// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package opaeval_test

import (
	"strings"
	"sync"
	"testing"

	opaeval "github.com/Gneiss-Group/Kessa/experimental/policy-opa"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/policy/conformance"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestConformance is the point of this module. It runs the identical suite the
// hand-rolled classifier runs in internal/policy/conformance_test.go, from one
// shared definition of the cases, so the two implementations cannot drift into
// agreeing on a test that only one of them is actually run against.
func TestConformance(t *testing.T) {
	conformance.Run(t, "../../examples/policies", func(t *testing.T, policyJSON []byte) policy.Evaluator {
		t.Helper()
		e, err := opaeval.New(policyJSON)
		if err != nil {
			t.Fatalf("opaeval.New: %v", err)
		}
		return e
	})
}

// TestDifferentialAgainstHandRolled compares the two implementations directly,
// on a grid of actions rather than on curated cases.
//
// The conformance suite asserts against expectations a human wrote down, so it
// can only catch divergences someone anticipated. This catches the ones nobody
// did: every action in the cross product is put through both evaluators and the
// full Decision is required to match. It is the cheap stand-in for a
// differential fuzz target, deterministic so it can run in a gate.
func TestDifferentialAgainstHandRolled(t *testing.T) {
	for _, file := range []string{
		"../../examples/policies/commerce-security.json",
		"../../examples/policies/commerce-security-allowlist.json",
		"../../examples/policies/legal-ediscovery.json",
	} {
		t.Run(file, func(t *testing.T) {
			handRolled, err := policy.Load(file)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			opa, err := opaeval.NewFromPolicy(handRolled)
			if err != nil {
				t.Fatalf("NewFromPolicy: %v", err)
			}

			for _, a := range differentialActions() {
				got, err := opa.Evaluate(a)
				if err != nil {
					t.Fatalf("opa.Evaluate(%+v): %v", a, err)
				}
				want, err := handRolled.Evaluate(a)
				if err != nil {
					t.Fatalf("handRolled.Evaluate(%+v): %v", a, err)
				}
				if got != want {
					t.Errorf("divergence on %+v:\n opa = %+v\n ref = %+v", a, got, want)
				}
			}
		})
	}
}

// differentialActions is a cross product built to land on both sides of every
// threshold the example policies contain, and to include actions missing the
// attributes those thresholds read, since an absent field is where the two
// implementations were most likely to part company.
func differentialActions() []types.Action {
	types_ := []string{"payment.transfer", "payment.wire", "payment.status", "account.read", "code.deploy", "post.publish", "document.review", "document.export", "document.produce", "database.drop"}
	amounts := []string{"", "0", "10", "25", "26", "99", "100", "101", "500", "-1", "not-a-number"}
	extras := []map[string]string{
		nil,
		{"audience": "internal"},
		{"audience": "external"},
		{"audience": "opposing-counsel"},
		{"environment": "staging"},
		{"environment": "production"},
		{"privileged": "true"},
		{"privileged": "false"},
		{"docCount": "500"},
		{"docCount": "2000"},
	}

	var out []types.Action
	for _, typ := range types_ {
		for _, amt := range amounts {
			for _, extra := range extras {
				attrs := map[string]string{}
				for k, v := range extra {
					attrs[k] = v
				}
				if amt != "" {
					attrs["amount"] = amt
				}
				out = append(out, types.Action{Type: typ, Target: "res-1", Attributes: attrs})
			}
		}
	}
	return out
}

// TestConcurrentEvaluation guards the property the enforcement proxy depends on:
// one Evaluator is shared across concurrent requests, so Evaluate must be safe
// to call from many goroutines.
//
// The assertion is on the DECISIONS, not merely on the absence of a panic. A
// version that checked only for a crash would still pass if concurrency produced
// wrong answers, and a shared prepared query returning another goroutine's
// decision is a more plausible failure here than a data race is. Run with -race
// for the other half.
func TestConcurrentEvaluation(t *testing.T) {
	e, err := opaeval.New([]byte(`{"version":"concurrent-v1","rules":[
		{"name":"high-value","when":[{"field":"amount","op":">=","value":"100"}],"consequential":true,"reason":"large transfer"}
	],"default":{"allowed":true,"consequential":false,"reason":"routine by default"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Two actions that must classify differently, interleaved across goroutines,
	// so a decision leaking between callers shows up as a wrong answer.
	big := types.Action{Type: "payment.transfer", Attributes: map[string]string{"amount": "500"}}
	small := types.Action{Type: "payment.transfer", Attributes: map[string]string{"amount": "5"}}

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			action, wantRule := big, "high-value"
			if i%2 == 0 {
				action, wantRule = small, policy.DefaultRule
			}
			for range 16 {
				d, err := e.Evaluate(action)
				if err != nil {
					t.Errorf("Evaluate: %v", err)
					return
				}
				if d.RuleFired != wantRule {
					t.Errorf("RuleFired = %q, want %q", d.RuleFired, wantRule)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestUnsupportedOperatorIsRejectedAtLoad pins the fail-loud path in condition().
// A backend that cannot express an operator must refuse the policy, never drop
// the condition: a dropped condition makes its rule match strictly more actions,
// which for a deny rule is a denial nobody wrote and for a routine rule is a
// bypass.
//
// The policy is built in memory rather than parsed, because policy.Parse rejects
// unknown operators first and the load path would therefore never reach the
// translation. That is the correct layering, and it is also exactly how this test
// could have ended up asserting nothing: routed through Parse it would still have
// failed, just never on the line it names.
func TestUnsupportedOperatorIsRejectedAtLoad(t *testing.T) {
	p := &policy.Policy{
		Ver:     "unsupported-v1",
		Rules:   []policy.Rule{{Name: "r", When: []policy.Condition{{Field: "amount", Op: "~=", Value: "1"}}, Reason: "should not compile"}},
		Default: policy.Default{Allowed: true, Reason: "routine"},
	}
	_, err := opaeval.NewFromPolicy(p)
	if err == nil {
		t.Fatal("expected an unsupported operator to be rejected at load time")
	}
	if !strings.Contains(err.Error(), "unsupported operator") {
		t.Fatalf("error %q does not name the unsupported operator", err)
	}
}

// TestGeneratedSourceIsReadable is a light guard on the artifact this experiment
// mostly exists to produce: the translation of a Kessa policy into Rego, which a
// reader has to be able to check by eye.
func TestGeneratedSourceIsReadable(t *testing.T) {
	e, err := opaeval.New([]byte(`{"version":"readable-v1","rules":[
		{"name":"high-value","when":[{"field":"amount","op":">=","value":"100"}],"consequential":true,"reason":"large transfer"}
	],"default":{"allowed":true,"consequential":false,"reason":"routine by default"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	src := e.Source()
	for _, want := range []string{
		"package kessa.policy",
		"default decision :=",
		"matches contains 0 if",
		"considered := matches | {i | some i, _ in uncomparable}",
		"i := min(considered)",
		// The ordering field census a reader needs in order to check the
		// uncomparable set by eye, which is the half of the module that is not
		// simply a transcription of the policy file.
		`ordering_fields := {`,
		`0: ["amount"],`,
		"# high-value",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated module does not contain %q:\n%s", want, src)
		}
	}
}
