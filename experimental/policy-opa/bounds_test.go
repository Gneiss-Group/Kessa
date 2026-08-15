// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package opaeval

import (
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// An evaluation the caller can make unbounded is a cost the untrusted party
// controls, on a path already serialized behind one mutex. The bound is Kessa's
// responsibility even though the work happens inside a dependency, so it is
// asserted here rather than assumed from OPA being fast.
//
// In-package (not opaeval_test) so it can shorten evalTimeout. That is the only
// reason evalTimeout is a var, and there is no other way to test a deadline
// without either waiting for the real one or writing a policy pathological enough
// to blow it, which would be testing OPA rather than the bound.
func TestEvaluationIsBounded(t *testing.T) {
	e, err := New([]byte(`{"version":"bounded-v1","rules":[
		{"name":"r","when":[{"field":"amount","op":">=","value":"100"}],"consequential":true,"reason":"rule fired"}
	],"default":{"allowed":true,"consequential":false,"reason":"routine by default"}}`))
	if err != nil {
		t.Fatal(err)
	}
	act := types.Action{Type: "payment.transfer", Target: "res-1",
		Attributes: map[string]string{"amount": "500"}, Timestamp: time.Now()}

	// The control first: with the real bound this evaluates fine, so the failure
	// below is the deadline and not a broken policy.
	if _, err := e.Evaluate(act); err != nil {
		t.Fatalf("a normal evaluation did not complete within the real bound: %v", err)
	}

	// A deadline that has already passed by the time Eval is called. Nothing can
	// finish inside it, so this isolates the bound from how fast OPA happens to be
	// on the machine running the test.
	restore := evalTimeout
	evalTimeout = -1
	defer func() { evalTimeout = restore }()

	_, err = e.Evaluate(act)
	if err == nil {
		t.Fatal("an evaluation past its deadline returned a decision rather than an error")
	}
	if !strings.Contains(err.Error(), "opaeval: evaluate") {
		t.Errorf("failed, but not as an evaluation error: %v", err)
	}
	// internal/enforce turns any policy error into a denial, so an error here is
	// what fail-closed looks like from this side of the seam. Asserting the shape
	// matters because a nil error with a zero Decision would be a silent ALLOW-
	// shaped value instead.
	var zero types.Decision
	if d, _ := e.Evaluate(act); d != zero {
		t.Errorf("a failed evaluation returned a non-zero decision: %+v", d)
	}
}
