// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"
)

// TestActionContext_ReservedNamesCannotBeShadowed is a security property: an
// action's attributes are attacker-influenced, so they must never be able to
// override action.type, target, or expiry, the fields macaroon caveats and
// policy rules are written against.
func TestActionContext_ReservedNamesCannotBeShadowed(t *testing.T) {
	ts := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	a := Action{
		Type:   "payment.transfer",
		Target: "acct/999",
		Attributes: map[string]string{
			"amount":        "50",
			FieldActionType: "post.publish",         // spoof attempt
			FieldTarget:     "acct/attacker",        // spoof attempt
			FieldExpiry:     "2099-01-01T00:00:00Z", // spoof attempt
		},
		Timestamp: ts,
	}
	ctx := a.Context()

	if got := ctx[FieldActionType]; got != "payment.transfer" {
		t.Fatalf("action.type = %q; an attribute shadowed the reserved field", got)
	}
	if got := ctx[FieldTarget]; got != "acct/999" {
		t.Fatalf("target = %q; an attribute shadowed the reserved field", got)
	}
	if got, want := ctx[FieldExpiry], ts.Format(time.RFC3339Nano); got != want {
		t.Fatalf("expiry = %q, want %q", got, want)
	}
	if got := ctx["amount"]; got != "50" {
		t.Fatalf("non-reserved attribute lost: amount = %q", got)
	}
}

func TestActionContext_IsDeterministic(t *testing.T) {
	a := Action{
		Type:       "post.publish",
		Target:     "blog/hello",
		Attributes: map[string]string{"audience": "external", "amount": "1"},
		Timestamp:  time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
	first := a.Context()
	for range 50 {
		next := a.Context()
		if len(next) != len(first) {
			t.Fatal("context size varies between calls")
		}
		for k, v := range first {
			if next[k] != v {
				t.Fatalf("context key %q varies between calls", k)
			}
		}
	}
}
