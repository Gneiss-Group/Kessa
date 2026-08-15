// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// panickingEvaluator is the thing policy.Evaluator's existence makes possible:
// an implementation that is not the shipped classifier and does not behave.
type panickingEvaluator struct{ marker string }

func (e panickingEvaluator) Version() string { return "panics-v1" }
func (e panickingEvaluator) Evaluate(types.Action) (types.Decision, error) {
	panic("evaluator exploded, carrying " + e.marker)
}

// TestPanickingEvaluatorBecomesARecordedDenial pins a property of the SEAM, not
// of either backend, which is why it uses a stub rather than a real evaluator.
//
// Without recovery the panic unwinds into net/http, which recovers it per
// connection: the caller sees a dropped connection and NO AUDIT ENTRY IS WRITTEN.
// The request vanishes. For a system whose claim is that consequential actions do
// not happen outside the audit trail, that is the worse of the two failures, so
// the recovered form is not merely tidier, it is the one that keeps the record
// complete.
func TestPanickingEvaluatorBecomesARecordedDenial(t *testing.T) {
	h := newHarness(t)
	var logged []string
	px := h.proxyWith(t, panickingEvaluator{marker: "panic-detail-marker-not-a-credential"},
		func(format string, args ...any) { logged = append(logged, format) })

	tip := px.Tip()
	a := action("100")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0")})
	if err != nil {
		t.Fatalf("a panicking evaluator made the request unattributable: %v", err)
	}
	if res.Decision.Allowed {
		t.Fatalf("a panicking evaluator produced an ALLOW: %+v", res.Decision)
	}
	if !strings.Contains(res.Decision.Reason, "policy evaluation failed") {
		t.Errorf("denied, but not as an evaluation failure: %+v", res.Decision)
	}
	// The record is the point: the denial has to be IN the log, not merely returned.
	if got := len(px.Entries()); got != 1 {
		t.Fatalf("the denial was not recorded: log holds %d entries", got)
	}

	// The panic value must not reach the signed entry. It is attacker-influenceable
	// and the entry is hash-chained and re-derived byte for byte by the verifier.
	if strings.Contains(res.Decision.Reason, "panic-detail-marker-not-a-credential") {
		t.Errorf("the panic value was written into a signed audit entry: %q", res.Decision.Reason)
	}
	for _, e := range px.Entries() {
		if strings.Contains(e.Decision.Reason, "panic-detail-marker-not-a-credential") {
			t.Errorf("the panic value reached the log: %q", e.Decision.Reason)
		}
	}
	// It has to go SOMEWHERE, or a panicking evaluator is undebuggable.
	if len(logged) == 0 {
		t.Error("the panic was swallowed entirely, leaving nothing to debug from")
	}
}

// The control. Every assertion above passes if the proxy simply denied
// everything, so the same harness must still allow an ordinary request when the
// evaluator behaves.
func TestNonPanickingEvaluatorIsUnaffected(t *testing.T) {
	h := newHarness(t)
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px := h.proxyWith(t, pol, nil)
	tip := px.Tip()
	a := action("10") // below the gating threshold, so routine
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "n-0")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("a routine action was denied, so the panic cases prove nothing: %+v", res.Decision)
	}
}
