// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package opaeval_test

import (
	"fmt"
	"testing"
	"time"

	opaeval "github.com/Gneiss-Group/Kessa/experimental/policy-opa"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestKnownDivergence_TimestampPrecisionBelow256ns records the one place the two
// implementations do not agree, and asserts that they still disagree.
//
// A test that asserts a defect is an unusual thing to write, so the reasoning is
// worth stating. The alternative was to describe the divergence in the README and
// leave it at that, which puts the finding one refactor away from being wrong
// with nothing to say so. Pinned like this, whoever eventually changes asScalar
// gets a failure naming this file, and the note that says "the two backends agree
// except here" cannot quietly stop being true in either direction.
//
// # What diverges
//
// internal/policy.asScalar parses an RFC3339 timestamp to float64(t.UnixNano()).
// Around 2026 that value is roughly 1.78e18, which needs 61 bits; float64 carries
// 53 bits of mantissa, so the representable values are 256ns apart. Every instant
// inside a 256ns window collapses onto one number, and the classifier cannot
// order two timestamps closer together than that. OPA's time.parse_rfc3339_ns
// returns exact integer nanoseconds and orders them correctly.
//
// So on this one input class OPA is RIGHT and the shipped classifier is lossy.
// That is a finding about the core, not about the translation, which is most of
// the argument for having built a second implementation from a different author's
// assumptions.
//
// # Why it is not being fixed here
//
// The spec this module was built under (§3) says it does not touch the
// classifier's behavior, and that is the right call for a change with this shape:
// internal/macaroon carries its own byte-identical copy of asScalar, and caveat
// satisfaction is re-derived by the independent verifier. Correcting one copy and
// not the other would make the proxy and the verifier disagree about whether a
// caveat holds, which is a considerably worse defect than 256ns of granularity.
// The two copies are consistent with each other today, so the limit is uniform
// across the system rather than a disagreement inside it, and nothing observable
// is wrong. Fixing it means fixing both together, deliberately.
func TestKnownDivergence_TimestampPrecisionBelow256ns(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Confirm the premise rather than assuming it: if float64 ever stops
	// collapsing these, the rest of this test is asserting nothing.
	if float64(base.UnixNano()) != float64(base.Add(100*time.Nanosecond).UnixNano()) {
		t.Fatal("premise no longer holds: float64 now distinguishes a 100ns delta at this epoch")
	}

	bound := base.Add(100 * time.Nanosecond).Format(time.RFC3339Nano)
	src := fmt.Sprintf(`{"version":"nano-v1","rules":[{"name":"before-bound","when":[{"field":%q,"op":"<","value":%q}],"consequential":true,"reason":"before the bound"}],"default":{"allowed":true,"consequential":false,"reason":"routine by default"}}`,
		types.FieldExpiry, bound)

	ref, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	opa, err := opaeval.New([]byte(src))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The action's instant is 100ns before the bound, so "expiry < bound" is true.
	a := types.Action{Type: "document.export", Target: "res-1", Timestamp: base}

	refDecision, err := ref.Evaluate(a)
	if err != nil {
		t.Fatalf("reference Evaluate: %v", err)
	}
	opaDecision, err := opa.Evaluate(a)
	if err != nil {
		t.Fatalf("opa Evaluate: %v", err)
	}

	// OPA orders the two instants correctly and fires the rule.
	if opaDecision.RuleFired != "before-bound" {
		t.Errorf("OPA should order a 100ns delta correctly, got RuleFired=%q", opaDecision.RuleFired)
	}
	// The classifier cannot, so the comparison is false and the default fires.
	if refDecision.RuleFired != policy.DefaultRule {
		t.Errorf("the classifier is expected to lose a 100ns delta, got RuleFired=%q.\n"+
			"If asScalar was corrected to compare integer nanoseconds, this divergence is CLOSED:\n"+
			"update the README's divergence section and delete this test, and check that\n"+
			"internal/macaroon.asScalar was corrected in the same change.", refDecision.RuleFired)
	}
}
