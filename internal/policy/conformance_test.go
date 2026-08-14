// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// This file runs the shared Evaluator contract against the hand-rolled
// classifier. Its counterpart lives in experimental/policy-opa, which runs the
// identical suite against an OPA-backed implementation; the two together are
// what makes the interface a proven boundary rather than a compiling one.
//
// It is an EXTERNAL test package (policy_test, not policy) because the
// conformance package imports policy, and an in-package test importing it back
// would be an import cycle.
package policy_test

import (
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/policy/conformance"
)

func TestHandRolledClassifierConformance(t *testing.T) {
	conformance.Run(t, "../../examples/policies", func(t *testing.T, policyJSON []byte) policy.Evaluator {
		t.Helper()
		p, err := policy.Parse(policyJSON)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return p
	})
}
