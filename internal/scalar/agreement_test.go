// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// This file is an EXTERNAL test package on purpose. internal/policy and
// internal/macaroon both import internal/scalar, so a test inside the package
// could not import them back. Placing the check here rather than in either
// caller is deliberate too: it belongs to neither of them, and putting it in one
// would put it under the maintenance of the half more likely to be edited.
package scalar_test

import (
	"fmt"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestPolicyAndMacaroonOrderOneFieldIdentically drives the two callers of this
// package through their own public entry points and requires them to reach the
// same verdict on every ordering comparison in a shared corpus.
//
// This is the property that made hoisting the implementation worth doing.
// internal/policy classifies at the enforcement proxy; internal/macaroon decides
// caveat satisfaction, and the independent verifier re-derives BOTH from a
// recorded action. They are written against one field vocabulary
// (types.Action.Context(), which says in as many words that a disagreement there
// could pass an action the proxy denied), and they used to hold a byte-identical
// copy of the coercion each. Nothing failed if one copy was corrected alone: the
// two simply began answering differently, in a system whose whole claim is that
// they cannot.
//
// The corpus is over the FOUR ORDERING OPERATORS, which is the whole of what
// internal/scalar decides. Equality and set membership are string operations
// that each package still spells for itself, and this test has no opinion about
// them (see UPCOMING.md, which records that they are not in fact identical).
func TestPolicyAndMacaroonOrderOneFieldIdentically(t *testing.T) {
	const field = "v"

	values := []string{
		"100", "100.0", "99", "0", "-0", "-1", "100.5",
		"1e18", "1.7833968e18", "9223372036854775807",
		"Inf", "-Inf", "NaN", "1e400", "0x10", "abc", "",
		"2026-07-09T12:00:00Z",
		"2026-07-09T12:00:00.000000100Z",
		"2026-07-09T12:00:00.000000200Z",
		"2026-07-09T12:00:00+01:00",
		"9999-12-31T23:59:59Z",
	}
	ops := []struct {
		policy   policy.Op
		macaroon macaroon.Op
	}{
		{policy.OpLe, macaroon.OpLe},
		{policy.OpLt, macaroon.OpLt},
		{policy.OpGe, macaroon.OpGe},
		{policy.OpGt, macaroon.OpGt},
	}

	rootKey := []byte("agreement-test-root-key-not-a-secret")

	for _, op := range ops {
		for _, bound := range values {
			// Step one: the two must agree on whether the bound is writable at
			// all. Both validate it while parsing a policy file / attenuating a
			// credential, so a bound one accepts and the other refuses is
			// already a split, before any action is compared against it.
			src := fmt.Sprintf(
				`{"version":"agreement-v1","rules":[{"name":"r","when":[{"field":%q,"op":%q,"value":%q}],"consequential":true,"reason":"the rule fired"}],"default":{"allowed":true,"consequential":false,"reason":"no rule matched"}}`,
				field, string(op.policy), bound)
			p, policyErr := policy.Parse([]byte(src))
			m, macaroonErr := macaroon.Attenuate(
				macaroon.Mint(rootKey, "cred-1", "agreement"),
				macaroon.Caveat{Field: field, Op: op.macaroon, Value: bound},
			)
			if (policyErr == nil) != (macaroonErr == nil) {
				t.Errorf("bound %q %q: policy accepts=%v (%v), macaroon accepts=%v (%v)",
					op.policy, bound, policyErr == nil, policyErr, macaroonErr == nil, macaroonErr)
				continue
			}
			if policyErr != nil {
				continue
			}

			// Step two: for a bound both accept, every context value must get
			// the same answer from both.
			for _, got := range values {
				action := types.Action{
					Type:       "document.export",
					Target:     "res-1",
					Attributes: map[string]string{field: got},
				}
				d, err := p.Evaluate(action)
				if err != nil {
					t.Fatalf("Evaluate: %v", err)
				}
				policyHolds := d.RuleFired == "r"
				macaroonHolds := macaroon.Satisfies(m, macaroon.Context(action.Context())) == nil

				if policyHolds != macaroonHolds {
					t.Errorf("%q %s %q: policy says %v, macaroon says %v",
						got, op.policy, bound, policyHolds, macaroonHolds)
				}
			}
		}
	}
}
