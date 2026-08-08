// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// A policy is untrusted input in the same scenario export.Parse is: an auditor
// receives one alongside an export, from a party whose enforcement they are
// checking rather than trusting. Parse is also the function export.Parse defers
// to for the carried-policy case, so a hole here is a hole in two places.
//
// The interesting property is not "Parse does not crash" but "Parse never hands
// back a policy that is not meaningful". A rule with a typo'd operator that is
// accepted silently never fires, and a rule that never fires is one an operator
// believes is protecting them.

func policySeeds(f *testing.F) {
	f.Helper()
	// The shipped examples are real structured input: they get the mutator to
	// the condition grammar instead of spending its budget rediscovering JSON.
	matches, err := filepath.Glob(filepath.Join("..", "..", "examples", "policies", "*.json"))
	if err != nil {
		f.Fatalf("seed corpus: %v", err)
	}
	if len(matches) == 0 {
		f.Fatal("seed corpus: no example policies found; the corpus would be empty")
	}
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			f.Fatalf("seed corpus: %v", err)
		}
		f.Add(data)
	}
	for _, s := range []string{
		`{"version":"v1","default":{"allowed":false,"reason":"deny by default"}}`,
		// Each of the shapes Validate exists to refuse.
		`{"version":"v1"}`,
		`{"version":"v1","default":{"allowed":true,"reason":""}}`,
		`{"version":"","default":{"allowed":true,"reason":"r"}}`,
		`{"version":"v1","rules":[{"name":"","when":[]}],"default":{"allowed":true,"reason":"r"}}`,
		`{"version":"v1","rules":[{"name":"n","when":[{"field":"amount","op":"<=","value":"abc"}]}],"default":{"allowed":true,"reason":"r"}}`,
		`{"version":"v1","rules":[{"name":"n","when":[{"field":"amount","op":"<=","value":"1e309"}]}],"default":{"allowed":true,"reason":"r"}}`,
		`{"version":"v1","rules":[{"name":"n","when":[{"field":"t","op":"in","value":"a,b,c"}]}],"default":{"allowed":true,"reason":"r"}}`,
		`{"version":"v1","default":null}`,
	} {
		f.Add([]byte(s))
	}
}

func FuzzParse(f *testing.F) {
	policySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if p != nil {
				t.Fatalf("Parse returned both a policy and an error %v", err)
			}
			return
		}
		if p == nil {
			t.Fatal("Parse returned a nil policy and a nil error")
		}

		// 1. Parse never returns a policy Validate would reject. These are the
		//    same rules by construction (Parse calls Validate), so a violation
		//    here means Validate is not deterministic over the value Parse
		//    built, which is the interesting failure rather than a tautology.
		if err := p.Validate(); err != nil {
			t.Fatalf("Parse returned a policy that fails Validate: %v", err)
		}

		// 2. An accepted policy states its posture. Both are load-bearing at
		//    verification time: the version is stamped into every audit entry,
		//    and the default reason is what an unmatched action is denied with.
		if p.Version() == "" {
			t.Fatal("Parse accepted a policy with an empty version")
		}
		if p.Default.Reason == "" {
			t.Fatal("Parse accepted a policy with an empty default reason")
		}

		// 3. Evaluate terminates and produces a stated reason for any action.
		//    A decision with no reason is the silent-deny footgun the required
		//    default block exists to prevent, reached by a different route.
		d, err := p.Evaluate(types.Action{
			Type:       "payment.transfer",
			Target:     "acct/999",
			Attributes: map[string]string{"amount": "100", "audience": "external"},
		})
		if err == nil && d.Reason == "" {
			t.Fatal("Evaluate returned a decision with no reason")
		}

		// 4. A parsed policy survives a serialize/reparse cycle. This is not
		//    housekeeping: export.PolicyID content-addresses the MARSHALLED
		//    bytes and the envelope signature covers that address, so a policy
		//    that parses but re-parses differently would be signed as one thing
		//    and re-derived as another.
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshalling a parsed policy failed: %v", err)
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("re-parsing a marshalled policy failed: %v (from %q)", err, out)
		}
		if again.Version() != p.Version() {
			t.Fatalf("round trip changed version: %q became %q", p.Version(), again.Version())
		}
		if len(again.Rules) != len(p.Rules) {
			t.Fatalf("round trip changed rule count: %d became %d", len(p.Rules), len(again.Rules))
		}
		if again.Default != p.Default {
			t.Fatalf("round trip changed the default block: %+v became %+v", p.Default, again.Default)
		}
	})
}
