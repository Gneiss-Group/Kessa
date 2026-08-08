// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/audit"
)

// Parse is the verifier's primary untrusted-input boundary: an auditor points
// `kessa verify` at a file produced by a party they are explicitly not required
// to trust. Everything downstream of it (signature re-derivation, evidence
// re-resolution) runs on the struct it returns, so a malformed envelope that
// gets past this function is a malformed envelope the rest of the verifier
// treats as real.
//
// The properties below are the ones Parse's own documentation claims, restated
// as assertions a fuzzer can search against. They are deliberately about the
// SHAPE Parse guarantees rather than about it not crashing: "does not panic" is
// the floor, and a version dispatch that silently admits a third shape is the
// defect class this target exists for.

// seedCorpus adds the committed goldens plus a few hand-shaped envelopes. Real
// structured input matters here: a mutator starting from an empty corpus spends
// its whole budget discovering that an export is JSON, and never reaches the
// version dispatch this target is aimed at.
func seedCorpus(f *testing.F) {
	f.Helper()
	for _, name := range []string{"audit_export.golden.json", "audit_export_v2.golden.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			// A missing golden is a real problem, not a reason to fuzz an empty
			// corpus quietly. Fail rather than silently seeding from nothing.
			f.Fatalf("seed corpus: %v", err)
		}
		f.Add(data)
	}
	// Minimal envelopes at each accepted version, and one at a version that is
	// not accepted, so the mutator has short inputs to work from as well as the
	// large goldens.
	f.Add([]byte(`{"version":"` + Version + `","signer":"did:web:localhost:proxies:gatekeeper","entries":[]}`))
	f.Add([]byte(`{"version":"` + audit.ExportVersion + `","signer":"did:web:localhost:proxies:gatekeeper","entries":[]}`))
	f.Add([]byte(`{"version":"kessa-audit-export/v3","signer":"","entries":[]}`))
	// A v1 envelope carrying v2 structure: the relabelling case F2 refuses.
	f.Add([]byte(`{"version":"` + audit.ExportVersion + `","entries":[],"policy":{"version":"p","default":{"allowed":true,"reason":"r"}},"envelopeSignature":"AA=="}`))
	// A v2 envelope whose carried policy is the kind policy.Validate rejects.
	f.Add([]byte(`{"version":"` + Version + `","entries":[],"policy":{"version":"p","rules":[{"name":"n","when":[{"field":"f","op":"~=","value":"v"}]}],"default":{"allowed":false,"reason":"r"}}}`))
}

func FuzzParse(f *testing.F) {
	seedCorpus(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		exp, err := Parse(data)
		if err != nil {
			if exp != nil {
				t.Fatalf("Parse returned both an export and an error %v", err)
			}
			return
		}
		if exp == nil {
			t.Fatal("Parse returned a nil export and a nil error")
		}

		// 1. The accepted set is exactly {v1, v2}. Parse documents itself as the
		//    only place that decides this, so any third version string reaching a
		//    caller means the dispatch has a hole rather than a default branch.
		if exp.Version != Version && exp.Version != audit.ExportVersion {
			t.Fatalf("Parse accepted unsupported version %q", exp.Version)
		}

		// 2. A v1 envelope carries no v2 structure. This is the downgrade refusal:
		//    a v2 export trimmed and relabelled as v1 would otherwise reach the
		//    integrity-only path while still carrying evidence fields, and the
		//    weaker path is the one an attacker wants.
		if exp.Version == audit.ExportVersion {
			if len(exp.Credentials) > 0 {
				t.Fatalf("v1 envelope accepted with %d credential records", len(exp.Credentials))
			}
			if exp.Policy != nil {
				t.Fatal("v1 envelope accepted with a carried policy")
			}
			if len(exp.EnvelopeSignature) > 0 {
				t.Fatal("v1 envelope accepted with an envelope signature")
			}
		}

		// 3. A carried policy is one a proxy would also have loaded. Parse and
		//    policy.Parse must never disagree about whether a policy is
		//    meaningful: if they can, a rule that silently never fires is
		//    accepted at verification time and the verdict is re-derived against
		//    a ruleset the enforcement point would have refused.
		if exp.Policy != nil {
			if err := exp.Policy.Validate(); err != nil {
				t.Fatalf("Parse accepted an export whose carried policy is invalid: %v", err)
			}
		}

		// 4. An accepted export survives its own serializer. Marshal is what
		//    writes the file an auditor is handed, and PolicyID and every
		//    envelope signature are computed over marshalled bytes, so an
		//    envelope that parses but cannot round-trip is one where the bytes
		//    verified and the bytes stored are not the same object.
		out, err := exp.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed export failed: %v", err)
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("re-parsing a marshalled export failed: %v", err)
		}
		if again.Version != exp.Version {
			t.Fatalf("round trip changed version: %q became %q", exp.Version, again.Version)
		}
		if len(again.Entries) != len(exp.Entries) {
			t.Fatalf("round trip changed entry count: %d became %d", len(exp.Entries), len(again.Entries))
		}
		if len(again.Credentials) != len(exp.Credentials) {
			t.Fatalf("round trip changed credential count: %d became %d", len(exp.Credentials), len(again.Credentials))
		}
	})
}
