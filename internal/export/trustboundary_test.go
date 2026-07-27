// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Trust-boundary regression suite.
//
// These tests pin the single property the whole policy-posture story rests on:
// a verifier re-derives consequentiality from the policy carried INSIDE the
// export it is verifying, and cannot be steered onto any other policy. That
// property is what makes "this deployment runs allow-list posture" a claim a
// reader of an export can check rather than take on faith.
//
// The protection is deliberately TWO independent bindings, and the tests below
// exercise them separately because either one alone is defeatable:
//
//  1. the envelope signature over {version, signer, policyID}, and
//  2. each entry's PolicyID, which is hash-covered by the entry signature.
//
// Derived from the 2026-07-22 verification pass; see docs/ for the narrative.

const allowlistPolPath = "../../examples/policies/commerce-security-allowlist.json"

// permissivePolicyJSON allows everything and classifies nothing as consequential.
// If a verifier could ever be steered onto it, every consequential allow would
// re-derive as routine and silently skip the approval and revocation checks.
const permissivePolicyJSON = `{
  "version": "attacker-permissive-v1",
  "rules": [],
  "default": { "allowed": true, "consequential": false, "reason": "everything is routine" }
}`

func mustPolicy(t *testing.T, js string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return p
}

// ---- 3.2.1 naive tamper baseline -------------------------------------------

// Swapping the carried policy without touching the envelope signature is caught
// by binding (1), before a single entry is examined.
func TestTrustBoundary_NaivePolicySwapFailsEnvelope(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))
	exp.Policy = mustPolicy(t, permissivePolicyJSON) // original signature left in place

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.FatalReason == "" {
		t.Fatal("a swapped policy must be a FATAL envelope failure")
	}
	if !strings.Contains(res.FatalReason, "envelope signature invalid") {
		t.Fatalf("expected an envelope-signature failure, got %q", res.FatalReason)
	}
	if res.Pass() {
		t.Fatal("must not pass")
	}
	// The failure precedes per-entry work: no entry verdicts are produced at all.
	if len(res.Entries) != 0 {
		t.Fatalf("envelope failure must short-circuit before entries; got %d verdicts", len(res.Entries))
	}
}

// ---- 3.2.2 the real adversarial case: genuine-signature splice --------------

// The sharp case. The envelope signature covers {version, signer, policyID}, so
// a SECOND legitimately-produced export from the same enforcement point carries a
// genuine signature over a DIFFERENT policy's id. Splicing that policy together
// with its own genuine envelope signature satisfies binding (1) completely,
// nothing is forged, and the signature verifies.
//
// Only binding (2) catches it: each entry pins the content address of the policy
// it was actually classified under, inside the entry hash the enforcement point
// signed. This test asserts that specific mechanism, not merely that verification
// failed, so a regression that removed the per-entry pin would be visible here
// even though the envelope check still passed.
func TestTrustBoundary_GenuineSignatureSpliceCaughtByEntryPin(t *testing.T) {
	f := newFixture(t)
	exp := f.build(t, f.records(t))

	// A second, entirely legitimate export from the SAME enforcement point key,
	// carrying a different (real, shipped) policy.
	otherPol, err := policy.Load(allowlistPolPath)
	if err != nil {
		t.Fatal(err)
	}
	// The donor covers the SAME entries, because the envelope signature now binds
	// the entry count and log tip too (R2-02). A donor over a different-length log
	// would be caught by the envelope check, which would make this test pass for
	// the wrong reason and stop exercising the per-entry pin it exists to pin.
	donor, err := Build(f.proxy, exp.Entries, f.set, otherPol)
	if err != nil {
		t.Fatal(err)
	}

	// The splice: real entries, the other policy, and that policy's GENUINE
	// envelope signature by the real enforcement point.
	exp.Policy = otherPol
	exp.EnvelopeSignature = donor.EnvelopeSignature

	res, err := Verify(exp, f.inputs())
	if err != nil {
		t.Fatal(err)
	}

	// Binding (1) is satisfied, that is the whole point of this test.
	if res.FatalReason != "" {
		t.Fatalf("the spliced envelope signature is genuine and must verify; got fatal %q", res.FatalReason)
	}

	// Binding (2) must catch it, on every ALLOWED entry, naming the mechanism.
	wantPID, err := PolicyID(otherPol)
	if err != nil {
		t.Fatal(err)
	}
	var caught int
	for i, e := range res.Entries {
		rec := f.records(t)[i]
		if !rec.Decision.Allowed {
			continue // denials are not re-derived; they pass on intact evidence
		}
		if e.Outcome != OutcomeFail {
			t.Fatalf("entry %d: allowed entry under a substituted policy must FAIL, got %s", i, e.Outcome)
		}
		if !strings.Contains(e.Reason, "policy substituted") {
			t.Fatalf("entry %d: expected a policy-substitution failure, got %q", i, e.Reason)
		}
		// The reason must name both the pinned and the carried content address, so
		// an operator can tell exactly which policy was swapped in.
		if !strings.Contains(e.Reason, f.polID) || !strings.Contains(e.Reason, wantPID) {
			t.Fatalf("entry %d: failure should name both policy ids (pinned %s, carried %s): %q",
				i, f.polID, wantPID, e.Reason)
		}
		caught++
	}
	if caught == 0 {
		t.Fatal("no allowed entry was checked; the fixture should contain at least one")
	}
	if res.Pass() {
		t.Fatal("must not pass")
	}
}

// ---- 3.2.3 v1 downgrade attempts -------------------------------------------

// Relabelling a v2 export as v1 to dodge policy re-derivation entirely.
func TestTrustBoundary_V1DowngradeCannotDodgeReDerivation(t *testing.T) {
	f := newFixture(t)

	t.Run("v1 label carrying v2 evidence is rejected at parse", func(t *testing.T) {
		exp := f.build(t, f.records(t))
		exp.Version = audit.ExportVersion
		data, err := exp.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse(data)
		if err == nil {
			t.Fatal("a v1-labelled envelope carrying evidence must be rejected")
		}
		if !strings.Contains(err.Error(), "v1 envelope must not carry a credential set") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("v1 with evidence stripped can never be a clean pass", func(t *testing.T) {
		exp := f.build(t, f.records(t))
		exp.Version = audit.ExportVersion
		exp.Policy = nil
		exp.Credentials = nil
		exp.EnvelopeSignature = nil

		data, err := exp.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(data) // now structurally a legitimate v1 export
		if err != nil {
			t.Fatalf("a bare v1 export should still parse: %v", err)
		}
		res, err := Verify(parsed, f.inputs())
		if err != nil {
			t.Fatal(err)
		}
		if res.EvidenceCarried {
			t.Fatal("a v1 export carries no evidence")
		}
		if res.Pass() {
			t.Fatal("SECURITY: a v1 downgrade produced a clean pass")
		}
		for _, e := range res.Entries {
			if e.Outcome != OutcomeIntegrityOnly {
				t.Fatalf("expected integrity-only verdicts, got %s", e.Outcome)
			}
		}
	})
}

// ---- posture is bound into the signed material ------------------------------

// Posture lives inside the content address, so two policies differing ONLY in
// their default block have different PolicyIDs, and therefore different
// envelope signatures and different per-entry pins. This is what makes "which
// posture was live" a checkable property of an export rather than an assertion.
func TestTrustBoundary_PolicyIDCoversPosture(t *testing.T) {
	denyList, err := policy.Load(commercePolPath)
	if err != nil {
		t.Fatal(err)
	}
	allowList, err := policy.Load(allowlistPolPath)
	if err != nil {
		t.Fatal(err)
	}
	denyID, err := PolicyID(denyList)
	if err != nil {
		t.Fatal(err)
	}
	allowID, err := PolicyID(allowList)
	if err != nil {
		t.Fatal(err)
	}
	if denyID == allowID {
		t.Fatal("SECURITY: PolicyID does not distinguish the two shipped postures")
	}

	// And narrowly: the default block ALONE moves the id, with rules held identical.
	base := `{"version":"x","rules":[],"default":{"allowed":true,"consequential":%s,"reason":"r"}}`
	routineID, err := PolicyID(mustPolicy(t, strings.Replace(base, "%s", "false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	conseqID, err := PolicyID(mustPolicy(t, strings.Replace(base, "%s", "true", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if routineID == conseqID {
		t.Fatal("SECURITY: PolicyID does not cover default.consequential")
	}
}

// ---- 2.2 carried-policy validation -----------------------------------------

// A policy that policy.Parse rejects must not slip into an export unnoticed.
func TestTrustBoundary_CarriedPolicyIsValidatedOnParse(t *testing.T) {
	cases := []struct {
		name       string
		policyJSON string
		want       string
	}{
		{"missing version", `{"rules":[],"default":{"allowed":true,"consequential":false,"reason":"r"}}`, "missing version"},
		{"missing default block", `{"version":"v1","rules":[]}`, `missing required "default" block`},
		{"empty default reason", `{"version":"v1","rules":[],"default":{"allowed":true,"consequential":false,"reason":""}}`, "default.reason must not be empty"},
		{"unknown operator", `{"version":"v1","rules":[{"name":"r","when":[{"field":"a","op":"~=","value":"1"}]}],"default":{"allowed":true,"consequential":false,"reason":"r"}}`, "unknown operator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// policy.Parse must reject it...
			if _, err := policy.Parse([]byte(tc.policyJSON)); err == nil {
				t.Fatal("policy.Parse should reject this fixture")
			}
			// ...and so must export.Parse, for the same reason.
			data := []byte(`{"version":"` + Version + `","signer":"` + didProxy + `","policy":` + tc.policyJSON + `}`)
			_, err := Parse(data)
			if err == nil {
				t.Fatal("export.Parse silently accepted a policy that policy.Parse rejects")
			}
			if !strings.Contains(err.Error(), "carried policy is invalid") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should name the carried policy and the defect, got: %v", err)
			}
		})
	}
}

// ---- 3.2.5 the documented trust boundary ------------------------------------

// TestTrustBoundary_DIDRootIsTheAnchor pins WHERE THE GUARANTEE STOPS.
//
// THIS IS A BOUNDARY-CONDITION TEST, NOT A VULNERABILITY TEST. The passing case
// below is expected, documented behavior, and the test asserts it deliberately so
// that a future change which accidentally strengthens or weakens this boundary
// becomes visible in CI rather than silently shifting.
//
// What it shows: the verifier's entire trust chain is anchored in the did:web
// documents it is given. Hand it a fabricated DID root in which the enforcement
// point's published key is the attacker's, and a wholly fabricated export, its
// own log, its own signatures, an arbitrarily permissive policy, classifications
// flipped to match, verifies clean. That is not policy substitution: the
// verifier still used the policy carried in the export it was handed. It is
// IDENTITY substitution, and it is why the provenance of --dids is load-bearing.
//
// Backlog cross-reference: documenting --dids provenance for verifier operators
// is tracked separately and is deliberately out of scope for this suite, whose
// job is to pin the behavior in code.
func TestTrustBoundary_DIDRootIsTheAnchor(t *testing.T) {
	f := newFixture(t)
	attacker := mustSigner(t, didProxy, 0xAA) // same DID, different key
	permissive := mustPolicy(t, permissivePolicyJSON)
	newPID, err := PolicyID(permissive)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the entire log under the attacker's key: re-pin every entry to the
	// permissive policy and restate every re-derivable field as that policy
	// derives it, exactly as a forger would. The forger is careful, it has to be,
	// since the verifier re-derives consequentiality (F1) and now the rule and
	// policy version too (R2-07): and being careful costs it nothing, because it
	// controls the whole log.
	//
	// The re-pinning happens inside the seal, not after it, because evidence binds
	// to PrevHash (R2-04): editing a sealed entry would break the next entry's
	// proofs, which is a different failure from the one this test pins.
	recs := f.recordsWith(t, func(_ int, r *audit.Record) {
		r.PolicyID = newPID
		derived, err := permissive.Evaluate(r.Action)
		if err != nil {
			t.Fatal(err)
		}
		r.Decision.Consequential = derived.Consequential
		r.Decision.RuleFired = derived.RuleFired
		r.Decision.PolicyVersion = derived.PolicyVersion
		if !derived.Consequential {
			// A non-consequential allow needs no status evidence, and claiming any
			// would now be re-derived against the credentials and caught.
			r.Decision.StatusCheckedHops = 0
		}
	})
	log := audit.NewLog(attacker)
	for i, r := range recs {
		if _, err := log.Append(r); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	forged, err := Build(attacker, log.Entries(), f.set, permissive)
	if err != nil {
		t.Fatal(err)
	}

	// Against the REAL DID root, the forgery is rejected: the published key for
	// the enforcement point is not the attacker's.
	res, err := Verify(forged, f.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass() {
		t.Fatal("SECURITY: a forgery verified against the real DID root")
	}
	if res.FatalReason == "" {
		t.Fatalf("expected an envelope failure against the real root, got %+v", res.Entries[0])
	}

	// Against a FABRICATED DID root that publishes the attacker's key as the
	// enforcement point's, it verifies clean. Expected and documented.
	forgedRoot := t.TempDir()
	copyDIDTree(t, didsRoot, forgedRoot)
	writeDIDDoc(t, filepath.Join(forgedRoot, "localhost/proxies/gatekeeper/did.json"), didProxy, attacker.Public().(ed25519.PublicKey))

	forgedInputs := f.inputs()
	forgedInputs.DIDs = did.FileResolver{Root: forgedRoot}
	res2, err := Verify(forged, forgedInputs)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Pass() {
		t.Fatalf("BOUNDARY MOVED: a forgery under a fabricated DID root no longer passes. "+
			"This may be an improvement, but it changes a documented boundary — update this test "+
			"and the --dids provenance docs deliberately. Detail: fatal=%q entries=%+v",
			res2.FatalReason, res2.Entries)
	}
}

// ---- helpers ---------------------------------------------------------------

func copyDIDTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, p)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatalf("copy did tree: %v", err)
	}
}

// writeDIDDoc publishes a did:web document binding id to pub, in the same shape
// scripts/genfixtures emits.
func writeDIDDoc(t *testing.T, path string, id types.DID, pub ed25519.PublicKey) {
	t.Helper()
	vm := string(id) + "#key-1"
	doc := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": string(id),
		"verificationMethod": []map[string]any{{
			"id": vm, "type": "JsonWebKey2020", "controller": string(id),
			"publicKeyJwk": map[string]string{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		"authentication":  []string{vm},
		"assertionMethod": []string{vm},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
