// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	commercePol  = "../../examples/policies/commerce-security.json"
	allowlistPol = "../../examples/policies/commerce-security-allowlist.json"
	exportFix    = "../../testdata/shadow/replay_export.json"
	actionsFix   = "../../testdata/shadow/actions.jsonl"
)

func loadPol(t *testing.T, path string) (*policy.Policy, string) {
	t.Helper()
	p, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	id, err := export.PolicyID(p)
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	return p, id
}

func exportInputs(t *testing.T) []Input {
	t.Helper()
	data, err := os.ReadFile(exportFix)
	if err != nil {
		t.Fatal(err)
	}
	in, err := FromExport(data, exportFix)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// ---- §3.3: the projection discipline ---------------------------------------

// A Prediction must be a genuinely distinct type, not an alias for or embedding
// of types.Decision. A type alias would compile but would defeat the entire point.
func TestPredictionIsStructurallyNotAVerdict(t *testing.T) {
	pt := reflect.TypeOf(Prediction{})
	dt := reflect.TypeOf(types.Decision{})

	if pt == dt {
		t.Fatal("Prediction is the same type as types.Decision (alias?); the distinction is the whole point")
	}
	if pt.ConvertibleTo(dt) {
		t.Fatal("Prediction is convertible to types.Decision; it must not be a structural twin")
	}

	// The only types.Decision anywhere in a Prediction must be the explicitly
	// named, pointer-typed Actual field, which is a REAL recorded verdict.
	for i := 0; i < pt.NumField(); i++ {
		f := pt.Field(i)
		if f.Anonymous {
			t.Fatalf("Prediction embeds %s; embedding would promote verdict fields into prediction output", f.Type)
		}
		if f.Type == dt {
			t.Fatalf("field %q is a bare types.Decision; predictions must project, never pass through", f.Name)
		}
		if f.Type == reflect.PointerTo(dt) && f.Name != "Actual" {
			t.Fatalf("field %q holds a types.Decision; only Actual (the real recorded verdict) may", f.Name)
		}
	}
}

// The serialized form must not carry the two fields that would invite a
// prediction to be read as a verdict.
func TestPredictionJSONOmitsVerdictOnlyFields(t *testing.T) {
	pol, id := loadPol(t, commercePol)
	p, err := Predict(pol, id, Input{
		Source: Source{Kind: SourceActionsFile, Path: "x", Index: 1},
		Action: types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "500"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	for _, banned := range []string{"allowed", "statusChecked"} {
		if _, ok := got[banned]; ok {
			t.Fatalf("prediction JSON carries %q; that field reads as an enforcement verdict: %s", banned, b)
		}
	}
	for _, want := range []string{"consequential", "policyDenies", "matchedRule", "policyID", "source"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("prediction JSON missing %q: %s", want, b)
		}
	}
}

// PolicyDenies is the inverted, renamed projection of Decision.Allowed.
func TestPredict_PolicyDeniesInvertsAllowed(t *testing.T) {
	pol, id := loadPol(t, commercePol)
	cases := []struct {
		name       string
		action     types.Action
		wantDenied bool
		wantConseq bool
	}{
		{"hard deny", types.Action{Type: "payment.wire", Target: "a"}, true, false},
		{"consequential allow", types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "500"}}, false, true},
		{"routine allow", types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "1"}}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Predict(pol, id, Input{Action: tc.action})
			if err != nil {
				t.Fatal(err)
			}
			dec, _ := pol.Evaluate(tc.action)
			if p.PolicyDenies != !dec.Allowed {
				t.Fatalf("PolicyDenies=%v but Decision.Allowed=%v", p.PolicyDenies, dec.Allowed)
			}
			if p.PolicyDenies != tc.wantDenied || p.Consequential != tc.wantConseq {
				t.Fatalf("got denied=%v conseq=%v want denied=%v conseq=%v",
					p.PolicyDenies, p.Consequential, tc.wantDenied, tc.wantConseq)
			}
			if p.MatchedRule != dec.RuleFired || p.PolicyVersion != dec.PolicyVersion {
				t.Fatal("projection lost rule/version provenance")
			}
		})
	}
}

// ---- the regression this design exists to prevent ---------------------------

// sinkProjection models what auditsink.AuditRecord would have carried: action
// type and target only, attributes dropped. This is the REJECTED data source
// (spec §1.2), reproduced here so the reason it was rejected stays measurable.
func sinkProjection(a types.Action) types.Action {
	return types.Action{Type: a.Type, Target: a.Target}
}

// Export replay must be exact where sink-sourced replay was not. The 2026-07-22
// review measured sink replay disagreeing with ground truth on 3 of 5 actions,
// every disagreement failing toward routine. This pins both halves: export replay
// gets 5/5, and the sink projection still gets 3 wrong, so the rejection rationale
// cannot quietly stop being true.
func TestReplayFidelity_ExportIsExactWhereSinkProjectionIsNot(t *testing.T) {
	pol, id := loadPol(t, commercePol)
	inputs := exportInputs(t)
	if len(inputs) != 5 {
		t.Fatalf("fixture should carry the review's 5 actions, got %d", len(inputs))
	}

	// Export replay: the full Action is carried verbatim, so every prediction
	// matches the recorded decision.
	preds, err := PredictAll(pol, id, inputs)
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(preds, 0)
	if s.Compared != 5 || s.Agreed != 5 {
		t.Fatalf("export replay must agree 5/5, got compared=%d agreed=%d under=%d over=%d",
			s.Compared, s.Agreed, s.UnderPredicted, s.OverPredicted)
	}

	// The rejected approach: same actions, attributes stripped as the sink seam
	// would have stripped them.
	sunk := make([]Input, len(inputs))
	for i, in := range inputs {
		sunk[i] = Input{Source: in.Source, Action: sinkProjection(in.Action), Actual: in.Actual}
	}
	sunkPreds, err := PredictAll(pol, id, sunk)
	if err != nil {
		t.Fatal(err)
	}
	ss := Summarize(sunkPreds, 0)
	if ss.Agreed != 2 || ss.UnderPredicted != 3 {
		t.Fatalf("sink-style projection should still get 3 wrong, all under-predicted; got agreed=%d under=%d over=%d",
			ss.Agreed, ss.UnderPredicted, ss.OverPredicted)
	}
	t.Logf("export replay %d/5 agree; sink-style projection %d/5 agree (%d under-predicted)",
		s.Agreed, ss.Agreed, ss.UnderPredicted)
}

// ---- agreement semantics ----------------------------------------------------

// Agreement compares consequentiality ONLY. An action the policy allows can be
// denied at enforcement time for reasons policy does not decide (here: exceeding
// delegated authority). That must NOT count as a policy disagreement, comparing
// allow bits would report it as one and make the headline number wrong.
func TestAgreement_IgnoresDenialsPolicyDidNotCause(t *testing.T) {
	pol, id := loadPol(t, commercePol)

	// $5000 transfer: policy says allowed + consequential. Enforcement denied it
	// for exceeding an attenuated $100 ceiling, which policy knows nothing about.
	action := types.Action{
		Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "5000"},
		Timestamp:  time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
	actual := types.Decision{
		Allowed: false, Consequential: true, RuleFired: "high-value-transfer",
		Reason: "exceeds attenuated ceiling (amount <= 100)",
	}

	p, err := Predict(pol, id, Input{Action: action, Actual: &actual})
	if err != nil {
		t.Fatal(err)
	}
	if p.Agreement == nil {
		t.Fatal("agreement should be populated when an actual decision is present")
	}
	if !*p.Agreement {
		t.Fatalf("policy agreed on consequentiality; a scope denial must not read as disagreement (predicted conseq=%v, actual conseq=%v, actual allowed=%v)",
			p.Consequential, actual.Consequential, actual.Allowed)
	}
	if p.PolicyDenies {
		t.Fatal("policy did not deny this action; the enforcement layer did")
	}
}

func TestSummarize_ClassifiesDisagreementDirection(t *testing.T) {
	conseq := func(b bool) *types.Decision { return &types.Decision{Consequential: b, Allowed: true} }
	pol, id := loadPol(t, commercePol)

	// $10 transfer is routine under commerce policy.
	routine := types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "10"}}
	// $500 transfer is consequential.
	consequential := types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "500"}}

	preds, err := PredictAll(pol, id, []Input{
		{Action: routine, Actual: conseq(true)},        // predicted routine, actually consequential -> UNDER
		{Action: consequential, Actual: conseq(false)}, // predicted consequential, actually routine -> OVER
		{Action: routine, Actual: conseq(false)},       // agree
	})
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(preds, 2)
	if s.UnderPredicted != 1 || s.OverPredicted != 1 || s.Agreed != 1 {
		t.Fatalf("got under=%d over=%d agreed=%d, want 1/1/1", s.UnderPredicted, s.OverPredicted, s.Agreed)
	}
	if s.Compared != 3 || s.Total != 3 || s.Skipped != 2 {
		t.Fatalf("got compared=%d total=%d skipped=%d", s.Compared, s.Total, s.Skipped)
	}
}

// Mode B carries no recorded decision, so there is nothing to diff against.
func TestActionsMode_HasNoAgreementFields(t *testing.T) {
	pol, id := loadPol(t, commercePol)
	p, err := Predict(pol, id, Input{Action: types.Action{Type: "payment.transfer", Target: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Actual != nil || p.Agreement != nil {
		t.Fatal("an actions-file prediction must not claim an actual decision")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "actual") || strings.Contains(string(b), "agreement") {
		t.Fatalf("omitempty should drop the diff fields entirely: %s", b)
	}
}

// ---- input handling (§4.5) --------------------------------------------------

func TestFromActions_SkipsMalformedAndContinues(t *testing.T) {
	f, err := os.Open(actionsFix)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inputs, skipped, err := FromActions(f, actionsFix)
	if err != nil {
		t.Fatalf("a malformed line must not fail the run: %v", err)
	}
	if len(inputs) != 5 {
		t.Fatalf("expected 5 good actions, got %d", len(inputs))
	}
	if len(skipped) != 3 {
		t.Fatalf("expected 3 skipped lines (bad json, unknown field, missing type), got %d: %+v", len(skipped), skipped)
	}
	// Line numbers must be 1-based and point at the real offending lines.
	for _, sk := range skipped {
		if sk.Line < 1 {
			t.Fatalf("skipped line number should be 1-based, got %d", sk.Line)
		}
		if sk.Err == nil {
			t.Fatal("skipped line should carry a reason")
		}
	}
	// Provenance must survive: blank lines are ignored but do not shift numbering.
	if inputs[0].Source.Index != 1 || inputs[0].Source.Kind != SourceActionsFile {
		t.Fatalf("bad provenance on first action: %+v", inputs[0].Source)
	}
	if inputs[2].Source.Index != 4 {
		t.Fatalf("blank line should not shift line numbering, got index %d", inputs[2].Source.Index)
	}
}

func TestFromExport_MalformedIsFatal(t *testing.T) {
	cases := map[string]string{
		"not json":        `{"version":`,
		"unknown version": `{"version":"kessa-audit-export/v9","entries":[]}`,
		"invalid carried policy": `{"version":"kessa-audit-export/v2","entries":[],` +
			`"policy":{"version":"v1","rules":[]}}`, // no default block
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := FromExport([]byte(data), "fixture.json"); err == nil {
				t.Fatal("a malformed export must fail the whole run")
			}
		})
	}
}

// Export replay must carry provenance and the recorded decision through.
func TestFromExport_CarriesProvenanceAndActual(t *testing.T) {
	inputs := exportInputs(t)
	for i, in := range inputs {
		if in.Source.Kind != SourceExport {
			t.Fatalf("input %d: wrong source kind %q", i, in.Source.Kind)
		}
		if in.Source.Index != i {
			t.Fatalf("input %d: source index should be the entry Seq, got %d", i, in.Source.Index)
		}
		if in.Actual == nil {
			t.Fatalf("input %d: export replay must carry the recorded decision", i)
		}
	}
}

// ---- posture needs no special handling (§4.4) -------------------------------

// The policy file carries its own Default, so posture flows through Evaluate with
// nothing extra in this package. Shadow-testing a candidate allow-list policy is
// just running it.
func TestPostureRequiresNoShadowSpecificHandling(t *testing.T) {
	denyPol, denyID := loadPol(t, commercePol)
	allowPol, allowID := loadPol(t, allowlistPol)
	if denyID == allowID {
		t.Fatal("the two example policies should have distinct content addresses")
	}

	// $50 transfer: routine under deny-list, consequential under allow-list.
	in := Input{Action: types.Action{Type: "payment.transfer", Target: "a", Attributes: map[string]string{"amount": "50"}}}

	pDeny, err := Predict(denyPol, denyID, in)
	if err != nil {
		t.Fatal(err)
	}
	pAllow, err := Predict(allowPol, allowID, in)
	if err != nil {
		t.Fatal(err)
	}
	if pDeny.Consequential {
		t.Fatalf("deny-list posture should predict routine, got %+v", pDeny)
	}
	if !pAllow.Consequential {
		t.Fatalf("allow-list posture should predict consequential, got %+v", pAllow)
	}
}

// ---- round 2: R2-06 ----------------------------------------------------------

// TestR2_06_JSONLinesCarryTheirOwnDisclaimers. The laundering direction was
// already closed, shadow output cannot be fed to the verifier. The reverse
// channel was not: FromExport takes its source file at face value by design, then
// copied each entry's decision into `actual` and emitted it verbatim. In TEXT
// mode every run is bracketed by "PREDICTIONS ONLY, nothing was enforced"; in
// JSON-Lines mode, which is the DEFAULT and the scriptable one, there was no
// marker at all, so a consumer reading .actual.allowed was reading attacker-
// authored text with nothing saying so.
//
// The disclaimers are per record rather than in a header because a scriptable
// format gets split, filtered and piped, and a header survives none of that.
func TestR2_06_JSONLinesCarryTheirOwnDisclaimers(t *testing.T) {
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := export.PolicyID(pol)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exportFix)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := FromExport(data, exportFix)
	if err != nil {
		t.Fatal(err)
	}
	preds, err := PredictAll(pol, pid, inputs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSONLines(&buf, preds); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("no predictions emitted")
	}
	for i, line := range lines {
		var got struct {
			Note                 string          `json:"_note"`
			Actual               json.RawMessage `json:"actual"`
			ActualSourceVerified *bool           `json:"actualSourceVerified"`
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		if !strings.Contains(got.Note, "nothing was enforced") {
			t.Fatalf("line %d must say on its own that nothing was enforced, got _note=%q", i, got.Note)
		}
		if !strings.Contains(got.Note, "not an audit record") {
			t.Fatalf("line %d must disclaim being an audit record, got _note=%q", i, got.Note)
		}
		// Every line carrying an `actual` must carry the flag saying it is
		// unverified, right beside it.
		if len(got.Actual) == 0 {
			t.Fatalf("line %d: this fixture replays an export, so every line should carry an actual", i)
		}
		if got.ActualSourceVerified == nil {
			t.Fatalf("line %d carries an `actual` with no provenance flag beside it", i)
		}
		if *got.ActualSourceVerified {
			t.Fatalf("line %d claims its source was verified; shadow mode never verifies its input", i)
		}
	}
}
