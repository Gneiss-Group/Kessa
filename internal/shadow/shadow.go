// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package shadow implements passive policy evaluation: it runs the real
// classifier over actions and reports what a policy WOULD say about them,
// without enforcing anything.
//
// Nothing in this package authorizes, gates, or approves. There is no
// proof-of-possession, no live status check, no human approval, no hash-chained
// audit log, and no signed export. Its output is a Prediction, which is
// deliberately NOT a verdict; see the Prediction doc comment for why that
// distinction is structural rather than cosmetic.
//
// The classifier is reused verbatim from internal/policy so predictions are
// faithful to what real enforcement would decide. This package must never
// reimplement or approximate classification logic, and must never import
// internal/enforce.
package shadow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// SourceKind names where an action came from.
type SourceKind string

const (
	// SourceExport is replay of actions recorded in an audit export.
	SourceExport SourceKind = "export"
	// SourceActionsFile is a hand-authored JSON-Lines file of actions.
	SourceActionsFile SourceKind = "actions-file"
)

// Source is an action's provenance, so a prediction can always be traced back to
// the exact input line or entry that produced it.
type Source struct {
	Kind  SourceKind `json:"kind"`
	Path  string     `json:"path"`
	Index int        `json:"index"` // export entry Seq, or 1-based line number in an actions file
}

// Input is one action to classify, with its provenance and, for export replay
// only, the decision enforcement actually recorded for it at the time.
type Input struct {
	Source Source
	Action types.Action
	// Actual is the decision the source file CLAIMS enforcement recorded. Non-nil
	// only for export replay. It is a genuine types.Decision by type, and the
	// asymmetry with the projected prediction fields is intentional, it makes it
	// visually obvious which side of a diff shadow computed and which side it was
	// handed.
	//
	// It is not, however, a verified decision, and this comment used to say "the
	// real, recorded enforcement decision", which overclaimed (R2-06).
	// FromExport calls export.Parse and takes the file at face value by design: it
	// never runs export.Verify, so every field here is unverified input, and a
	// hand-authored file naming a nonexistent enforcement point produces an
	// "actual" decision that was never actually anything.
	Actual *types.Decision
}

// Prediction is what shadow mode produces. It is NOT a verdict, and the type
// exists to make that impossible to confuse.
//
// policy.Policy.Evaluate returns a types.Decision. That value is NEVER passed
// through as this tool's output, it is always projected into this type, and the
// projection is deliberately lossy in two specific ways:
//
//   - Decision.Allowed is dropped in favour of PolicyDenies. In a classifier
//     result, Allowed:true means only "no rule hard-denies this", NOT "this action
//     would be permitted", real authorization additionally requires satisfied
//     caveats, an unrevoked chain, proof of possession, and (if consequential) a
//     human approval, none of which shadow mode evaluates. Emitting a field named
//     "allowed" would invite exactly the misreading this whole type exists to
//     prevent, so the polarity is inverted and the name is explicit.
//
//   - Decision.StatusChecked is dropped entirely. Shadow mode never performs a
//     status check, so the field could only ever be false, and a false value would
//     read as "the check failed" rather than "no check was attempted".
//
// A future maintainer tempted to simplify this by embedding types.Decision should
// read the two points above first: the data being similar is the reason the type
// separation matters, not a reason to remove it.
type Prediction struct {
	Source Source       `json:"source"`
	Action types.Action `json:"action"`

	// The classification itself: exactly what the policy decided, nothing more.
	Consequential bool   `json:"consequential"` // would this demand a status check + human approval?
	PolicyDenies  bool   `json:"policyDenies"`  // does a policy rule forbid it outright?
	MatchedRule   string `json:"matchedRule"`   // rule that fired, or "default"
	Reason        string `json:"reason"`
	PolicyVersion string `json:"policyVersion"`
	PolicyID      string `json:"policyID"` // content address, same scheme as export.PolicyID

	// Note is a fixed, unconditional marker that this record is a prediction. It
	// exists so the DEFAULT output format is as self-describing as the text one
	// (R2-06). The text format brackets every run with "PREDICTIONS ONLY, nothing
	// was enforced" and "none of it is an audit record"; JSON-Lines is the primary,
	// scriptable format and carried no such marker at all, so a consumer reading
	// these lines had nothing in-band telling it what it was reading.
	Note string `json:"_note"`

	// Actual, ActualSourceVerified and Agreement are populated only for export
	// replay.
	//
	// Agreement compares CONSEQUENTIALITY ONLY. It deliberately does not compare
	// Decision.Allowed: an action the policy allows can still be denied at
	// enforcement time for reasons policy knows nothing about (exceeding delegated
	// authority, a revoked hop, a failed proof of possession). Comparing allow bits
	// would report those legitimate denials as policy disagreements and make the
	// summary's headline number wrong.
	Actual *types.Decision `json:"actual,omitempty"`
	// ActualSourceVerified is always false, and is emitted rather than omitted
	// precisely so it appears in every line that has an "actual" (R2-06). Shadow
	// mode parses its source export; it never verifies it. A consumer reading
	// .actual.allowed is reading a claim from an unverified file, which may be
	// attacker-authored, and the field next to it says so. If shadow ever gains a
	// verified-replay mode, this becomes the flag that distinguishes them; until
	// then a constant false is the honest value.
	ActualSourceVerified *bool `json:"actualSourceVerified,omitempty"`
	Agreement            *bool `json:"agreement,omitempty"`
}

// predictionNote is stamped into every emitted Prediction. Short enough to not
// bloat a JSON-Lines file, explicit enough that a consumer cannot claim it did
// not know.
const predictionNote = "kessa-shadow prediction; nothing was enforced and this is not an audit record"

// Predict classifies one input. This function is the ONLY place a types.Decision
// becomes output, and it always produces a Prediction.
func Predict(pol *policy.Policy, policyID string, in Input) (Prediction, error) {
	dec, err := pol.Evaluate(in.Action)
	if err != nil {
		return Prediction{}, fmt.Errorf("shadow: classify %s entry %d: %w", in.Source.Kind, in.Source.Index, err)
	}

	p := Prediction{
		Source:        in.Source,
		Action:        in.Action,
		Note:          predictionNote,
		Consequential: dec.Consequential,
		PolicyDenies:  !dec.Allowed,
		MatchedRule:   dec.RuleFired,
		Reason:        dec.Reason,
		PolicyVersion: dec.PolicyVersion,
		PolicyID:      policyID,
	}
	if in.Actual != nil {
		actual := *in.Actual
		agree := actual.Consequential == p.Consequential
		unverified := false
		p.Actual = &actual
		p.ActualSourceVerified = &unverified
		p.Agreement = &agree
	}
	return p, nil
}

// PredictAll classifies every input in order.
func PredictAll(pol *policy.Policy, policyID string, inputs []Input) ([]Prediction, error) {
	out := make([]Prediction, 0, len(inputs))
	for _, in := range inputs {
		p, err := Predict(pol, policyID, in)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- input mode A: export replay --------------------------------------------

// FromExport reads actions out of an audit export.
//
// IMPORTANT: this does NOT verify the export. No signature is checked, no DID is
// resolved, no hash chain is walked. The file's contents are taken at face value
// purely as a source of recorded actions. Shadow mode is not a substitute for
// cmd/verify and carries none of its guarantees.
//
// A malformed export fails the whole run, matching cmd/verify's behaviour: unlike
// a hand-authored file, an export is not a partial-content case.
func FromExport(data []byte, path string) ([]Input, error) {
	exp, err := export.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("shadow: read export %q: %w", path, err)
	}
	inputs := make([]Input, 0, len(exp.Entries))
	for i := range exp.Entries {
		e := &exp.Entries[i]
		// Copy the decision so a Prediction can never alias into the parsed export.
		actual := e.Decision
		inputs = append(inputs, Input{
			Source: Source{Kind: SourceExport, Path: path, Index: int(e.Seq)},
			Action: e.Action,
			Actual: &actual,
		})
	}
	return inputs, nil
}

// ---- input mode B: hand-authored actions file --------------------------------

// SkippedLine records one unparseable line of an actions file.
type SkippedLine struct {
	Line int
	Err  error
}

// FromActions reads a JSON-Lines file of types.Action values, one per line.
//
// Blank lines are ignored. A malformed line is SKIPPED rather than fatal, and
// reported in the returned slice: this tool is for iterative policy tuning, and
// aborting on line 47 of a 500-line file would make that loop painful. An error
// is returned only if the stream itself cannot be read.
func FromActions(r io.Reader, path string) ([]Input, []SkippedLine, error) {
	var (
		inputs  []Input
		skipped []SkippedLine
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate long action lines
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var a types.Action
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields() // a typo'd field name is a silent misclassification
		if err := dec.Decode(&a); err != nil {
			skipped = append(skipped, SkippedLine{Line: line, Err: err})
			continue
		}
		if strings.TrimSpace(a.Type) == "" {
			skipped = append(skipped, SkippedLine{Line: line, Err: fmt.Errorf(`action has no "type"`)})
			continue
		}
		inputs = append(inputs, Input{
			Source: Source{Kind: SourceActionsFile, Path: path, Index: line},
			Action: a,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("shadow: read actions %q: %w", path, err)
	}
	return inputs, skipped, nil
}

// ---- summary -----------------------------------------------------------------

// Summary aggregates a run.
type Summary struct {
	Total         int `json:"total"`
	Consequential int `json:"consequential"`
	Routine       int `json:"routine"`
	PolicyDenied  int `json:"policyDenied"`

	// Diff figures, populated only when actions came from an export.
	Compared int `json:"compared"`
	Agreed   int `json:"agreed"`
	// UnderPredicted: the candidate policy says routine where enforcement actually
	// treated the action as consequential. This is the DANGEROUS direction, it
	// means the policy under test would let through, unapproved, something the live
	// policy gated.
	UnderPredicted int `json:"underPredicted"`
	// OverPredicted: the candidate policy says consequential where enforcement
	// treated it as routine. Extra approval traffic, not a safety regression.
	OverPredicted int `json:"overPredicted"`

	Skipped int `json:"skipped"`
}

// Summarize aggregates predictions. skipped is the count of unparseable input
// lines, carried through so the total is honest about what was not classified.
func Summarize(preds []Prediction, skipped int) Summary {
	s := Summary{Total: len(preds), Skipped: skipped}
	for i := range preds {
		p := &preds[i]
		if p.Consequential {
			s.Consequential++
		} else {
			s.Routine++
		}
		if p.PolicyDenies {
			s.PolicyDenied++
		}
		if p.Agreement == nil {
			continue
		}
		s.Compared++
		switch {
		case *p.Agreement:
			s.Agreed++
		case !p.Consequential: // predicted routine, actual consequential
			s.UnderPredicted++
		default: // predicted consequential, actual routine
			s.OverPredicted++
		}
	}
	return s
}

// ---- output ------------------------------------------------------------------

// WriteJSONLines emits one Prediction per line. This is the primary, scriptable
// format, and every line carries its own framing: a fixed `_note` saying nothing
// was enforced, and (on replayed entries) `actualSourceVerified: false` next to
// the `actual` decision copied out of an unverified source file (R2-06). The
// disclaimers are per record rather than in a header because a scriptable format
// gets split, filtered and piped, and a header does not survive any of that.
func WriteJSONLines(w io.Writer, preds []Prediction) error {
	enc := json.NewEncoder(w)
	for i := range preds {
		if err := enc.Encode(&preds[i]); err != nil {
			return fmt.Errorf("shadow: encode prediction %d: %w", i, err)
		}
	}
	return nil
}

// WriteText emits a human-readable table plus a summary, for interactive policy
// tuning. Every line is prefixed so the output cannot be mistaken for an
// enforcement log.
func WriteText(w io.Writer, preds []Prediction, s Summary, skipped []SkippedLine) error {
	bw := newErrWriter(w)

	bw.printf("\nkessa-shadow: PREDICTIONS ONLY, nothing was enforced\n\n")
	if len(preds) == 0 {
		bw.printf("  no actions classified\n")
	}

	for i := range preds {
		p := &preds[i]
		class := "routine"
		if p.Consequential {
			class = "CONSEQUENTIAL"
		}
		if p.PolicyDenies {
			class = "POLICY-DENIED"
		}
		mark := ""
		if p.Agreement != nil && !*p.Agreement {
			mark = "  <-- differs from recorded"
			if !p.Consequential {
				mark = "  <-- differs from recorded (UNDER-predicted)"
			}
		}
		bw.printf("  %-4d %-14s %-18s %-22s rule=%s%s\n",
			p.Source.Index, class, truncate(p.Action.Type, 18), truncate(p.Action.Target, 22), p.MatchedRule, mark)
	}

	bw.printf("\n  %d classified: %d consequential, %d routine, %d denied by policy\n",
		s.Total, s.Consequential, s.Routine, s.PolicyDenied)

	if s.Compared > 0 {
		bw.printf("\n  Compared against %d recorded decisions:\n", s.Compared)
		bw.printf("    agreed            %d\n", s.Agreed)
		bw.printf("    under-predicted   %d  (policy says routine, enforcement treated it as consequential)\n", s.UnderPredicted)
		bw.printf("    over-predicted    %d  (policy says consequential, enforcement treated it as routine)\n", s.OverPredicted)
		if s.UnderPredicted > 0 {
			bw.printf("\n    NOTE: under-prediction is the direction that matters. This candidate policy\n")
			bw.printf("          would let %d action(s) proceed unapproved that the recorded policy gated.\n", s.UnderPredicted)
		}
		bw.printf("\n    Agreement compares CONSEQUENTIALITY only. An action a policy allows can still\n")
		bw.printf("    be denied at enforcement time for reasons policy does not decide (delegated\n")
		bw.printf("    authority, revocation, proof of possession, approval).\n")
	}

	if len(skipped) > 0 {
		bw.printf("\n  %d input line(s) skipped:\n", len(skipped))
		sort.Slice(skipped, func(i, j int) bool { return skipped[i].Line < skipped[j].Line })
		for _, sk := range skipped {
			bw.printf("    line %d: %v\n", sk.Line, sk.Err)
		}
	}

	bw.printf("\n  These are PREDICTIONS from a policy file. Nothing here was authorized,\n")
	bw.printf("  gated, or signed, and none of it is an audit record.\n\n")
	return bw.err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// errWriter collects the first write error so the formatting above stays readable.
type errWriter struct {
	w   io.Writer
	err error
}

func newErrWriter(w io.Writer) *errWriter { return &errWriter{w: w} }

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}
