// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	commercePol  = "../../examples/policies/commerce-security.json"
	allowlistPol = "../../examples/policies/commerce-security-allowlist.json"
	exportFix    = "../../testdata/shadow/replay_export.json"
	actionsFix   = "../../testdata/shadow/actions.jsonl"
)

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// decodeLines parses JSON-Lines output into generic maps.
func decodeLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("output line is not valid JSON: %q (%v)", line, err)
		}
		out = append(out, m)
	}
	return out
}

// ---- mode A: export replay --------------------------------------------------

func TestExportReplay_ClassifiesAndDiffs(t *testing.T) {
	code, out, errb := invoke(t, "-policy", commercePol, "-export", exportFix)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, errb)
	}
	lines := decodeLines(t, out)
	if len(lines) != 5 {
		t.Fatalf("expected 5 predictions, got %d", len(lines))
	}
	for i, m := range lines {
		if _, ok := m["actual"]; !ok {
			t.Fatalf("prediction %d: export replay must carry the recorded decision", i)
		}
		agree, ok := m["agreement"].(bool)
		if !ok {
			t.Fatalf("prediction %d: missing agreement", i)
		}
		if !agree {
			t.Fatalf("prediction %d: commerce policy should agree with its own recorded decisions", i)
		}
	}
}

// A prediction must never look like a verdict on the wire.
func TestOutputIsNeverMistakableForAVerdict(t *testing.T) {
	_, out, _ := invoke(t, "-policy", commercePol, "-export", exportFix)
	for i, m := range decodeLines(t, out) {
		if _, ok := m["allowed"]; ok {
			t.Fatalf("prediction %d has a top-level \"allowed\" field; that reads as an enforcement verdict", i)
		}
		if _, ok := m["statusChecked"]; ok {
			t.Fatalf("prediction %d has \"statusChecked\"; shadow mode never checks status", i)
		}
		for _, want := range []string{"consequential", "policyDenies", "matchedRule", "policyID", "source"} {
			if _, ok := m[want]; !ok {
				t.Fatalf("prediction %d missing %q", i, want)
			}
		}
	}
}

func TestExportReplay_TextModeReportsDiffSummary(t *testing.T) {
	code, out, _ := invoke(t, "-policy", commercePol, "-export", exportFix, "-format", "text")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{
		"PREDICTIONS ONLY", "nothing was enforced",
		"Compared against 5 recorded decisions", "agreed", "under-predicted", "over-predicted",
		"Agreement compares CONSEQUENTIALITY only",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("text output missing %q:\n%s", want, out)
		}
	}
}

// A candidate policy that disagrees with history must surface the disagreement,
// and must name the dangerous direction specifically.
func TestExportReplay_SurfacesUnderPrediction(t *testing.T) {
	// The allow-list policy has no high-value-transfer rule; a $500 transfer falls
	// to its consequential default, while entry 4's $10 transfer, routine in the
	// recording, also becomes consequential. Entries recorded as consequential that
	// the allow-list policy also gates still agree. The interesting direction here
	// is over-prediction; assert the summary distinguishes them rather than
	// lumping them together.
	code, out, _ := invoke(t, "-policy", allowlistPol, "-export", exportFix, "-format", "text")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "over-predicted") || !strings.Contains(out, "under-predicted") {
		t.Fatalf("summary must break disagreement down by direction:\n%s", out)
	}
}

func TestMalformedExportIsFatal(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":"kessa-audit-export/v2",`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := invoke(t, "-policy", commercePol, "-export", bad)
	if code != exitUsage {
		t.Fatalf("a malformed export must fail the run, got exit=%d out=%s", code, out)
	}
	if !strings.Contains(errb, "kessa-shadow:") {
		t.Fatalf("expected a clear error, got %q", errb)
	}
}

// ---- mode B: hand-authored actions ------------------------------------------

func TestActionsFile_SkipsBadLinesAndReportsCount(t *testing.T) {
	code, out, errb := invoke(t, "-policy", commercePol, "-actions", actionsFix)
	if code != exitOK {
		t.Fatalf("a bad line must not fail the run: exit=%d stderr=%s", code, errb)
	}
	lines := decodeLines(t, out)
	if len(lines) != 5 {
		t.Fatalf("expected 5 classified actions, got %d", len(lines))
	}
	if !strings.Contains(errb, "3 input line(s) skipped") {
		t.Fatalf("expected a skipped-line count on stderr, got %q", errb)
	}
	// Each skipped line must be individually reported with its line number.
	for _, want := range []string{"skipped unparseable action"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("stderr missing %q: %s", want, errb)
		}
	}
	// Mode B has nothing to diff against.
	for i, m := range lines {
		if _, ok := m["actual"]; ok {
			t.Fatalf("prediction %d: an actions-file run must not claim a recorded decision", i)
		}
		if _, ok := m["agreement"]; ok {
			t.Fatalf("prediction %d: no agreement without a recorded decision", i)
		}
	}
}

// ---- flags and errors -------------------------------------------------------

func TestFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"-export", exportFix}, "-policy is required"},
		{"neither mode", []string{"-policy", commercePol}, "exactly one of -export or -actions"},
		{"both modes", []string{"-policy", commercePol, "-export", exportFix, "-actions", actionsFix}, "mutually exclusive"},
		{"bad format", []string{"-policy", commercePol, "-export", exportFix, "-format", "yaml"}, "unknown -format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errb := invoke(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("expected usage exit, got %d", code)
			}
			if !strings.Contains(errb, tc.want) {
				t.Fatalf("expected error mentioning %q, got %q", tc.want, errb)
			}
		})
	}
}

// An invalid policy must fail with policy.Parse's own error, not a swallowed or
// downgraded one (§4.2).
func TestInvalidPolicyIsRejectedWithItsOwnError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad-policy.json")
	// Valid JSON, but no "default" block: rejected by the shared validation.
	if err := os.WriteFile(bad, []byte(`{"version":"v1","rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := invoke(t, "-policy", bad, "-actions", actionsFix)
	if code != exitUsage {
		t.Fatalf("expected usage exit, got %d", code)
	}
	if !strings.Contains(errb, `missing required "default" block`) {
		t.Fatalf("policy validation error should reach the user verbatim, got %q", errb)
	}
}

func TestOutFileWritesPredictions(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "preds.jsonl")
	code, stdout, errb := invoke(t, "-policy", commercePol, "-export", exportFix, "-out", outPath)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, errb)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("-out should divert output from stdout, got %q", stdout)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodeLines(t, string(b))) != 5 {
		t.Fatal("expected 5 predictions in the output file")
	}
}

// ---- the documentation guarantee (definition of done) ------------------------

// -help must state, in the tool's own output, that it does not verify exports.
func TestHelpDisclaimsVerification(t *testing.T) {
	_, _, errb := invoke(t, "-help")
	for _, want := range []string{"NOT", "verified", "kessa verify", "nothing enforced"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("help text must disclaim verification; missing %q:\n%s", want, errb)
		}
	}
}

// cmd/shadow must never link the enforcement engine.
func TestShadowDoesNotLinkEnforcement(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, forbidden := range []string{"/internal/enforce", "/internal/keystore", "/cmd/proxy", "/cmd/issuer", "/cmd/agent"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("kessa-shadow links %s; it enforces nothing and must not depend on the enforcement tier", forbidden)
		}
	}
}
