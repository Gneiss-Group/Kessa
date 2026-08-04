// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Policy-ingress surface tests.
//
// The production guarantee is narrow and absolute: the ONLY policy that can
// influence a verification run is the one unmarshalled from the export's own
// bytes. internal/export's trust-boundary suite proves a substituted policy is
// caught cryptographically; these tests guard the other half, that there is no
// way to hand the verifier a policy in the first place.
//
// They exist because that guarantee is currently upheld by an ABSENCE (no flag,
// no env var, no config discovery), and an absence is exactly the kind of
// property that erodes silently. Encoding it as assertions means a future change
// that widens the ingress surface trips a visible test rather than passing
// unnoticed.

// The complete, intended flag surface of `kessa verify`. `color` is a pure
// presentation control: it is read only after export.Verify has returned and
// cannot reach the verification path, so it does not widen what steers a verdict.
var wantFlags = []string{"color", "dids", "export", "fetch-dids", "quiet", "status"}

// substrings that would suggest a flag can steer classification
var policyish = []string{"policy", "rule", "default", "verdict", "eval", "classif", "consequen"}

// TestIngress_FlagSurfaceIsExactlyAsExpected pins the flag set. Adding a flag is
// fine, but it must be a deliberate act that updates this list, not a silent
// expansion of what can influence a verdict.
func TestIngress_FlagSurfaceIsExactlyAsExpected(t *testing.T) {
	_, _, usage := invoke(t, "verify", "--help")

	var got []string
	for _, line := range strings.Split(usage, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "-") {
			continue // continuation/description line
		}
		name := strings.TrimPrefix(trimmed, "-")
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			got = append(got, name)
		}
	}
	sort.Strings(got)

	want := append([]string(nil), wantFlags...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("flag surface changed.\n got: %v\nwant: %v\n\nIf this is intentional, update wantFlags: "+
			"and satisfy yourself the new flag cannot influence which policy a verdict is derived from.\nusage:\n%s",
			got, want, usage)
	}

	for _, f := range got {
		for _, bad := range policyish {
			if strings.Contains(strings.ToLower(f), bad) {
				t.Fatalf("flag %q looks like it could steer classification (matched %q). "+
					"The only policy a verification may use is the one carried in the export.", f, bad)
			}
		}
	}
}

// TestIngress_NoPolicyOverrideFlagIsAccepted probes the argv parser directly for
// every plausible spelling of a policy-override flag.
func TestIngress_NoPolicyOverrideFlagIsAccepted(t *testing.T) {
	for _, f := range []string{
		"--policy", "-policy", "--policy-file", "--policyfile", "--rules",
		"--default-verdict", "--policy-default", "--evaluator", "--classifier",
	} {
		code, out, errb := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot,
			"--status", statusArg(), f, "/nonexistent/policy.json")
		if code != exitUsage {
			t.Fatalf("%s: exit=%d, want %d: the flag appears to be ACCEPTED\nstdout:\n%s\nstderr:\n%s",
				f, code, exitUsage, out, errb)
		}
		if !strings.Contains(errb, "flag provided but not defined") {
			t.Fatalf("%s: unexpected rejection reason: %s", f, errb)
		}
	}
}

// TestIngress_EnvironmentCannotSteerVerification sets every plausible env var to
// a permissive policy file and asserts the verdict is byte-identical. The
// verifier reads no environment at all; this pins that.
func TestIngress_EnvironmentCannotSteerVerification(t *testing.T) {
	polPath := filepath.Join(t.TempDir(), "permissive.json")
	permissive := `{"version":"attacker-v1","rules":[],"default":{"allowed":true,"consequential":false,"reason":"everything is routine"}}`
	if err := os.WriteFile(polPath, []byte(permissive), 0o644); err != nil {
		t.Fatal(err)
	}

	codeBase, baseline, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg())

	for _, k := range []string{
		"KESSA_POLICY", "KESSA_POLICY_FILE", "KESSA_POLICY_PATH", "KESSA_DEFAULT_VERDICT",
		"KESSA_CONFIG", "KESSA_RULES", "POLICY", "POLICY_FILE", "KESSA_EVALUATOR",
		"KESSA_POLICY_DEFAULT", "KESSA_DEBUG", "KESSA_TEST_HOOK",
	} {
		t.Setenv(k, polPath)
	}
	codeEnv, withEnv, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg())

	if codeEnv != codeBase || withEnv != baseline {
		t.Fatalf("the environment changed the verdict (exit %d -> %d).\nbaseline:\n%s\nwith env:\n%s",
			codeBase, codeEnv, baseline, withEnv)
	}
}

// TestIngress_NoSidecarPolicyDiscovery asserts the verifier does not pick up a
// policy file sitting next to the export it was pointed at.
func TestIngress_NoSidecarPolicyDiscovery(t *testing.T) {
	dir := t.TempDir()
	golden, err := os.ReadFile(v2Golden)
	if err != nil {
		t.Fatal(err)
	}
	expPath := filepath.Join(dir, "export.json")
	if err := os.WriteFile(expPath, golden, 0o644); err != nil {
		t.Fatal(err)
	}
	permissive := []byte(`{"version":"attacker-v1","rules":[],"default":{"allowed":true,"consequential":false,"reason":"routine"}}`)
	for _, n := range []string{"policy.json", "export.policy.json", "kessa.json", ".kessarc", "config.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), permissive, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, out, errb := invoke(t, "verify", "--export", expPath, "--dids", didsRoot, "--status", statusArg())
	if code != exitPass {
		t.Fatalf("sidecar files perturbed a legitimate verification: exit=%d\nstdout:\n%s\nstderr:\n%s", code, out, errb)
	}
}

// TestIngress_VerifierDoesNotDirectlyImportPolicy encodes the guarantee as
// directly as the tooling allows.
//
// cmd/verify DOES link internal/policy transitively, through internal/export,
// and that is correct: re-deriving consequentiality (F1) requires running the
// same classifier the proxy ran. What must stay true is that cmd/verify's own
// code never names the package, because the only way it could obtain a
// policy.Policy of its own is by importing it. Every policy reaching a verdict
// therefore arrives through export.Parse, i.e. from the export's bytes.
//
// `go list -f {{.Imports}}` reports DIRECT imports only, which is exactly the
// distinction being asserted.
func TestIngress_VerifierDoesNotDirectlyImportPolicy(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{range .Imports}}{{.}}{{"\n"}}{{end}}`, ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	imports := strings.Fields(string(out))
	if len(imports) == 0 {
		t.Fatal("go list reported no direct imports; the check would pass vacuously")
	}

	for _, imp := range imports {
		if strings.HasSuffix(imp, "/internal/policy") {
			t.Fatalf("cmd/verify directly imports %q.\n\n"+
				"The verifier must never hold a policy of its own: the only policy that may "+
				"influence a verdict is the one carried in the export under verification, "+
				"obtained via export.Parse. A direct import is how that guarantee would be "+
				"lost. See internal/export/trustboundary_test.go.", imp)
		}
	}

	// Sanity: the transitive link IS expected, so this test is asserting the
	// direct/transitive distinction rather than trivially passing.
	deps, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	if !strings.Contains(string(deps), "/internal/policy") {
		t.Fatal("expected internal/policy to be linked transitively (via internal/export); " +
			"if that changed, consequentiality re-derivation (F1) may no longer be happening")
	}
}
