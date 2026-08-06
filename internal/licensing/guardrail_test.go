// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package licensing

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The legal guardrail, exercised rather than asserted.
//
// The Section 7 additional permission fires only for code that reaches the AGPL
// core exclusively through a designated interface. If a designated package
// imports the core itself, the condition is unsatisfiable for every implementer,
// and the combined binary is plain AGPL-3.0 over the whole thing. That is the
// sentence a plugin author relies on, so it gets a test, not a paragraph.
//
// Each case builds a throwaway module in a temp directory and runs the real
// scripts/license-check.sh against it. The script derives its module path from
// `go list -m` in the working directory for exactly this reason: a check that can
// only ever be pointed at this repository cannot be shown a violation.

const marker = "//kessa:plugin-interface"

// notice is the permission pointer every marked file must carry, assembled from
// pieces for the same reason hdr is: fixtures that quote it must not read as
// carrying it. See the comment on hdr.
func notice() string {
	return "// ADDITIONAL " + "PERMISSION: see the clause at the end of LICENSE.\n"
}

// hdr builds the SPDX header this test writes into its fixture files.
//
// The tag is assembled from two pieces rather than written whole, and that is not
// squeamishness. Spelled out literally, every scanner that reads this repository
// finds the fixture headers and takes them for this file's own licensing: `reuse
// lint` tries to parse "AGPL-3.0-only\n\n\"" as an SPDX expression, fails, and
// then skips the file entirely, reporting it as having no licence at all. The
// same root cause made license-check.sh read this package as split-tier before
// its scans were anchored.
//
// The general shape is worth naming, because this file has now tripped it twice
// against two different tools: a file that must *quote* the thing a scanner looks
// for has to keep the quotation from reading as a declaration. Anchoring solves
// it on the scanner side, splitting solves it on this side, and a file that
// writes licence headers as data needs the second one too.
func hdr(license string) string {
	tag := "SPDX-License-" + "Identifier"
	return "// SPDX-FileCopyright" + "Text: 2026 Gneiss Group Inc.\n" +
		"//\n// " + tag + ": " + license + "\n\n"
}

var (
	apacheHdr = hdr("Apache-2.0")
	agplHdr   = hdr("AGPL-3.0-only")
)

// fixture is one synthesized module: a set of files, written verbatim.
type fixture map[string]string

// build writes the fixture into a temp module rooted at example.test/fixture and
// returns its path.
func (f fixture) build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := fixture{"go.mod": "module example.test/fixture\n\ngo 1.26\n"}
	for name, body := range f {
		files[name] = body
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// scriptPath locates the real check relative to this test file.
func scriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	p := filepath.Join(wd, "..", "..", "scripts", "license-check.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("cannot find license-check.sh at %s: %v", p, err)
	}
	return p
}

// runCheck runs the check (or a mutated copy of it) against a fixture module.
func runCheck(t *testing.T, script, moduleDir string) (string, bool) {
	t.Helper()
	cmd := exec.Command("bash", script)
	cmd.Dir = moduleDir
	// GOFLAGS is cleared so a caller's -mod setting cannot make go list fail in a
	// module that has no dependencies to resolve.
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// mutate returns a copy of the script with one sentinel-delimited guard deleted,
// so a test can confirm the failure it observed came from that guard and not from
// some unrelated check happening to trip on the same fixture.
func mutate(t *testing.T, script, guard string) string {
	t.Helper()
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	var kept []string
	skipping := false
	for _, line := range strings.Split(string(src), "\n") {
		switch {
		case strings.Contains(line, "BEGIN GUARDRAIL "+guard):
			skipping = true
		case strings.Contains(line, "END GUARDRAIL "+guard):
			skipping = false
		case !skipping:
			kept = append(kept, line)
		}
	}
	if skipping {
		t.Fatalf("guard %q has a BEGIN sentinel with no END", guard)
	}
	out := filepath.Join(t.TempDir(), "license-check-mutated.sh")
	if err := os.WriteFile(out, []byte(strings.Join(kept, "\n")), 0o755); err != nil {
		t.Fatalf("write mutated script: %v", err)
	}
	return out
}

// A designated plug point that only touches the standard library is the shape the
// permission is written for, and it must pass. Without this case the suite could
// be satisfied by a check that rejects everything.
func TestDesignatedPlugPoint_StdlibOnly_Passes(t *testing.T) {
	dir := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug is a designated plug point.\n" +
			"//\n" + notice() + "//\n" + marker + "\npackage plug\n\n" +
			"import \"time\"\n\n" +
			"// Record is what crosses the seam.\ntype Record struct{ At time.Time }\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(r Record) error\n}\n",
		"internal/core/core.go": agplHdr + "package core\n\n// Enforce is core authority.\nfunc Enforce() bool { return true }\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if !ok {
		t.Fatalf("clean designated plug point was rejected:\n%s", out)
	}
}

// THE guardrail, in the case where only the guardrail can catch it.
//
// A designated plug point may depend on the standard library and other
// designated packages, and on nothing else. Depending on a package that is
// merely permissive is not caught by the tier check (no copyleft crosses, both
// sides are Apache), yet it still breaks the promise the designation makes: an
// implementer is forced to link a package that is not itself part of the
// designated seam, and whose own closure nothing constrains, so it is free to
// grow an AGPL dependency later and drag every plugin in with it.
//
// This is the fixture the mutation check is built on, precisely because it trips
// one check and not two.
func TestDesignatedPlugPoint_DependingOnUndesignatedPackage_IsRejected(t *testing.T) {
	files := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug is a designated plug point that reaches outside its seam.\n" +
			"//\n" + notice() + "//\n" + marker + "\npackage plug\n\n" +
			"import \"example.test/fixture/internal/helper\"\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n\n" +
			"// Normalize drags a non-designated package across the seam.\n" +
			"func Normalize(s string) string { return helper.Normalize(s) }\n",
		"internal/helper/helper.go": apacheHdr + "package helper\n\n" +
			"// Normalize is permissive, but it is not a designated plug point.\n" +
			"func Normalize(s string) string { return s }\n",
	}
	dir := files.build(t)
	script := scriptPath(t)

	out, ok := runCheck(t, script, dir)
	if ok {
		t.Fatalf("a designated plug point depending on an undesignated package was accepted:\n%s", out)
	}
	if !strings.Contains(out, "GUARDRAIL VIOLATION") {
		t.Fatalf("rejected, but not by the guardrail:\n%s", out)
	}

	// Observed to fail with its guard removed, per docs/go-standards.md. With the
	// closure check deleted this tree must pass CLEANLY: nothing else in the
	// script has an opinion about it. That is what proves the rejection above came
	// from the guardrail and not from a neighbour.
	out, ok = runCheck(t, mutate(t, script, "closure"), files.build(t))
	if !ok {
		t.Fatalf("with the closure guard removed the violating tree still failed, so the\nassertion above was not observing that guard:\n%s", out)
	}
}

// The headline legal case: a plugin seam that touches AGPL internals directly.
// Two independent checks reject this, which is the correct amount of
// defence-in-depth and also why it cannot carry the mutation check above. The
// assertion here is that the guardrail is one of the two, and that it is the
// guardrail specifically that names the boundary.
func TestDesignatedPlugPoint_ReachingIntoAGPLCore_IsRejected(t *testing.T) {
	files := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug is a designated plug point that cheats.\n" +
			"//\n" + notice() + "//\n" + marker + "\npackage plug\n\n" +
			"import \"example.test/fixture/internal/core\"\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n\n" +
			"// Allowed leaks the core across the seam.\nfunc Allowed() bool { return core.Enforce() }\n",
		"internal/core/core.go": agplHdr + "package core\n\n// Enforce is core authority.\nfunc Enforce() bool { return true }\n",
	}
	dir := files.build(t)
	script := scriptPath(t)

	out, ok := runCheck(t, script, dir)
	if ok {
		t.Fatalf("a designated plug point importing the AGPL core was accepted:\n%s", out)
	}
	if !strings.Contains(out, "GUARDRAIL VIOLATION") {
		t.Fatalf("rejected, but the guardrail did not fire on it:\n%s", out)
	}

	// Remove the closure guard and the tier check must still catch it, with the
	// guardrail's message gone. If GUARDRAIL VIOLATION survived its own guard's
	// deletion, the message would be coming from somewhere else and the assertion
	// above would mean nothing.
	out, ok = runCheck(t, mutate(t, script, "closure"), files.build(t))
	if ok {
		t.Fatalf("with the closure guard removed, nothing caught a plug point importing\nthe AGPL core; the tier check is meant to be the second layer:\n%s", out)
	}
	if strings.Contains(out, "GUARDRAIL VIOLATION") {
		t.Fatalf("the guardrail message survived deletion of the guardrail, so it is not\ncoming from the guard the test claims to exercise:\n%s", out)
	}
	if !strings.Contains(out, "LICENSE VIOLATION") {
		t.Fatalf("expected the tier check to be the surviving layer:\n%s", out)
	}
}

// Fail closed: a package shaped like a plug point but missing the marker must be
// rejected rather than quietly treated as ordinary permissive code, which would
// leave it outside the closure guardrail entirely.
func TestPlugPointShapedPackage_WithoutMarker_IsRejected(t *testing.T) {
	files := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug forgot its marker.\npackage plug\n\n" +
			"// Sink looks exactly like a designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n",
	}
	dir := files.build(t)
	script := scriptPath(t)

	out, ok := runCheck(t, script, dir)
	if ok {
		t.Fatalf("an unmarked, externally importable interface package was accepted:\n%s", out)
	}
	if !strings.Contains(out, "UNDESIGNATED PLUG POINT") {
		t.Fatalf("rejected, but not by the designation check:\n%s", out)
	}

	out, ok = runCheck(t, mutate(t, script, "designation"), files.build(t))
	if !ok {
		t.Fatalf("with the designation guard removed the unmarked tree still failed:\n%s", out)
	}
}

// An interface under internal/ is not an external seam: the Go toolchain already
// forbids importing it from another module, so nobody can implement it as a
// plugin and it needs no marker. This is the exclusion the fail-closed check
// above is allowed to make, and it is stated as a test so it stays deliberate.
func TestInternalInterface_NeedsNoMarker(t *testing.T) {
	dir := fixture{
		"internal/policy/policy.go": apacheHdr +
			"// Package policy is internal.\npackage policy\n\n" +
			"// Evaluator is not an external seam.\ntype Evaluator interface {\n\tEval(s string) bool\n}\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if !ok {
		t.Fatalf("an internal interface was treated as an undesignated plug point:\n%s", out)
	}
}

// The marker designates the file that DECLARES the interface. On an implementing
// file it would move the boundary to wherever someone last pasted a comment.
func TestMarker_OnImplementationFile_IsRejected(t *testing.T) {
	dir := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug declares the seam.\npackage plug\n\n" +
			"// Sink is the interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n",
		"plug/impl.go": apacheHdr + notice() +
			"package plug\n\n" +
			"// The marker does not belong here.\n//\n" + marker + "\ntype noopSink struct{}\n\n" +
			"func (noopSink) Write(string) error { return nil }\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("a marker on an implementation file was accepted:\n%s", out)
	}
	if !strings.Contains(out, "MISPLACED MARKER") {
		t.Fatalf("rejected, but not for the marker's placement:\n%s", out)
	}
}

// Designation is a directive, not a mention. A file that merely quotes the marker
// or an SPDX identifier, in a string literal, in prose, in a test that builds
// fixtures out of them, does not thereby designate or reclassify its package.
//
// This is a regression test, not a hypothetical. The first run of the rewritten
// check read this very file as a split-tier, marker-carrying plug point, because
// the constants at the top of it contain both strings. An unanchored scan makes
// the classification something any file can trigger by talking about it, which is
// the same failure as a check that passes without testing anything, arriving from
// the other direction.
func TestQuotedMarkerAndIdentifiers_DoNotDesignate(t *testing.T) {
	// Split for the same reason hdr splits: this fixture's whole point is to
	// contain the tag as data, so it must not read as this file's own header.
	quotedTag := "SPDX-License-" + "Identifier"
	dir := fixture{
		"tool/tool.go": apacheHdr + "package tool\n\n" +
			"// These are strings a checker must not read as declarations.\n" +
			"const (\n" +
			"\tmarkerText = \"" + marker + "\"\n" +
			"\theaderText = \"// " + quotedTag + ": AGPL-3.0-only\"\n" +
			")\n\n" +
			"// Describe reports what this package talks about.\n" +
			"func Describe() string { return markerText + headerText }\n\n" +
			"// Doer is an exported interface, so the fail-closed check would demand a\n" +
			"// marker here if the quoted one counted.\ntype Doer interface {\n\tDo() error\n}\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("expected the fail-closed designation check to fire (the package is\nplug-point-shaped and genuinely unmarked):\n%s", out)
	}
	if !strings.Contains(out, "UNDESIGNATED PLUG POINT") {
		t.Fatalf("expected UNDESIGNATED PLUG POINT, meaning the quoted marker did not\ncount as a designation:\n%s", out)
	}
	if strings.Contains(out, "SPLIT-TIER PACKAGE") {
		t.Fatalf("a quoted SPDX identifier reclassified the package:\n%s", out)
	}
	if strings.Contains(out, "BAD DESIGNATION") || strings.Contains(out, "MISPLACED MARKER") {
		t.Fatalf("a quoted marker was treated as a designation:\n%s", out)
	}
}

// A licensing requirement from counsel, enforced rather than remembered.
//
// The marker travels with a file when someone copies it out of the distribution.
// LICENSE does not. A detached file carrying a designation whose grant the reader
// cannot locate is worse than an undesignated one, so a marked file must also
// point at the clause. This is the rule that stops a NEW plug point shipping
// without it, which is the only way the requirement decays: auditsink will not
// lose its notice, but the second designated interface could be added without one.
func TestMarkedFileWithoutItsPermissionNotice_IsRejected(t *testing.T) {
	files := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug is designated but says nothing about the permission.\n" +
			"//\n" + marker + "\npackage plug\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n",
	}
	dir := files.build(t)
	script := scriptPath(t)

	out, ok := runCheck(t, script, dir)
	if ok {
		t.Fatalf("a marked file with no permission notice was accepted:\n%s", out)
	}
	if !strings.Contains(out, "MARKED FILE WITHOUT ITS PERMISSION NOTICE") {
		t.Fatalf("rejected, but not for the missing notice:\n%s", out)
	}

	// Observed to fail with its guard removed. With the notice check deleted this
	// tree must pass cleanly: nothing else in the script has an opinion about it,
	// which is what proves the rejection came from this guard and not a neighbour.
	out, ok = runCheck(t, mutate(t, script, "notice"), files.build(t))
	if !ok {
		t.Fatalf("with the notice guard removed the tree still failed, so the assertion\nabove was not observing that guard:\n%s", out)
	}
}

// The notice is a POINTER to the clause, never a copy of it. Two copies of
// operative text is how they come to disagree, and a file quoting the notice must
// not thereby appear to carry it, which is the anchoring lesson this suite has now
// learned three times.
func TestQuotedNoticeDoesNotSatisfyTheRequirement(t *testing.T) {
	files := fixture{
		"plug/plug.go": apacheHdr +
			"// Package plug quotes the notice instead of carrying it.\n" +
			"//\n" + marker + "\npackage plug\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n\n" +
			"// Text is the notice as data, indented, not as a comment of this file.\n" +
			"const Text = \"" + strings.TrimSuffix(notice(), "\n") + "\"\n",
	}
	dir := files.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("a quoted notice satisfied the requirement:\n%s", out)
	}
	if !strings.Contains(out, "MARKED FILE WITHOUT ITS PERMISSION NOTICE") {
		t.Fatalf("rejected, but not for the missing notice:\n%s", out)
	}
}

// A designated plug point under a protective licence promises a third party
// something its own SPDX headers refuse to grant.
func TestDesignatedPlugPoint_UnderAGPLHeader_IsRejected(t *testing.T) {
	dir := fixture{
		"plug/plug.go": agplHdr +
			"// Package plug claims to be a plug point.\n" +
			"//\n" + notice() + "//\n" + marker + "\npackage plug\n\n" +
			"// Sink is the designated interface.\ntype Sink interface {\n\tWrite(s string) error\n}\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("an AGPL-licensed designated plug point was accepted:\n%s", out)
	}
	if !strings.Contains(out, "BAD DESIGNATION") {
		t.Fatalf("rejected, but not for the licence contradiction:\n%s", out)
	}
}

// Tier is derived per package from its own headers, so a package whose files
// disagree has no tier and must not be guessed at.
func TestSplitTierPackage_IsRejected(t *testing.T) {
	dir := fixture{
		"mix/a.go": apacheHdr + "package mix\n\n// A is permissive.\nfunc A() {}\n",
		"mix/b.go": agplHdr + "package mix\n\n// B is protective.\nfunc B() {}\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("a package with contradictory SPDX headers was accepted:\n%s", out)
	}
	if !strings.Contains(out, "SPLIT-TIER PACKAGE") {
		t.Fatalf("rejected, but not for the split tier:\n%s", out)
	}
}

// The original viral-copyleft check, which the rewrite must not have lost.
func TestApacheTierImportingAGPLTier_IsRejected(t *testing.T) {
	dir := fixture{
		"tool/tool.go": apacheHdr + "package tool\n\n" +
			"import \"example.test/fixture/internal/core\"\n\n" +
			"// Run links the core.\nfunc Run() bool { return core.Enforce() }\n",
		"internal/core/core.go": agplHdr + "package core\n\n// Enforce is core authority.\nfunc Enforce() bool { return true }\n",
	}.build(t)

	out, ok := runCheck(t, scriptPath(t), dir)
	if ok {
		t.Fatalf("an Apache-tier package importing an AGPL-tier one was accepted:\n%s", out)
	}
	if !strings.Contains(out, "LICENSE VIOLATION") {
		t.Fatalf("rejected, but not for the tier import:\n%s", out)
	}
}
