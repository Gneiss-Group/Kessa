// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hdr assembles an SPDX header rather than spelling one out.
//
// Same reason internal/licensing does it: a file that writes licence headers as
// data must not read as declaring one. This file would otherwise claim several
// contradictory licences for itself, and the checker it tests would fail the
// build on it. The tag is split so no scanner, this one included, sees a
// declaration here.
func hdr(comment, license string) string {
	tag := "SPDX-License-" + "Identifier"
	return comment + " SPDX-FileCopyright" + "Text: 2026 Gneiss Group Inc.\n" +
		comment + " " + tag + ": " + license + "\n\n"
}

// spdxTagText is the bare tag, for tests that place it somewhere it must NOT be
// read as a declaration.
func spdxTagText() string { return "SPDX-License-" + "Identifier" }

// newRepo builds a throwaway git repository. git is real here rather than
// stubbed, because trackedFiles asks git for the file set and a test that swapped
// it out would not exercise the path the gate runs.
func newRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// baseFiles is a minimal compliant repository: two licence texts, a REUSE.toml
// covering the JSON that cannot carry a header, and one Go file that can.
func baseFiles() map[string]string {
	return map[string]string{
		"LICENSES/Apache-2.0.txt":      "Apache License text.\n",
		"LICENSES/AGPL-3.0-only.txt":   "AGPL text.\n",
		"REUSE.toml":                   reuseTOML(`"data/*.json"`, "Apache-2.0"),
		"main.go":                      hdr("//", "Apache-2.0") + "package main\n",
		"core.go":                      hdr("//", "AGPL-3.0-only") + "package main\n",
		"data/config.json":             "{}\n",
		"docs/note.md":                 hdr("<!--", "Apache-2.0") + "# Note\n",
		"docs/agpl-note.md":            hdr("<!--", "AGPL-3.0-only") + "# Note\n",
		"data/second.json":             "{}\n",
		"scripts/annotated-thing.json": "{}\n",
	}
}

// reuseTOML builds the fixture's annotation file. It annotates itself, exactly as
// the repository's own REUSE.toml does: a TOML file cannot carry a comment header
// that the format's consumers would keep, so it is covered by an entry of its
// own. Leaving that out is what made the first run of these tests fail, correctly.
func reuseTOML(paths, license string) string {
	return "version = 1\n\n[[annotations]]\npath = [" + paths + `, "scripts/**", "REUSE.toml"` + "]\n" +
		"SPDX-FileCopyright" + "Text = \"2026 Gneiss Group Inc.\"\n" +
		spdxTagText() + " = \"" + license + "\"\n"
}

func run(t *testing.T, files map[string]string) ([]problem, error) {
	t.Helper()
	problems, _, err := check(newRepo(t, files))
	return problems, err
}

func mustContain(t *testing.T, problems []problem, want string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("expected a %s problem, got:\n%s", want, strings.Join(problems, "\n"))
}

func TestCompliantTree_Passes(t *testing.T) {
	problems, err := run(t, baseFiles())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("a compliant tree was rejected:\n%s", strings.Join(problems, "\n"))
	}
}

// The flagship case, and the reason this program exists rather than `reuse lint`.
// A blanket glob that contradicts a file's own header lints clean under REUSE,
// because the header silently wins. Here it is an error: the project has stated
// two different licences for one file and a reader cannot tell which was meant.
func TestInlineHeaderContradictingAnnotation_IsRejected(t *testing.T) {
	files := baseFiles()
	// The file says AGPL; the glob covering scripts/ says Apache.
	files["scripts/tool.go"] = hdr("//", "AGPL-3.0-only") + "package main\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "CONTRADICTORY LICENCE")
	for _, p := range problems {
		if strings.Contains(p, "CONTRADICTORY") && !strings.Contains(p, "scripts/tool.go") {
			t.Fatalf("wrong file named:\n%s", p)
		}
	}
}

// Two annotations claiming one file different licences is the same defect
// reached from the other side, with no inline header involved at all.
func TestTwoAnnotationsDisagreeing_IsRejected(t *testing.T) {
	files := baseFiles()
	files["REUSE.toml"] = reuseTOML(`"data/*.json"`, "Apache-2.0") +
		"\n[[annotations]]\npath = [\"data/config.json\"]\n" +
		"SPDX-FileCopyright" + "Text = \"2026 Gneiss Group Inc.\"\n" +
		spdxTagText() + " = \"AGPL-3.0-only\"\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "CONTRADICTORY LICENCE")
}

func TestFileWithNoLicenceAtAll_IsRejected(t *testing.T) {
	files := baseFiles()
	files["orphan.txt"] = "no licence anywhere\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "UNLICENSED")
}

// The coverage property, stated as a test because it is the whole point of
// starting from git ls-files: a file type nobody anticipated must still be
// caught, not skipped for want of a matching glob.
func TestUnanticipatedFileType_IsStillChecked(t *testing.T) {
	files := baseFiles()
	files["weird.xyzzy"] = "a format nobody planned for\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "UNLICENSED")
}

func TestLicenceWithNoTextInLicensesDir_IsRejected(t *testing.T) {
	files := baseFiles()
	files["exotic.go"] = hdr("//", "MIT") + "package main\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "UNKNOWN LICENCE")
}

func TestLicenceTextNobodyUses_IsRejected(t *testing.T) {
	files := baseFiles()
	files["LICENSES/CC-BY-4.0.txt"] = "CC text.\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "UNUSED LICENCE TEXT")
}

func TestAnnotationMatchingNothing_IsRejected(t *testing.T) {
	files := baseFiles()
	files["REUSE.toml"] = reuseTOML(`"data/*.json", "deleted/**"`, "Apache-2.0")

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "STALE ANNOTATION")
}

// Licence texts do not need their own licence. Stated as a test so the exclusion
// stays deliberate rather than becoming a hole someone widens later.
func TestLicenceTextsThemselves_AreExempt(t *testing.T) {
	files := baseFiles()
	files["LICENSE"] = "The AGPL text, verbatim, with no header of its own.\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("licence texts should be exempt:\n%s", strings.Join(problems, "\n"))
	}
}

// A tag inside code, or in prose, is a mention and not a declaration. This is a
// regression test twice over: unanchored scans previously misread both
// internal/licensing's fixtures and REUSE.toml's own `SPDX-License-Identifier`
// key as headers.
func TestTagOutsideAComment_IsNotAHeader(t *testing.T) {
	files := baseFiles()
	files["quoter.go"] = hdr("//", "Apache-2.0") + "package main\n\n" +
		"var claim = \"" + spdxTagText() + ": AGPL-3.0-only\"\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("a quoted tag was read as a declaration:\n%s", strings.Join(problems, "\n"))
	}
}

// An SPDX header is at the top of a file by definition. A tag buried past the
// header window is not one, and treating it as one is how a scanner starts
// reading string literals as licensing.
func TestTagBelowTheHeaderWindow_IsNotAHeader(t *testing.T) {
	files := baseFiles()
	files["deep.go"] = "// " + strings.Repeat("filler\n// ", headerLines+4) + "\n" +
		"// " + spdxTagText() + ": AGPL-3.0-only\npackage main\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, problems, "UNLICENSED")
}

// Markdown in this repository carries its header as bare lines inside an HTML
// comment, where the tag line has no prefix of its own. If block comments were
// not tracked, every .md file would read as unlicensed.
func TestHeaderInsideABlockComment_IsRecognized(t *testing.T) {
	files := baseFiles()
	files["block.md"] = "<!--\n" +
		"SPDX-FileCopyright" + "Text: 2026 Gneiss Group Inc.\n" +
		spdxTagText() + ": Apache-2.0\n-->\n\n# Doc\n"

	problems, err := run(t, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("a block-comment header was not recognized:\n%s", strings.Join(problems, "\n"))
	}
}

// The parser refuses what it does not understand. A parser that skipped unknown
// keys would report OK while ignoring the key that changed the answer.
func TestParserRejectsUnknownKey(t *testing.T) {
	files := baseFiles()
	files["REUSE.toml"] = reuseTOML(`"data/*.json"`, "Apache-2.0") + "surprise = \"value\"\n"

	_, _, err := check(newRepo(t, files))
	if err == nil {
		t.Fatal("expected an error for an unknown REUSE.toml key")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("wrong error: %v", err)
	}
}

// `precedence` decides which statement wins when two disagree. This checker
// forbids disagreement instead of resolving it, so honouring the key is not
// possible and silently ignoring it would make the program's central claim false
// while it reported OK.
func TestParserRejectsPrecedenceKey(t *testing.T) {
	files := baseFiles()
	files["REUSE.toml"] = reuseTOML(`"data/*.json"`, "Apache-2.0") + "precedence = \"override\"\n"

	_, _, err := check(newRepo(t, files))
	if err == nil {
		t.Fatal("expected an error for the precedence key")
	}
	if !strings.Contains(err.Error(), "precedence") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"docs/*.md", "docs/a.md", true},
		{"docs/*.md", "docs/sub/a.md", false}, // * does not cross a separator
		{"docs/**", "docs/sub/deep/a.png", true},
		{"examples/**", "examples/a.json", true},
		{"a?c.txt", "abc.txt", true},
		{"a?c.txt", "a/c.txt", false},
		{"exact.md", "exact.md", true},
		{"exact.md", "other.md", false},
	}
	for _, c := range cases {
		got, err := matchPath(c.pattern, c.path)
		if err != nil {
			t.Fatalf("matchPath(%q, %q): %v", c.pattern, c.path, err)
		}
		if got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// The strongest single assertion available: the real repository passes. It is
// what the gate runs, and it catches anything the synthetic trees above model
// wrongly.
func TestThisRepository_IsCompliant(t *testing.T) {
	problems, summary, err := check("../..")
	if err != nil {
		t.Fatalf("checking the repository: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("the repository is not compliant:\n%s", strings.Join(problems, "\n"))
	}
	if !strings.Contains(summary, "no file carries two licences") {
		t.Fatalf("unexpected summary: %s", summary)
	}
}
