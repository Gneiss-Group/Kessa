// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// next-version.sh decides the version of the next release from the commit
// range, and the BREAKING CHANGE footer is the only route to a minor bump for a
// release that carries no feat: commit. That makes the footer check the single
// point where an understated version number gets decided, and it was racy: the
// old form short-circuited with `grep -q`, which cut `git log` off mid-write and
// let `set -o pipefail` report the whole pipeline as failed at the moment the
// footer was found.
//
// The important property of these fixtures is therefore SIZE, not shape. A
// two-commit range reproduced the bug only about one run in ten; the real
// v0.1.0..HEAD range, at 33 KB, missed it seven times in ten. So the range below
// is deliberately large and the footer is on the NEWEST commit, which is where
// git log emits it first and leaves the most output still unwritten behind it.
// A fixture that put the footer on the oldest commit would pass against the bug,
// because by then git has already written everything.
const (
	filler      = 40        // commits after the footer, in git log's output order
	fillerBytes = 20 * 1024 // body size each, so the range clears any pipe buffer
	fixtureVer  = "0.1.0"   // what the temp repo's version.go carries
	wantVer     = "0.2.0"   // minor, because a 0.x breaking change cannot take the major
	footer      = "BREAKING CHANGE: the shape of a thing changed, and this sentence exists to be found."
)

// nextVersion builds a throwaway repository tagged v0.1.0, lays down a range of
// commits, and runs the real next-version.sh inside it.
//
// The script is COPIED into the temporary repository rather than invoked in
// place, for the reason renderNotes gives: it resolves its own root as two
// directories up from itself and cd's there, so the checked-out copy would read
// the real repository's history and pass no matter what the fixture said.
// version.sh comes along because next-version.sh shells out to it.
func nextVersion(t *testing.T, subjects []string) (stdout, stderr string) {
	t.Helper()

	repo := t.TempDir()
	scripts := filepath.Join(repo, "scripts", "release")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"next-version.sh", "version.sh"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scripts, name), src, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// version.sh reads the constant, so the fixture needs one to read.
	verDir := filepath.Join(repo, "internal", "version")
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verDir, "version.go"),
		[]byte("package version\n\nconst Version = \""+fixtureVer+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	git(t, repo, "init", "--quiet", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(repo, "base"), []byte("base"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "--quiet", "--no-gpg-sign", "-m", "chore: base")
	git(t, repo, "tag", "v"+fixtureVer)

	for i, subject := range subjects {
		name := filepath.Join(repo, fmt.Sprintf("f%03d", i))
		if err := os.WriteFile(name, []byte(subject), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, repo, "add", ".")
		git(t, repo, "commit", "--quiet", "--no-gpg-sign", "-m", subject)
	}

	cmd := exec.Command("bash", filepath.Join(scripts, "next-version.sh"), "auto")
	cmd.Dir = repo
	cmd.Env = gitEnv()
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("next-version.sh: %v\n%s", err, errBuf.String())
	}
	return strings.TrimSpace(string(out)), errBuf.String()
}

// bulk builds a range whose only route to a minor bump is the footer: every
// subject is a fix:, none is a feat:, and none carries the "!" marker.
func bulk(t *testing.T, withFooter bool) []string {
	t.Helper()
	body := strings.Repeat("padding to make this commit body large enough to matter. ", fillerBytes/56)
	subjects := make([]string, 0, filler+1)
	for i := 0; i < filler; i++ {
		subjects = append(subjects, "fix(thing): a change that breaks nothing\n\n"+body)
	}
	if withFooter {
		// Committed LAST, so git log emits it FIRST and the whole filler range is
		// still unwritten behind it.
		subjects = append(subjects, "fix(thing): a change that does break something\n\n"+body+"\n\n"+footer)
	}
	return subjects
}

// TestNextVersionSeesABreakingFooterBehindALargeRange is the regression. Against
// the short-circuiting form it fails: the footer is found, git is cut off, and
// the derived bump comes back patch.
func TestNextVersionSeesABreakingFooterBehindALargeRange(t *testing.T) {
	stdout, stderr := nextVersion(t, bulk(t, true))
	if stdout != wantVer {
		t.Errorf("derived %s, want %s: a BREAKING CHANGE footer behind a large range was missed\n%s",
			stdout, wantVer, stderr)
	}
	if !strings.Contains(stderr, "breaking:") {
		t.Errorf("the reasoning does not mention the footer, so the bump above may be right for the wrong reason:\n%s", stderr)
	}
}

// The control, and it is not optional. The case above passes if the script
// started answering "minor" to everything, which would be a worse defect wearing
// this test as a green light. The identical range without the footer must still
// come back patch.
func TestNextVersionWithoutAFooterIsStillAPatch(t *testing.T) {
	stdout, stderr := nextVersion(t, bulk(t, false))
	if stdout != "0.1.1" {
		t.Errorf("derived %s, want 0.1.1: a range of plain fixes should not move the minor\n%s", stdout, stderr)
	}
}
