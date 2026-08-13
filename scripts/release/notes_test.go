// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// notes.sh renders the release notes and the CHANGELOG.md section from commit
// messages, which makes it the one part of the release pipeline whose output
// nobody diffs against a source of truth: the commits ARE the source of truth,
// so a transcription bug reads as history rather than as damage.
//
// That is how the breaking-change footers shipped truncated. The collector was a
// line-oriented `grep`, a wrapped footer contributed only its first line, and
// v0.0.1's CHANGELOG entry ended on a semicolon in the middle of a sentence.
// Nothing failed, and the truncated text was plausible enough to read as terse.
//
// So these tests assert on the END of a footer, never its beginning. An
// assertion that the first line is present passes against the broken version,
// which makes it a check that cannot fail for the reason it was written.

// gitEnv keeps the throwaway repositories independent of the developer's own git
// configuration. Identity is set because commit refuses without one, and signing
// is forced off because a machine with commit.gpgsign=true globally would
// otherwise need a key to run the test suite.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid",
	)
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// renderNotes builds a throwaway repository whose history is exactly the given
// commit messages, then runs the real notes.sh inside it.
//
// The script is COPIED into the temporary repository rather than invoked in
// place, because it resolves its own root as two directories up from itself and
// cd's there. Running the checked-out copy would render the notes of the real
// repository and quietly pass no matter what the fixtures said.
func renderNotes(t *testing.T, messages ...string) string {
	t.Helper()

	repo := t.TempDir()
	scripts := filepath.Join(repo, "scripts", "release")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("notes.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(scripts, "notes.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}

	git(t, repo, "init", "--quiet", "--initial-branch=main")
	for i, msg := range messages {
		// A distinct tracked file per commit: --allow-empty would work, but an
		// empty commit is not what a release range looks like.
		name := filepath.Join(repo, "file"+string(rune('a'+i)))
		if err := os.WriteFile(name, []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, repo, "add", ".")
		git(t, repo, "commit", "--quiet", "--no-gpg-sign", "-m", msg)
	}

	// No tags in the fixture repository, so notes.sh finds no previous release
	// and takes the whole history as the range.
	cmd := exec.Command("bash", script, "1.0.0")
	cmd.Dir = repo
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("notes.sh: %v\n%s", err, out)
	}
	return string(out)
}

// breakingSection returns just the "### Breaking changes" section, so an
// assertion about what is absent cannot be satisfied by a later section.
func breakingSection(t *testing.T, notes string) string {
	t.Helper()
	_, after, found := strings.Cut(notes, "### Breaking changes\n")
	if !found {
		t.Fatalf("no breaking-changes section in:\n%s", notes)
	}
	if next := strings.Index(after, "\n### "); next >= 0 {
		return after[:next]
	}
	return after
}

func TestNotesKeepsWholeMultiLineFooter(t *testing.T) {
	// Shaped like the real #59 footer: the consequence, which is the only part
	// asking the reader to do anything, is on the second line.
	notes := renderNotes(t, "feat(proxy)!: refuse to start with no listeners\n\n"+
		"Body text that is not part of the footer.\n\n"+
		"BREAKING CHANGE: `kessa-proxy serve` with both listener addresses\n"+
		"empty now exits 2 instead of 0. Any script relying on that as a\n"+
		"no-op start will fail.\n")

	got := breakingSection(t, notes)

	// The last sentence is the assertion. Checking for the first line would
	// pass against the truncating implementation this test exists to catch.
	if !strings.Contains(got, "no-op start will fail.") {
		t.Errorf("footer truncated: final line missing\n%s", got)
	}
	if !strings.Contains(got, "empty now exits 2 instead of 0") {
		t.Errorf("footer truncated: middle line missing\n%s", got)
	}
	// Rejoined onto one line, not emitted as three bullets. Counting bullets in
	// the whole section would be wrong: the `!:` subject contributes its own,
	// and that one is supposed to be there.
	var footerLines int
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		if strings.Contains(line, "listener addresses") {
			footerLines++
			if !strings.HasSuffix(line, "no-op start will fail.") {
				t.Errorf("footer bullet does not run to the end of the footer:\n%q", line)
			}
		}
	}
	if footerLines != 1 {
		t.Errorf("footer produced %d bullets, want 1\n%s", footerLines, got)
	}
}

func TestNotesStopsFooterAtTrailer(t *testing.T) {
	// v0.0.1's second footer is followed by a blank line and a Co-Authored-By
	// trailer. Reading a footer to the end of the message would transcribe an
	// address into the release notes.
	notes := renderNotes(t, "feat!: rename the listener flag\n\n"+
		"BREAKING CHANGE: the proxy serve --addr flag is renamed to\n"+
		"--http-addr. Update any deployment that passed --addr.\n\n"+
		"Co-Authored-By: Someone <someone@example.invalid>\n")

	got := breakingSection(t, notes)

	if !strings.Contains(got, "Update any deployment that passed --addr.") {
		t.Errorf("footer truncated before its last line\n%s", got)
	}
	if strings.Contains(got, "Co-Authored-By") || strings.Contains(got, "example.invalid") {
		t.Errorf("trailer leaked into the breaking-changes section\n%s", got)
	}
}

func TestNotesKeepsFootersFromDifferentCommitsApart(t *testing.T) {
	// Two footers, each running to the end of its own message. Without a
	// per-commit boundary the first would absorb the second commit's subject.
	notes := renderNotes(t,
		"feat!: first change\n\nBREAKING CHANGE: the first thing changed and\nhere is why it matters.\n",
		"feat!: second change\n\nBREAKING CHANGE: the second thing changed and\nhere is its own consequence.\n",
	)

	got := breakingSection(t, notes)

	if !strings.Contains(got, "here is why it matters.") {
		t.Errorf("first footer truncated\n%s", got)
	}
	if !strings.Contains(got, "here is its own consequence.") {
		t.Errorf("second footer truncated\n%s", got)
	}
	// The subjects belong to the `!:` bullets. A footer that ran past its own
	// commit would carry one into the footer bullet as well.
	if strings.Contains(got, "matters. feat") || strings.Contains(got, "matters. second") {
		t.Errorf("a footer absorbed the following commit\n%s", got)
	}
}

func TestNotesStillRendersSingleLineFooter(t *testing.T) {
	notes := renderNotes(t, "fix!: tighten the check\n\nBREAKING CHANGE: one line, no wrapping at all.\n")

	got := breakingSection(t, notes)

	if !strings.Contains(got, "- one line, no wrapping at all.") {
		t.Errorf("single-line footer lost or reshaped\n%s", got)
	}
}

func TestNotesOmitsBreakingSectionWhenNothingBreaks(t *testing.T) {
	// The section is conditional. A collector that emitted an empty bullet for
	// every commit would show up here rather than in the tests above.
	notes := renderNotes(t, "feat(proxy): add a flag\n\nJust an ordinary body.\n")

	if strings.Contains(notes, "### Breaking changes") {
		t.Errorf("breaking-changes section rendered with no breaking change\n%s", notes)
	}
}
