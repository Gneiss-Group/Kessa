// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"regexp"
	"strings"
	"testing"
)

// semverRe is the semantic-versioning 2.0.0 pattern, minus the leading "v" the
// git tag carries.
var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-.]+)?(\+[0-9A-Za-z-.]+)?$`)

// TestVersion_IsSemver guards the constant the release pipeline rewrites. The
// tag, the release notes, and the artifact filenames are all derived from it, so
// a malformed value here is not cosmetic: it produces a release nothing can
// order against its predecessors.
func TestVersion_IsSemver(t *testing.T) {
	if !semverRe.MatchString(Version) {
		t.Fatalf("Version = %q, which is not semantic versioning (MAJOR.MINOR.PATCH, no leading v)", Version)
	}
	if strings.HasPrefix(Version, "v") {
		t.Fatalf("Version = %q: the leading v belongs to the git tag, not the constant", Version)
	}
}

func TestCurrent_ReportsTheConstantAndAToolchain(t *testing.T) {
	b := Current()
	if b.Version != Version {
		t.Fatalf("Current().Version = %q, want the constant %q", b.Version, Version)
	}
	// A test binary is built without VCS stamping, so Commit is legitimately
	// empty here; the toolchain is always known.
	if b.Go == "" {
		t.Fatal("Current().Go is empty; runtime.Version() always reports something")
	}
}

// TestString_NeverInventsACommit: an unstamped build must say "unknown" rather
// than print an empty or plausible-looking revision. "Which source is this?" is
// the whole point of the line.
func TestString_NeverInventsACommit(t *testing.T) {
	got := Build{Version: "1.2.3", Go: "go1.26.3"}.String("kessa")
	if want := "kessa 1.2.3 (commit unknown, go1.26.3)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestString_ShortensAndMarksDirty(t *testing.T) {
	full := "0123456789abcdef0123456789abcdef01234567"
	clean := Build{Version: "1.2.3", Commit: full, Go: "go1.26.3"}.String("kessa")
	if want := "kessa 1.2.3 (commit 0123456789ab, go1.26.3)"; clean != want {
		t.Fatalf("String() = %q, want %q", clean, want)
	}

	dirty := Build{Version: "1.2.3", Commit: full, Modified: true, Go: "go1.26.3"}.String("kessa")
	if !strings.Contains(dirty, "-dirty") {
		t.Fatalf("a build from a modified tree must say so: %q", dirty)
	}
}

func TestRequested(t *testing.T) {
	for _, args := range [][]string{
		{"--version"},
		{"-version"},
		{"version"},
		{"--version", "ignored"},
	} {
		if !Requested(args) {
			t.Errorf("Requested(%q) = false, want true", args)
		}
	}

	// Not a version request: no args, a real subcommand, or the word appearing
	// as a flag VALUE, where intercepting it would silently answer a different
	// question than the one asked.
	for _, args := range [][]string{
		nil,
		{},
		{"verify", "--export", "e.json"},
		{"verify", "--export", "--version"},
		{"attempt", "--type", "version"},
	} {
		if Requested(args) {
			t.Errorf("Requested(%q) = true, want false", args)
		}
	}
}
