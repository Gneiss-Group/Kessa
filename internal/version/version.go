// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package version reports which build of Kessa you are holding.
//
// Every binary answers `--version` before it parses anything else, so the
// question "what is this artifact?" can be asked without running the artifact:
// no subcommand, no flags, no files touched, no network, exit 0.
//
// The version is a plain constant in this file, not a value injected at link
// time with `-ldflags -X`. That is deliberate. A verifier whose trust story is
// "read the source, then build it yourself" should not have its identity
// supplied by the build command: with a constant, the version a binary prints is
// the version its source said, and `go build ./cmd/verify` from a tag produces a
// binary indistinguishable from the released one. The release pipeline rewrites
// this constant in a commit, tags that commit, and refuses to tag if the two
// disagree (scripts/release/set-version.sh, .github/workflows/release.yml).
//
// The commit and dirty flag come from the toolchain's own VCS stamping, read
// back through runtime/debug. They are therefore build facts, not claims this
// package makes, and they are absent (rather than wrong) when the build had no
// VCS to stamp.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the released version of this module: semantic versioning, no
// leading "v" (the git tag adds it). It is the single source of truth for the
// version of every binary in this repository, they ship together, from one
// tree, at one version.
//
// Do not edit by hand outside a release: `make release-version V=x.y.z` and the
// release workflow own this line.
const Version = "0.1.0"

// Build is the identity of a compiled binary: the source's version plus what the
// toolchain stamped about the tree it was built from.
type Build struct {
	// Version is the Version constant above.
	Version string
	// Commit is the VCS revision the toolchain stamped, or "" if it stamped none
	// (`-buildvcs=false`, a build from outside a checkout, or a test binary).
	Commit string
	// Modified reports that the checkout had uncommitted changes at build time.
	// A true here means the binary does not correspond to any commit.
	Modified bool
	// Go is the toolchain that compiled the binary.
	Go string
}

// Current reads this binary's identity.
func Current() Build {
	b := Build{Version: Version, Go: runtime.Version()}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Commit = s.Value
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	return b
}

// String renders a build as the single line `--version` prints, e.g.
//
//	kessa 0.0.1 (commit 1a2b3c4, go1.26.3)
//
// An unstamped build says so rather than inventing a commit, and a build from a
// dirty tree is marked, because "which source is this?" has no honest answer
// when the answer is "some commit, plus edits".
func (b Build) String(binary string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s (commit ", binary, b.Version)
	switch {
	case b.Commit == "":
		sb.WriteString("unknown")
	default:
		sb.WriteString(shortCommit(b.Commit))
		if b.Modified {
			sb.WriteString("-dirty")
		}
	}
	fmt.Fprintf(&sb, ", %s)", b.Go)
	return sb.String()
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// Requested reports whether a command line is asking for the version and nothing
// else. Only the first argument counts: a bare `--version` is a question about
// the artifact, whereas `kessa verify --export --version` is a file named
// "--version" and must not be intercepted.
func Requested(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-version", "version":
		return true
	}
	return false
}
