// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Command reusecheck verifies that every tracked file states exactly one licence,
// and that the repository never states two.
//
// # Why this is not the `reuse` tool
//
// The FSFE's `reuse` is the reference implementation of the REUSE spec and it is
// a good tool. It is not used here because installing it means pulling eleven
// prebuilt Python wheels, and scripts/ci/secret-scan.sh already settled the
// question this repository asks about third-party tooling: gitleaks is pinned and
// BUILT FROM SOURCE rather than fetched as a binary, because "don't trust an
// artifact you did not build" is the product's whole thesis and CI is not exempt
// from it. A pip install in the gate would contradict the script next to it.
//
// The drift objection to reimplementing a spec does not apply, because this does
// not implement the spec. It checks a narrower property that is what the gate
// actually needs, and it is deliberately STRICTER than `reuse lint` in the place
// that matters:
//
//	reuse lint answers "does every file resolve to some licence?"
//	This answers   "does every file resolve to some licence, and do all of the
//	                repository's statements about that file agree?"
//
// `reuse lint` cannot answer the second. A blanket glob in REUSE.toml that
// contradicts a file's own inline header lints perfectly clean, because the
// header silently wins under REUSE's default precedence. docs/enrollment.md sat
// in exactly that state (inline AGPL-3.0-only, glob claiming Apache-2.0) and was
// found by hand, not by a check.
//
// Note what that buys, because it is the interesting part: this program does not
// model REUSE's precedence rules at all. It does not have to. Precedence only
// decides who wins when two statements disagree, and a disagreement is a failure
// here, so the case where precedence matters cannot exist in a green tree. A rule
// you enforce is cheaper than a rule you emulate.
//
// # What it checks
//
// Starting from the complete tracked set (git ls-files), never a curated list,
// per the coverage rule in docs/go-standards.md:
//
//  1. Every file resolves to a licence, by an inline SPDX header or a REUSE.toml
//     annotation. Licence texts themselves are the one exclusion, named below.
//  2. No file is given two different licences by two different statements.
//  3. Every licence used has its text in LICENSES/.
//  4. Every text in LICENSES/ is used by at least one file.
//  5. Every annotation path matches at least one tracked file, so the annotations
//     cannot rot into claims about files that no longer exist.
//
// Usage:  go run ./scripts/reusecheck [repo-root]
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// headerLines bounds how far into a file an SPDX header may sit.
//
// The bound is the point. An SPDX header is by definition at the top of a file,
// and scanning further makes any file that MENTIONS an identifier appear to
// declare one. That is not hypothetical: internal/licensing's test builds fixture
// files out of header constants, and scripts/license-check.sh greps for the tag
// by name. Both would reclassify themselves under an unbounded scan. A file that
// quotes what a scanner looks for must not read as declaring it.
const headerLines = 16

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	problems, summary, err := check(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reuse-check: %v\n", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Printf("\nreuse-check: FAILED (%d problem(s))\n", len(problems))
		os.Exit(1)
	}
	fmt.Print(summary)
}

// exemptFromLicensing is the checker's only exclusion, and it is enumerated here
// rather than implied by a glob elsewhere. A licence text does not itself need a
// licence; REUSE says so, and a self-referential requirement would be unmeetable.
func exemptFromLicensing(path string) bool {
	return path == "LICENSE" || strings.HasPrefix(path, "LICENSES/")
}

type annotation struct {
	paths     []string
	license   string
	copyright string
	block     int // 1-based, for error messages that point at the right block
}

type problem = string

func check(root string) ([]problem, string, error) {
	files, err := trackedFiles(root)
	if err != nil {
		return nil, "", err
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("git ls-files returned nothing in %s; not a repository?", root)
	}
	anns, err := parseREUSE(filepath.Join(root, "REUSE.toml"))
	if err != nil {
		return nil, "", err
	}
	available, err := availableLicenses(root)
	if err != nil {
		return nil, "", err
	}

	var problems []problem
	usedLicense := map[string]bool{}
	resolved := 0

	// Matched state is tracked per PATH, not per block. Per block, a dead path
	// sitting among live ones in the same annotation is invisible, because a
	// sibling keeps the block looking used. That is the stale-entry check
	// reporting OK while covering less than it claims, which is the failure this
	// file's coverage rule is about, so it gets the finer granularity.
	annMatched := make([][]bool, len(anns))
	for i := range anns {
		annMatched[i] = make([]bool, len(anns[i].paths))
	}

	for _, f := range files {
		if exemptFromLicensing(f) {
			continue
		}
		inline, err := inlineLicense(filepath.Join(root, f))
		if err != nil {
			return nil, "", fmt.Errorf("reading %s: %w", f, err)
		}

		// Collect every annotation that claims this file, not just the first.
		// Stopping at the first match would hide precisely the case this program
		// exists to catch: two statements about one file.
		var claims []string
		for i, a := range anns {
			hit := false
			// Every path is tested, with no early break, so each one's matched
			// state is recorded rather than only the first that happens to fire.
			for j, pat := range a.paths {
				ok, err := matchPath(pat, f)
				if err != nil {
					return nil, "", fmt.Errorf("REUSE.toml block %d: bad path %q: %w", a.block, pat, err)
				}
				if ok {
					annMatched[i][j] = true
					hit = true
				}
			}
			if hit {
				claims = append(claims, a.license)
			}
		}

		// Every distinct licence anyone claims for this file, inline or annotated.
		distinct := map[string]bool{}
		if inline != "" {
			distinct[inline] = true
		}
		for _, c := range claims {
			distinct[c] = true
		}

		switch {
		case len(distinct) == 0:
			problems = append(problems, fmt.Sprintf(
				"UNLICENSED: %s\n"+
					"  No SPDX header in its first %d lines and no REUSE.toml annotation covers it.\n"+
					"  Add a header, or annotate it in REUSE.toml if its format has no comments (JSON, images).",
				f, headerLines))
		case len(distinct) > 1:
			problems = append(problems, fmt.Sprintf(
				"CONTRADICTORY LICENCE: %s is given %s\n"+
					"  %s\n"+
					"  One file, one licence. REUSE would silently resolve this (the inline header\n"+
					"  wins over an annotation), which is why it has to fail here instead: a reader\n"+
					"  cannot tell which statement the project meant.",
				f, sortedList(distinct), describeSources(inline, claims)))
		default:
			lic := onlyKey(distinct)
			resolved++
			usedLicense[lic] = true
			if !available[lic] {
				problems = append(problems, fmt.Sprintf(
					"UNKNOWN LICENCE: %s declares %q, which has no text in LICENSES/.\n"+
						"  Either the identifier is wrong, or LICENSES/%s.txt is missing.",
					f, lic, lic))
			}
		}
	}

	for i, a := range anns {
		for j, pat := range a.paths {
			if !annMatched[i][j] {
				problems = append(problems, fmt.Sprintf(
					"STALE ANNOTATION: REUSE.toml block %d (%s) lists %q, which matches no tracked file.\n"+
						"  A path nobody matches is a claim about files that are gone, and it rots\n"+
						"  quietly: the block keeps working because its other paths still match.",
					a.block, a.license, pat))
			}
		}
	}

	for lic := range available {
		if !usedLicense[lic] {
			problems = append(problems, fmt.Sprintf(
				"UNUSED LICENCE TEXT: LICENSES/%s.txt is not used by any tracked file.\n"+
					"  Remove it, or find the file that was supposed to declare it.", lic))
		}
	}

	sort.Strings(problems)
	summary := fmt.Sprintf(
		"reuse-check: OK: %d tracked files, %d licensed (%d licence texts exempt);\n"+
			"             no file carries two licences; licences in use: %s\n",
		len(files), resolved, len(files)-resolved, strings.Join(sortedKeys(usedLicense), ", "))
	return problems, summary, nil
}

// trackedFiles is the complete tracked set. git is the authority rather than a
// filesystem walk so that ignored and untracked files cannot quietly enter or
// leave the checked set.
func trackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %w", root, err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return files, nil
}

func availableLicenses(root string) (map[string]bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, "LICENSES"))
	if err != nil {
		return nil, fmt.Errorf("reading LICENSES/: %w", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".txt") {
			out[strings.TrimSuffix(n, ".txt")] = true
		}
	}
	return out, nil
}

var spdxTag = regexp.MustCompile(`SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)`)

// inlineLicense reads a file's own SPDX header, if it has one.
//
// The tag counts only inside a comment, and only within the first headerLines
// lines. Both conditions matter. Without the comment rule, a TOML key or a Go
// string literal spelling the tag would read as a declaration; REUSE.toml's own
// `SPDX-License-Identifier = "..."` key is exactly that shape. Block comments are
// tracked because Markdown headers in this repository are written as bare lines
// inside an HTML comment, where the tag line carries no prefix of its own.
func inlineLicense(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inBlock := false
	for n := 0; n < headerLines && sc.Scan(); n++ {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		commented := inBlock ||
			strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "<!--") || strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, ";")

		if m := spdxTag.FindStringSubmatch(line); m != nil && commented {
			return m[1], nil
		}
		// Update block state after matching, so the line that opens a block can
		// also carry the tag.
		if strings.Contains(line, "<!--") && !strings.Contains(line, "-->") {
			inBlock = true
		}
		if strings.Contains(line, "/*") && !strings.Contains(line, "*/") {
			inBlock = true
		}
		if strings.Contains(line, "-->") || strings.Contains(line, "*/") {
			inBlock = false
		}
	}
	// A read error on a binary file is not a licensing problem; such files are
	// covered by annotations. Only surface real I/O failures.
	if err := sc.Err(); err != nil && !strings.Contains(err.Error(), "token too long") {
		return "", err
	}
	return "", nil
}

// matchPath implements REUSE's glob semantics: ** crosses directory separators,
// * does not, ? is one non-separator character.
func matchPath(pattern, path string) (bool, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false, err
	}
	return re.MatchString(path), nil
}

func sortedList(set map[string]bool) string { return strings.Join(sortedKeys(set), " and ") }

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func onlyKey(set map[string]bool) string { return sortedKeys(set)[0] }

func describeSources(inline string, claims []string) string {
	var parts []string
	if inline != "" {
		parts = append(parts, fmt.Sprintf("its own header says %s", inline))
	}
	seen := map[string]bool{}
	for _, c := range claims {
		if !seen[c] {
			seen[c] = true
			parts = append(parts, fmt.Sprintf("REUSE.toml says %s", c))
		}
	}
	return strings.Join(parts, "; ")
}
