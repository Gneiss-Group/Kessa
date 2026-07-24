// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
)

const (
	didsRoot     = "../../testdata/dids"
	v2Golden     = "../../testdata/audit_export_v2.golden.json"
	v1Golden     = "../../testdata/audit_export.golden.json"
	statusGolden = "../../testdata/status/acme_status.json"

	acmeListURL = "https://localhost/orgs/acme/status.json"

	idxWorkerLive    = 42
	idxWorkerRevoked = 43
)

// invoke runs the verifier in-process and returns (exitCode, stdout, stderr).
func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func statusArg() string { return acmeListURL + "=" + statusGolden }

// ---- color is presentation-only: off for non-terminals, on only when forced -
//
// The property that matters for a trust tool: color must never alter a byte a
// pipe, a golden, or the exit code depends on. It is therefore off whenever
// stdout is not a real terminal, which every test and pipe is.
func TestColor_OffForNonTTY_OnWhenForced(t *testing.T) {
	base := []string{"verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg()}
	with := func(extra string) (int, string, string) {
		return invoke(t, append(append([]string(nil), base...), extra)...)
	}

	// Default is --color=auto; invoke() sinks into a bytes.Buffer, which is not a
	// char device, so the output must be byte-plain.
	if _, out, _ := invoke(t, base...); strings.Contains(out, "\x1b[") {
		t.Fatalf("auto color must not emit ANSI to a non-terminal:\n%q", out)
	}

	// --color=always forces color even into a buffer, and the verdict text stays
	// findable as a plain substring (the color only wraps it).
	if _, out, _ := with("--color=always"); !strings.Contains(out, "\x1b[32m") || !strings.Contains(out, "PASS") {
		t.Fatalf("--color=always must emit green and keep PASS findable:\n%q", out)
	}
	if _, out, _ := with("--color=never"); strings.Contains(out, "\x1b[") {
		t.Fatalf("--color=never must be plain:\n%q", out)
	}
	if code, _, errb := with("--color=bogus"); code != exitUsage || !strings.Contains(errb, "invalid --color") {
		t.Fatalf("invalid --color must be a usage error, got code=%d err=%q", code, errb)
	}
}

// ---- §4 acceptance: a valid export verifies, offline -----------------------

// The issuer and proxy do not exist as processes here at all, nothing is
// started, nothing is dialled. That IS the "kill them first" acceptance test:
// the verifier's only inputs are files.
func TestAcceptance_ValidExportPasses(t *testing.T) {
	code, out, errb := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg())
	if code != exitPass {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errb)
	}
	if !strings.Contains(out, "VERDICT: PASS") {
		t.Fatalf("expected a PASS verdict:\n%s", out)
	}
	// Two allows verified, two denials with intact evidence.
	if !strings.Contains(out, "2 allow verified, 2 deny") {
		t.Fatalf("unexpected verdict tally:\n%s", out)
	}
	// The chain is reconstructed from evidence, in human-readable form.
	for _, want := range []string{
		"did:web:localhost:people:alice",
		"-> did:web:localhost:orgs:acme",
		"-> did:web:localhost:agents:worker",
		"-> did:web:localhost:agents:helper",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("chain reconstruction missing %q:\n%s", want, out)
		}
	}
	// The claim and its limits are stated, not hidden.
	if !strings.Contains(out, "What a PASS proves:") || !strings.Contains(out, "Known limits") {
		t.Fatalf("verifier must disclose what it proves and what it does not:\n%s", out)
	}
	if !strings.Contains(out, "CURRENT status list") {
		t.Fatalf("the S1 caveat must be surfaced in output:\n%s", out)
	}
}

// ---- §4 acceptance: one flipped byte fails at exactly that entry ------------

func TestAcceptance_TamperedExportFailsAtExactlyThatEntry(t *testing.T) {
	orig, err := os.ReadFile(v2Golden)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a single character inside entry 1's decision reason. Entry 0 precedes
	// it and must still verify; entries 2-3 follow a broken hash link.
	tampered := bytes.Replace(orig,
		[]byte("status live-checked; no hop revoked"),
		[]byte("status live-checked; no hop revokeD"), 1)
	if bytes.Equal(orig, tampered) {
		t.Fatal("tamper target not found in the golden export")
	}
	path := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, _ := invoke(t, "verify", "--export", path, "--dids", didsRoot, "--status", statusArg())
	if code != exitFail {
		t.Fatalf("tampered export must exit non-zero, got %d\n%s", code, out)
	}
	lines := entryLines(out)
	if len(lines) != 4 {
		t.Fatalf("expected 4 entry lines, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "PASS") || strings.Contains(lines[0], "FAIL") {
		t.Fatalf("entry 0 (before the tamper) must still pass: %q", lines[0])
	}
	if !strings.Contains(lines[1], "FAIL") {
		t.Fatalf("entry 1 (the tampered one) must fail: %q", lines[1])
	}
	for i := 2; i < 4; i++ {
		if !strings.Contains(lines[i], "UNVERIFIED") {
			t.Fatalf("entry %d follows a broken hash chain and must be UNVERIFIED: %q", i, lines[i])
		}
	}
}

// ---- §4 acceptance: revoked-then-used consequential action fails ------------

// This also demonstrates the deferred S1 caveat concretely: the export is
// unchanged and was legitimate when written, but a LATER revocation of the
// credential flips its previously-passing consequential entry to FAIL.
func TestAcceptance_RevokedThenUsedFailsThatEntry(t *testing.T) {
	// Publish a status list in which the worker credential entry 1 relied on is
	// now revoked (bit 42), alongside the already-revoked rotated one (bit 43).
	acme, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:orgs:acme", seed32(0x11))
	if err != nil {
		t.Fatal(err)
	}
	list := status.New(status.MinBits)
	for _, idx := range []int{idxWorkerLive, idxWorkerRevoked} {
		if err := list.Set(idx, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := list.Sign(acme); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "revoked_status.json")
	if err := status.Save(list, path); err != nil {
		t.Fatal(err)
	}

	code, out, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", acmeListURL+"="+path)
	if code != exitFail {
		t.Fatalf("a revoked-then-used consequential action must exit non-zero, got %d\n%s", code, out)
	}
	lines := entryLines(out)

	// Entry 1 was ALLOWED and consequential -> the revocation must fail it.
	if !strings.Contains(lines[1], "FAIL") || !strings.Contains(lines[1], "revoked") {
		t.Fatalf("entry 1 must fail on revocation: %q", lines[1])
	}
	// Entry 0 was allowed but NOT consequential, so no live status check is
	// required of it. This is the honest revocation-propagation boundary, not a
	// bug: routine actions ride a cached decision.
	if !strings.Contains(lines[0], "PASS") || strings.Contains(lines[0], "FAIL") {
		t.Fatalf("entry 0 (routine, non-consequential) should be unaffected: %q", lines[0])
	}
	// The denials remain fine, their evidence is intact.
	for i := 2; i < 4; i++ {
		if !strings.Contains(lines[i], "PASS/DENY") {
			t.Fatalf("entry %d should remain PASS/DENY: %q", i, lines[i])
		}
	}
}

// ---- v1 exports are reported as integrity-only, never a bare PASS ----------

func TestV1Export_DisclosesThatNoEvidenceIsCarried(t *testing.T) {
	code, out, _ := invoke(t, "verify", "--export", v1Golden, "--dids", didsRoot)
	// F2: a v1 (integrity-only) export must NOT exit 0 as a clean pass. Its
	// integrity still checks out, but presenting that as a clean PASS is exactly
	// the downgrade F2 closes, so the exit is non-zero and the verdict distinct.
	if code == exitPass {
		t.Fatalf("v1 export must not return a clean-pass exit; got %d\n%s", code, out)
	}
	if !strings.Contains(out, "evidence         NONE") && !strings.Contains(out, "evidence NONE") {
		t.Fatalf("v1 output must say plainly that no evidence is carried:\n%s", out)
	}
	if !strings.Contains(out, "CANNOT be re-derived") {
		t.Fatalf("v1 output must not imply authority was verified:\n%s", out)
	}
	if !strings.Contains(out, "DOWNGRADED") {
		t.Fatalf("v1 verdict must be a distinct downgrade, not a bare PASS:\n%s", out)
	}
}

// TestV1Export_QuietStillWarns is the F2 --quiet guarantee: even at the lowest
// verbosity, the integrity-only downgrade is surfaced, not masked.
func TestV1Export_QuietStillWarns(t *testing.T) {
	code, out, _ := invoke(t, "verify", "--export", v1Golden, "--dids", didsRoot, "--quiet")
	if code == exitPass {
		t.Fatalf("v1 --quiet must still exit non-zero; got %d\n%s", code, out)
	}
	if !strings.Contains(out, "evidence NONE") {
		t.Fatalf("--quiet must NOT hide the evidence-NONE security warning:\n%s", out)
	}
}

// ---- CLI hygiene -----------------------------------------------------------

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},                               // no subcommand
		{"frobnicate"},                   // unknown subcommand
		{"verify", "--dids", didsRoot},   // no --export
		{"verify", "--export", v2Golden}, // no --dids and no --fetch-dids
		{"verify", "--export", "/nope.json", "--dids", didsRoot}, // unreadable export
	}
	for _, args := range cases {
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Fatalf("args %v: exit = %d, want %d", args, code, exitUsage)
		}
	}
}

// A future v3 envelope must be refused outright, not verified on a best effort.
// The accepted set is exactly {v1 integrity-only, v2 evidence}; anything past v2
// is an unknown format and is refused at the door, not parsed on a guess.
func TestUnknownExportVersionRefused(t *testing.T) {
	for _, version := range []string{"kessa-audit-export/v3", "kessa-audit-export/v9"} {
		t.Run(version, func(t *testing.T) { assertVersionRefused(t, version) })
	}
}

func assertVersionRefused(t *testing.T, version string) {
	t.Helper()
	orig, err := os.ReadFile(v2Golden)
	if err != nil {
		t.Fatal(err)
	}
	relabeled := bytes.Replace(orig, []byte("kessa-audit-export/v2"), []byte(version), 1)
	path := filepath.Join(t.TempDir(), "relabeled.json")
	if err := os.WriteFile(path, relabeled, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := invoke(t, "verify", "--export", path, "--dids", didsRoot, "--status", statusArg())
	if code != exitUsage {
		t.Fatalf("unknown version: exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "unsupported export version") {
		t.Fatalf("stderr should name the problem: %q", errb)
	}
}

// A consequential allow whose status list was not supplied must FAIL loudly, not
// silently skip the revocation check.
func TestMissingStatusListFailsLoudly(t *testing.T) {
	code, out, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot)
	if code != exitFail {
		t.Fatalf("missing status list must fail verification, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "no status list was provided") {
		t.Fatalf("the reason must name the missing status list:\n%s", out)
	}
	if !strings.Contains(out, acmeListURL) {
		t.Fatalf("the reason must name WHICH status list is missing:\n%s", out)
	}
}

// ---- §4 acceptance: the verifier's dependency set is sacred ----------------

// `go build ./cmd/verify` must pull in no server packages, no enforcement
// engine, and no third-party modules.
//
// Note on internal/policy (F1): the verifier now DOES link internal/policy, and
// that is correct. To close the consequentiality-suppression bypass it must
// re-derive consequentiality from the policy carried as signed evidence in the
// export, which means running the same pure Option-B classifier the proxy used.
// internal/policy is a stdlib+types leaf, no enforcement, no server, no network,
// no OS beyond reading a file (which the verifier never asks it to do here). What
// stays forbidden is the enforcement engine (internal/enforce) and the server
// binaries; linking those WOULD blur the adversarial-verifier boundary.
func TestVerifierDependencySetIsClean(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")

	var forbidden []string
	for _, d := range deps {
		switch {
		case strings.Contains(d, "/internal/enforce"),
			strings.Contains(d, "/cmd/issuer"),
			strings.Contains(d, "/cmd/proxy"),
			strings.Contains(d, "/cmd/agent"):
			forbidden = append(forbidden, d)
		}
	}
	if len(forbidden) > 0 {
		t.Fatalf("verifier links packages it must not: %v", forbidden)
	}

	// And no third-party modules at all: everything is stdlib or ours.
	//
	// A module path is identified by its FIRST path element being a domain (it
	// contains a dot). That correctly treats stdlib internals such as
	// "crypto/internal/entropy/v1.0.0" as stdlib despite the version-like suffix,
	// and Go's own vendored deps ("vendor/golang.org/x/...") as stdlib too.
	for _, d := range deps {
		if strings.HasPrefix(d, "github.com/Gneiss-Group/Kessa") {
			continue
		}
		first, _, _ := strings.Cut(d, "/")
		if strings.Contains(first, ".") {
			t.Fatalf("verifier links a third-party dependency: %s", d)
		}
	}

	var sawExport bool
	for _, d := range deps {
		if strings.HasSuffix(d, "/internal/export") {
			sawExport = true
		}
	}
	if !sawExport {
		t.Fatal("expected the verifier to use internal/export for its verification logic")
	}
}

// ---- helpers ---------------------------------------------------------------

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

// entryLines extracts the per-entry report lines, in order.
// A per-entry line is "entry <seq> ...". The digit check matters: the prose in
// WhatIsProven and KnownCaveats is hard-wrapped, so a wrapped line can begin with
// the word "entry" and would otherwise be counted as a verdict.
func entryLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(l), "entry ")
		if ok && len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			lines = append(lines, l)
		}
	}
	return lines
}

// ---- round 2: R2-05, the trust root ------------------------------------------

// TestR2_05_TrustRootIsDisclosed. A fully fabricated export passes clean when the
// DID documents it names are fabricated to match. That is by design and settled;
// the finding was that nothing in the tool SAID so. The flag help called --dids
// "directory of published did:web documents", the package doc described DID
// documents as "public key material, not a service of ours" (a reassurance about
// us, read as a reassurance about the verdict), and the printed "Known limits"
// listed three caveats, none of which was the one that matters.
//
// The concrete failure mode this closes: an operator being audited hands the
// auditor export.json and a public/ directory, both from the same party, and
// `kessa verify` prints PASS with no mention that the second one is the anchor.
func TestR2_05_TrustRootIsDisclosed(t *testing.T) {
	code, out, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg())
	if code != exitPass {
		t.Fatalf("golden export should pass, got %d\n%s", code, out)
	}
	for _, want := range []string{"TRUST ROOT", didsRoot, "not\n              'genuine'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("verifier output must disclose its trust root (%q missing):\n%s", want, out)
		}
	}
	// And the long-form caveat is in the stated limits, not only the banner.
	if !strings.Contains(out, "RELATIVE TO THE DID DOCUMENTS YOU SUPPLIED") {
		t.Fatalf("the known limits must name the trust root:\n%s", out)
	}
}

// The banner prints under --quiet too. Same discipline as the F2 downgrade
// warning: a verbosity flag may drop cosmetic output, never a security notice,
// and this one conditions every other line of the verdict.
func TestR2_05_TrustRootIsDisclosedUnderQuiet(t *testing.T) {
	_, out, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg(), "--quiet")
	if !strings.Contains(out, "TRUST ROOT") {
		t.Fatalf("--quiet must not mask the trust-root disclosure:\n%s", out)
	}
}

// R2-01: a PASS that covers hops with no revocation list must say so per entry.
func TestR2_01_UnrevocableHopsAreStatedInOutput(t *testing.T) {
	_, out, _ := invoke(t, "verify", "--export", v2Golden, "--dids", didsRoot, "--status", statusArg())
	if !strings.Contains(out, "LIMIT: revocation NOT checkable") {
		t.Fatalf("a PASS covering unrevocable hops must state the limit per entry:\n%s", out)
	}
}

// ---- --version: identify the artifact without running it ---------------------

// The point of --version is that an evaluator can ask "what did I download?"
// before trusting it with anything: it must answer on stdout, exit 0, and reach
// none of the machinery — no export read, no DID resolved, no verdict printed.
func TestVersion_AnswersWithoutVerifying(t *testing.T) {
	for _, arg := range []string{"--version", "-version", "version"} {
		code, out, errb := invoke(t, arg)
		if code != exitPass {
			t.Fatalf("%s: exit = %d, want 0 (stderr: %s)", arg, code, errb)
		}
		if !strings.HasPrefix(out, "kessa ") || !strings.Contains(out, "commit ") {
			t.Fatalf("%s: unexpected version line: %q", arg, out)
		}
		if strings.Contains(out, "VERDICT") || strings.Contains(out, "TRUST ROOT") {
			t.Fatalf("%s: --version must not verify anything: %q", arg, out)
		}
	}
}
