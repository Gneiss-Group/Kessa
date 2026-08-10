// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Command kessa is the independent verifier: the component that proves Kessa's
// thesis. You point it at an audit export and it re-derives, from scratch, every
// verdict the enforcement point claimed to reach.
//
// Read this file with suspicion, that is what it is for. Here is everything it
// trusts:
//
//   - The export file you hand it. Nothing in it is believed; every claim is
//     recomputed from the evidence the file carries.
//   - Public did:web documents, read from a local directory by default. They are
//     public key material, not a service of ours. HTTPS fetching of those same
//     public documents is available but OFF unless you pass -fetch-dids.
//   - Published, issuer-signed status lists, likewise read from local files.
//
// That is the entire list. There is no Kessa server, no API key, no callback, no
// hidden default endpoint. Kill the issuer and the proxy and this still works.
//
// Read the second item again, though, because it is the one that can mislead
// (R2-05). "Not a service of ours" is a statement about US, and it is easy to
// read it as a reassurance when it is actually a transfer of responsibility. The
// -dids directory is this tool's TRUST ROOT. Every signature it checks is checked
// against a key it read from there, so a wholly fabricated export verifies clean
// if the DID documents it names were fabricated to match. The verdict means
// "internally consistent with these keys", never "genuine". If the export and the
// DID documents reached you from the same party, you have confirmed that party
// agrees with itself. The verifier says so unconditionally in its own output; see
// export.KnownCaveats.
//
// The verification logic lives in internal/export; this file is only a CLI, a
// reporter, and an exit code.
//
// Exit codes: 0 = every entry verified, 1 = at least one entry FAILED,
// 2 = usage or I/O error (nothing was verified).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/internal/version"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	exitPass  = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// --version answers "what is this artifact?" before anything else happens:
	// nothing is read, nothing is resolved, nothing is verified.
	if version.Requested(args) {
		fmt.Fprintln(stdout, version.Current().String("kessa"))
		return exitPass
	}
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintf(stderr, "usage: kessa verify --export <file> --dids <dir> [--status <url>=<file>]...\n")
		fmt.Fprintf(stderr, "       kessa --version\n")
		return exitUsage
	}

	fs := flag.NewFlagSet("kessa verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exportPath := fs.String("export", "", "path to the audit export file (required)")
	didsDir := fs.String("dids", "", "directory of published did:web documents: THIS IS THE TRUST ROOT: every signature is checked against a key from here, so a verdict is only as good as the directory's provenance (required unless -fetch-dids)")
	fetchDIDs := fs.Bool("fetch-dids", false, "resolve did:web documents over HTTPS instead of from -dids, making web PKI the trust root instead of the local directory; the only network access this tool can ever make, and it is off by default")
	didHosts := fs.String("did-hosts", "", "comma-separated did:web hosts this verification may contact (required with -fetch-dids): the export chooses the DIDs, so the deployment must choose the hosts")
	quiet := fs.Bool("quiet", false, "print only the final verdict")
	colorMode := fs.String("color", "auto", "colorize the PASS/FAIL outcomes: auto (only on a terminal), always, or never")
	var lists statusFlag
	fs.Var(&lists, "status", "signed status list as `url=file`, or a bare file used for any list URL (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}

	if *exportPath == "" {
		fmt.Fprintln(stderr, "kessa: --export is required")
		return exitUsage
	}
	if *didsDir == "" && !*fetchDIDs {
		fmt.Fprintln(stderr, "kessa: --dids is required (or pass --fetch-dids to resolve them over HTTPS)")
		return exitUsage
	}

	data, err := os.ReadFile(*exportPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa: read export: %v\n", err)
		return exitUsage
	}
	exp, err := export.Parse(data)
	if err != nil {
		fmt.Fprintf(stderr, "kessa: %v\n", err)
		return exitUsage
	}

	var resolver did.Resolver = did.FileResolver{Root: *didsDir}
	trustRoot := fmt.Sprintf("the directory %s", *didsDir)
	if *fetchDIDs {
		// Network resolution requires naming the hosts. Refusing rather than
		// warning, because the export being verified chooses the DIDs, so without
		// a list the artifact under audit would pick the trust root. An operator
		// who wants network resolution knows which hosts their org publishes;
		// the auditor handed a hostile export does not know they need protecting.
		hosts := splitHosts(*didHosts)
		if len(hosts) == 0 {
			fmt.Fprintln(stderr, "kessa: --fetch-dids requires --did-hosts: name the did:web hosts this verification may contact, comma separated")
			fmt.Fprintln(stderr, "       (the export chooses the DIDs, so it would otherwise choose the trust root)")
			return exitUsage
		}
		resolver = did.HTTPResolver{AllowedHosts: hosts}
		trustRoot = fmt.Sprintf("HTTPS fetches of %s (web PKI)", strings.Join(hosts, ", "))
	} else if *didHosts != "" {
		fmt.Fprintln(stderr, "kessa: --did-hosts only applies with --fetch-dids")
		return exitUsage
	}
	statusResolver, err := lists.resolver()
	if err != nil {
		fmt.Fprintf(stderr, "kessa: %v\n", err)
		return exitUsage
	}

	useColor, err := resolveColor(*colorMode, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "kessa: %v\n", err)
		return exitUsage
	}

	res, err := export.Verify(exp, export.Inputs{DIDs: resolver, Status: statusResolver})
	if err != nil {
		fmt.Fprintf(stderr, "kessa: %v\n", err)
		return exitUsage
	}

	report(stdout, *exportPath, trustRoot, exp, res, *quiet, useColor)
	if !res.Pass() {
		return exitFail
	}
	return exitPass
}

// ---- reporting -------------------------------------------------------------

func report(w io.Writer, path, trustRoot string, exp *export.Export, res *export.Result, quiet, color bool) {
	// Security-relevant warnings print REGARDLESS of --quiet (F2): a fatal
	// envelope failure, or an integrity-only downgrade, must never be masked by a
	// low verbosity flag. Quiet may drop cosmetic output, never a security notice.
	if res.FatalReason != "" {
		fmt.Fprintf(w, "  SECURITY: envelope rejected: %s\n", res.FatalReason)
	}
	if !res.EvidenceCarried {
		fmt.Fprintf(w, "  SECURITY: evidence NONE: this is a v1 export. Integrity can be checked; delegated\n")
		fmt.Fprintf(w, "            authority CANNOT be re-derived. This is NOT an evidence-backed pass.\n")
	}
	// R2-05. The trust root conditions the verdict itself, so it prints at the
	// same volume as the verdict, including under --quiet, alongside the other
	// notices a low verbosity flag must never mask.
	fmt.Fprintf(w, "  TRUST ROOT: keys came from %s. A PASS means 'consistent with those keys', not\n", trustRoot)
	fmt.Fprintf(w, "              'genuine'. Obtain them independently of whoever gave you the export.\n")

	if !quiet {
		fmt.Fprintf(w, "\nkessa: independent verifier\n\n")
		fmt.Fprintf(w, "  export           %s\n", path)
		fmt.Fprintf(w, "  format           %s\n", res.Version)
		fmt.Fprintf(w, "  enforcement pt   %s\n", exp.Signer)
		fmt.Fprintf(w, "  entries          %d\n", len(res.Entries))
		if res.EvidenceCarried {
			fmt.Fprintf(w, "  evidence         %d credentials embedded\n", len(exp.Credentials))
		} else {
			fmt.Fprintf(w, "  evidence         NONE: this is a v1 export.\n")
			fmt.Fprintf(w, "                   Integrity can be checked; delegated authority CANNOT be re-derived.\n")
		}
		fmt.Fprintln(w)

		for _, e := range res.Entries {
			// Pad the plain token to width FIRST, then colorize, so the ANSI bytes
			// never throw off the column alignment.
			tok := colorize(color, outcomeColor(e.Outcome), fmt.Sprintf("%-9s", shortOutcome(e.Outcome)))
			fmt.Fprintf(w, "  entry %-3d %s %s\n", e.Seq, tok, e.Reason)
			printChain(w, e.Chain)
			// A limitation is part of the verdict, not a footnote: it names what
			// this entry's PASS does not establish (R2-01).
			for _, lim := range e.Limitations {
				fmt.Fprintf(w, "            LIMIT: %s\n", lim)
			}
		}
		fmt.Fprintln(w)
	}

	var pass, deny, integrity, fail, unver int
	for _, e := range res.Entries {
		switch e.Outcome {
		case export.OutcomePass:
			pass++
		case export.OutcomePassDeny:
			deny++
		case export.OutcomeIntegrityOnly:
			integrity++
		case export.OutcomeFail:
			fail++
		case export.OutcomeUnverified:
			unver++
		}
	}

	verdict := "PASS"
	verdictColor := ansiGreen
	switch {
	case res.FatalReason != "":
		verdict, verdictColor = "FAIL (envelope rejected)", ansiRed
	case !res.EvidenceCarried:
		verdict, verdictColor = "DOWNGRADED (integrity-only, no evidence, not a clean pass)", ansiYellow
	case !res.Pass():
		verdict, verdictColor = "FAIL", ansiRed
	}
	fmt.Fprintf(w, "  VERDICT: %s  (%d allow verified, %d deny: evidence intact, %d integrity-only, %d failed, %d unverified)\n",
		colorize(color, verdictColor, verdict), pass, deny, integrity, fail, unver)

	if quiet {
		return
	}

	// State the claim exactly. Overstating it would be a lie, and this is trust
	// infrastructure.
	fmt.Fprintf(w, "\n  What a PASS proves:\n")
	fmt.Fprintf(w, "%s\n", wrapIndent(export.WhatIsProven, "    ", 78))
	fmt.Fprintf(w, "\n  Known limits of that claim:\n")
	for _, c := range export.KnownCaveats {
		fmt.Fprintf(w, "    - %s\n", strings.TrimSpace(wrapIndent(c, "      ", 78)))
	}
}

// ---- color -----------------------------------------------------------------
//
// The verifier links no third-party modules, so terminal detection is the
// stdlib char-device check, not an isatty dependency. Color is a presentation
// layer only: it never changes a byte the exit code or a pipe depends on, and
// it is off unless stdout is a real terminal (or --color=always is explicit).

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

func colorize(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

// outcomeColor: green for a re-derived verdict (a verified allow or a verified
// deny), red for a hard failure, yellow for anything the verifier could not
// stand behind (integrity-only, unverified).
func outcomeColor(o export.Outcome) string {
	switch o {
	case export.OutcomePass, export.OutcomePassDeny:
		return ansiGreen
	case export.OutcomeFail:
		return ansiRed
	default:
		return ansiYellow
	}
}

// resolveColor turns the --color mode into a decision. auto colorizes only when
// stdout is a character device and NO_COLOR is unset; always and never are
// explicit overrides. A buffer (as in tests) is never a char device, so tests
// and pipes stay plain without any special-casing.
func resolveColor(mode string, w io.Writer) (bool, error) {
	switch mode {
	case "never":
		return false, nil
	case "always":
		return true, nil
	case "auto":
		if os.Getenv("NO_COLOR") != "" {
			return false, nil
		}
		f, ok := w.(*os.File)
		if !ok {
			return false, nil
		}
		info, err := f.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0, nil
	default:
		return false, fmt.Errorf("invalid --color %q (want auto, always, or never)", mode)
	}
}

func shortOutcome(o export.Outcome) string {
	switch o {
	case export.OutcomePass:
		return "PASS"
	case export.OutcomePassDeny:
		return "PASS/DENY"
	case export.OutcomeIntegrityOnly:
		return "INTEGRITY"
	case export.OutcomeFail:
		return "FAIL"
	default:
		return "UNVERIFIED"
	}
}

// printChain renders the delegation chain the verifier reconstructed from the
// embedded evidence, not the chain the entry claimed.
func printChain(w io.Writer, chain []types.DID) {
	for i, p := range chain {
		if i == 0 {
			fmt.Fprintf(w, "            chain: %s\n", p)
			continue
		}
		fmt.Fprintf(w, "                -> %s\n", p)
	}
}

// wrapIndent hard-wraps s at width, prefixing every line with indent.
func wrapIndent(s, indent string, width int) string {
	var b strings.Builder
	line := indent
	for _, word := range strings.Fields(s) {
		if len(line)+len(word)+1 > width && line != indent {
			b.WriteString(line + "\n")
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += word
	}
	b.WriteString(line)
	return b.String()
}

// ---- --status flag ---------------------------------------------------------

// statusFlag collects repeatable --status arguments. Each is either "url=file"
// (bind a specific published list URL to a local file) or a bare "file" used as
// the fallback for any list URL, convenient for a single-issuer demo.
type statusFlag []string

func (s *statusFlag) String() string { return strings.Join(*s, ",") }

func (s *statusFlag) Set(v string) error {
	if v == "" {
		return errors.New("empty --status value")
	}
	*s = append(*s, v)
	return nil
}

// resolver loads every referenced status list from disk. Returns nil if none
// were supplied, an export that needs one will then fail loudly, per entry,
// rather than silently skipping the revocation check.
func (s *statusFlag) resolver() (export.StatusResolver, error) {
	if len(*s) == 0 {
		return nil, nil
	}
	r := &statusLists{byURL: make(map[string]*status.StatusList)}
	for _, spec := range *s {
		url, path, bound := strings.Cut(spec, "=")
		if !bound {
			list, err := status.Load(url) // the whole spec was a bare path
			if err != nil {
				return nil, fmt.Errorf("load status list %q: %w", url, err)
			}
			r.fallback = list
			continue
		}
		list, err := status.Load(path)
		if err != nil {
			return nil, fmt.Errorf("load status list %q: %w", path, err)
		}
		r.byURL[url] = list
	}
	return r, nil
}

type statusLists struct {
	byURL    map[string]*status.StatusList
	fallback *status.StatusList
}

func (r *statusLists) ResolveStatus(listURL string) (*status.StatusList, error) {
	if l, ok := r.byURL[listURL]; ok {
		return l, nil
	}
	if r.fallback != nil {
		return r.fallback, nil
	}
	return nil, fmt.Errorf("no status list supplied for %q (pass --status %s=<file>)", listURL, listURL)
}

// splitHosts parses the comma-separated -did-hosts value, dropping empty
// entries so a trailing comma or a stray space cannot silently produce an entry
// that matches nothing (or, worse, an empty host).
func splitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}
