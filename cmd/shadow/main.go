// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Command kessa-shadow is passive policy evaluation: it reports what a policy
// WOULD classify as consequential, without enforcing anything.
//
// It exists for one workflow: tune a policy before you turn on enforcement.
// Point it at a candidate policy file plus either real historical traffic (an
// audit export) or a handful of hand-written actions, and it tells you what that
// policy would gate.
//
// WHAT THIS TOOL IS NOT. It performs no enforcement of any kind: no
// proof-of-possession, no live revocation check, no human approval, no signed
// audit log. And when reading an export it does NOT verify it, no signature is
// checked, no DID is resolved, no hash chain is walked. The file is read at face
// value purely as a source of recorded actions. kessa-shadow is not a substitute
// for `kessa verify` and carries none of its guarantees; if you need to know
// whether an export is authentic, run the verifier.
//
// Its output is a stream of PREDICTIONS, which are not verdicts: unsigned,
// un-chained, and never accepted as input by the verifier.
//
// Exit codes: 0 = ran to completion, 2 = usage or I/O error (nothing classified).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/shadow"
	"github.com/Gneiss-Group/Kessa/internal/version"
)

const (
	exitOK    = 0
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if version.Requested(args) {
		fmt.Fprintln(stdout, version.Current().String("kessa-shadow"))
		return exitOK
	}

	fs := flag.NewFlagSet("kessa-shadow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
		fmt.Fprint(stderr, usageTail)
	}

	policyPath := fs.String("policy", "", "policy file to evaluate against (required)")
	exportPath := fs.String("export", "", "audit export to replay actions from; NOT verified, read at face value")
	actionsPath := fs.String("actions", "", "JSON-Lines file of actions, one per line")
	format := fs.String("format", "json", "output format: `json` (JSON-Lines, default) or text")
	outPath := fs.String("out", "", "write output to this file instead of stdout")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if *policyPath == "" {
		fmt.Fprintln(stderr, "kessa-shadow: -policy is required")
		return exitUsage
	}
	switch {
	case *exportPath == "" && *actionsPath == "":
		fmt.Fprintln(stderr, "kessa-shadow: exactly one of -export or -actions is required")
		return exitUsage
	case *exportPath != "" && *actionsPath != "":
		fmt.Fprintln(stderr, "kessa-shadow: -export and -actions are mutually exclusive; pass exactly one")
		return exitUsage
	}
	if *format != "json" && *format != "text" {
		fmt.Fprintf(stderr, "kessa-shadow: unknown -format %q (want json or text)\n", *format)
		return exitUsage
	}

	// Load the policy through the same path kessa-proxy uses, so shadow mode gets
	// identical validation and rejects exactly what the proxy would reject.
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
		return exitUsage
	}
	policyID, err := export.PolicyID(pol)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
		return exitUsage
	}

	var (
		inputs  []shadow.Input
		skipped []shadow.SkippedLine
	)
	if *exportPath != "" {
		data, err := os.ReadFile(*exportPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: read export: %v\n", err)
			return exitUsage
		}
		// A malformed export is fatal: unlike a hand-authored file it is not a
		// partial-content case.
		if inputs, err = shadow.FromExport(data, *exportPath); err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
			return exitUsage
		}
	} else {
		f, err := os.Open(*actionsPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: read actions: %v\n", err)
			return exitUsage
		}
		defer func() { _ = f.Close() }()
		if inputs, skipped, err = shadow.FromActions(f, *actionsPath); err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
			return exitUsage
		}
	}

	preds, err := shadow.PredictAll(pol, policyID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
		return exitUsage
	}

	// Malformed input lines are surfaced on stderr as they are reported, so they
	// are visible even when stdout is piped into another tool.
	for _, sk := range skipped {
		fmt.Fprintf(stderr, "kessa-shadow: %s:%d: skipped unparseable action: %v\n", *actionsPath, sk.Line, sk.Err)
	}
	if len(skipped) > 0 {
		fmt.Fprintf(stderr, "kessa-shadow: %d input line(s) skipped, %d classified\n", len(skipped), len(preds))
	}

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: create output: %v\n", err)
			return exitUsage
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if *format == "text" {
		if err := shadow.WriteText(out, preds, shadow.Summarize(preds, len(skipped)), skipped); err != nil {
			fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
			return exitUsage
		}
		return exitOK
	}
	if err := shadow.WriteJSONLines(out, preds); err != nil {
		fmt.Fprintf(stderr, "kessa-shadow: %v\n", err)
		return exitUsage
	}
	return exitOK
}

const usage = `kessa-shadow: passive policy evaluation (predictions only, nothing enforced)

  kessa-shadow -policy <file> -export  <file> [-format json|text] [-out <file>]
  kessa-shadow -policy <file> -actions <file> [-format json|text] [-out <file>]
  kessa-shadow --version

Classifies actions against a policy and reports what that policy WOULD gate.
Nothing is authorized, approved, or signed.

  -export   replay actions recorded in an audit export. The export is NOT
            verified: no signature is checked, no DID resolved, no hash chain
            walked. It is read at face value as a source of actions. This tool
            is NOT a substitute for ` + "`kessa verify`" + ` and carries none of its
            guarantees. Because the export also carries each entry's real
            recorded decision, this mode reports a predicted-vs-actual diff.

  -actions  read hand-written actions, one JSON object per line, matching the
            action shape used everywhere else. For a deployment that does not
            exist yet: write a few representative actions and see how a
            candidate policy classifies them.

Flags:
`

const usageTail = `
Output is JSON-Lines predictions by default. A prediction is not a verdict: it
is unsigned, un-chained, and is never accepted as input by the verifier.
`
