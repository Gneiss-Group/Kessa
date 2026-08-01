// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Command kessa-agent is a MOCK agent that attempts actions through the
// enforcement proxy. It is not the trust path, there is no LLM here (spec §1),
// only the client end of the chokepoint: it holds a delegation credential and a
// key, constructs an action, proves possession, and submits.
//
// It talks to a running proxy over localhost HTTP (the mock transport), using
// the one wire protocol in internal/enforce. The same request-building path is
// exercised in-process by the scenario tests, so what you drive from the command
// line and what the tests assert are the same code.
//
// The --as flag is the point of scenario 5 (token loan): sign the proof of
// possession as some principal OTHER than the credential's bound holder, and the
// proxy denies, a copied credential blob is inert without the private key.
//
// Exit codes: 0 = allowed, 1 = denied or rejected, 2 = usage or I/O error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/keystore"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/internal/version"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	exitAllowed = 0
	exitDenied  = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// --version is answered before anything is attempted; it exits 0 as a
	// successful invocation, not as an allowed action.
	if version.Requested(args) {
		fmt.Fprintln(stdout, version.Current().String("kessa-agent"))
		return exitAllowed
	}
	if len(args) == 0 || args[0] != "attempt" {
		fmt.Fprint(stderr, "usage: kessa-agent attempt --proxy <url> --chain <file> --keystore <file> --type <t> --target <r> [--attr k=v]...\n")
		fmt.Fprint(stderr, "       kessa-agent --version\n")
		return exitUsage
	}
	return cmdAttempt(args[1:], stdout, stderr)
}

func cmdAttempt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attempt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proxyURL := fs.String("proxy", "http://127.0.0.1:8181", "base URL of a running kessa-proxy")
	chainPath := fs.String("chain", "", "delegation chain file (the credential this agent holds) (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON: DID -> hex seed (required unless --agent-sock is set)")
	agentSock := fs.String("agent-sock", "", "path to a running kessa-issuer daemon socket; fetch signing keys from it instead of a keystore")
	as := fs.String("as", "", "sign proof-of-possession as this DID (default: the chain's actor). Use a different DID to impersonate — it will be denied.")
	approver := fs.String("approver", "", "human DID to sign an approval (needed for consequential actions)")
	actionType := fs.String("type", "", "action type, e.g. payment.transfer (required)")
	target := fs.String("target", "", "action target, e.g. acct/999")
	nonce := fs.String("nonce", "agent-nonce-1", "proof-of-possession challenge nonce")
	tsStr := fs.String("timestamp", "2026-07-09T12:00:00Z", "action timestamp (RFC3339)")
	var attrs attrFlag
	fs.Var(&attrs, "attr", "action attribute as key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *chainPath == "" || *actionType == "" || (*ksPath == "" && *agentSock == "") {
		fmt.Fprintln(stderr, "kessa-agent: --chain, --type, and one of --keystore/--agent-sock are required")
		return exitUsage
	}
	ts, err := time.Parse(time.RFC3339, *tsStr)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-agent: bad --timestamp: %v\n", err)
		return exitUsage
	}

	ch, err := loadChain(*chainPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-agent: %v\n", err)
		return exitUsage
	}
	// signerFor resolves a DID to a signer either from the on-device daemon
	// (--agent-sock, the ssh-agent shape: the private key never leaves the daemon)
	// or from the mock keystore. The rest of the agent is identical either way —
	// both return a signer.Signer, which is the whole point of the seam.
	var ks keystore.Keystore
	if *agentSock == "" {
		ks, err = keystore.Load(*ksPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-agent: %v\n", err)
			return exitUsage
		}
	}
	signerFor := func(d types.DID) (signer.Signer, error) {
		if *agentSock != "" {
			return signerd.Dial(*agentSock, d)
		}
		return ks.Signer(d)
	}

	actorDID := types.DID(*as)
	if actorDID == "" {
		actorDID = ch.Actor() // the credential's bound holder
	}
	actor, err := signerFor(actorDID)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-agent: signer for %q: %v\n", actorDID, err)
		return exitUsage
	}
	var approverSigner signer.Signer
	if *approver != "" {
		approverSigner, err = signerFor(types.DID(*approver))
		if err != nil {
			fmt.Fprintf(stderr, "kessa-agent: approver %q: %v\n", *approver, err)
			return exitUsage
		}
	}

	action := types.Action{Type: *actionType, Target: *target, Attributes: attrs.m, Timestamp: ts}
	// Ask the proxy which chain slot our entry will occupy, so the proof of
	// possession and approval bind to that exact position (F4).
	tip, err := enforce.FetchTip(nil, *proxyURL)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-agent: %v\n", err)
		return exitUsage
	}
	req, err := buildRequest(ch, actor, approverSigner, action, *nonce, tip)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-agent: %v\n", err)
		return exitUsage
	}

	res, err := enforce.Submit(nil, *proxyURL, req)
	if err != nil {
		var rej *enforce.ErrRejected
		if errors.As(err, &rej) {
			fmt.Fprintf(stdout, "REJECTED  %s\n", rej.Reason)
			return exitDenied
		}
		fmt.Fprintf(stderr, "kessa-agent: %v\n", err)
		return exitUsage
	}

	if res.Decision.Allowed {
		fmt.Fprintf(stdout, "ALLOW  %s -> %s  (%s)\n", action.Type, action.Target, res.Decision.Reason)
		return exitAllowed
	}
	fmt.Fprintf(stdout, "DENY   %s -> %s  (%s)\n", action.Type, action.Target, res.Decision.Reason)
	return exitDenied
}

// buildRequest is the agent's core: from a held chain, the actor's key, an
// action, and (optionally) a human approver, produce the enforce.Request. It
// signs the proof of possession with the actor key and, if an approver is given,
// that human's approval over the action. The proxy independently re-verifies all
// of it, the agent asserts nothing the proxy trusts.
func buildRequest(ch *chain.Chain, actor signer.Signer, approver signer.Signer, action types.Action, nonce string, tip enforce.Tip) (enforce.Request, error) {
	if ch == nil || len(ch.Links) == 0 {
		return enforce.Request{}, fmt.Errorf("empty chain")
	}
	terminal := &ch.Links[len(ch.Links)-1].Credential
	pop, err := terminal.ProvePossession(actor, []byte(nonce), action, tip.Seq, tip.PrevHash)
	if err != nil {
		return enforce.Request{}, err
	}
	req := enforce.Request{Chain: ch, Action: action, PoP: pop}
	if approver != nil {
		// The approval binds the credential's bound holder (terminal.Subject),
		// not whoever signed the PoP (an impostor can't launder an approval) and
		// the entry position (Seq + PrevHash), so it authorizes exactly this one
		// entry in this one log (F4, R2-04).
		sig, err := audit.SignApproval(approver, terminal.Subject, action, tip.Seq, tip.PrevHash)
		if err != nil {
			return enforce.Request{}, err
		}
		req.Approver = approver.DID()
		req.Approval = sig
	}
	return req, nil
}

func loadChain(path string) (*chain.Chain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chain %q: %w", path, err)
	}
	return chain.Parse(data)
}

// attrFlag collects repeatable --attr key=value pairs.
type attrFlag struct{ m map[string]string }

func (a *attrFlag) String() string { return fmt.Sprint(a.m) }
func (a *attrFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("--attr %q must be key=value", v)
	}
	if a.m == nil {
		a.m = map[string]string{}
	}
	a.m[k] = val
	return nil
}
