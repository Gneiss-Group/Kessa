// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Command kessa-proxy is the enforcement chokepoint that sits in front of tool
// calls. Every consequential guarantee the independent verifier later re-derives
// is composed once, in internal/enforce, before any Allowed:true is written. A
// proxy that cuts a corner does not win, it produces an export `kessa verify`
// rejects.
//
// Two modes, one enforcement path underneath:
//
//   - run    batch: read a requests file, enforce each, write a signed export.
//   - serve  a localhost HTTP shell around the same enforcement engine, so an
//     agent in a SEPARATE process can attempt actions across a real
//     boundary. Transport is a mock (spec §1): plain JSON over HTTP, no
//     mTLS, no service mesh. The wire type is enforce.Request itself, so
//     there is nothing to keep in sync.
//
// Exit codes: 0 = ran, 2 = usage or I/O error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Gneiss-Group/Kessa/auditsink"
	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/keystore"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/internal/version"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	exitOK    = 0
	exitUsage = 2

	// sinkFlushTimeout bounds how long shutdown waits for asynchronous sink
	// writes to drain (R2-03). Bounded on purpose: a hung third-party sink must
	// not be able to hold the process open any more than it can hold up a
	// decision. Exceeding it means some records were dropped, which is what
	// best-effort means.
	sinkFlushTimeout = 2 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if version.Requested(args) {
		fmt.Fprintln(stdout, version.Current().String("kessa-proxy"))
		return exitOK
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, "usage: kessa-proxy <run|serve> [flags]\n")
		fmt.Fprint(stderr, "       kessa-proxy --version\n")
		return exitUsage
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "kessa-proxy: unknown command %q (want run or serve)\n", args[0])
		return exitUsage
	}
}

// buildProxy assembles the shared enforcement engine from CLI flags. now, if
// non-nil, fixes the audit entry timestamp for deterministic runs. sink, if
// non-nil, forwards each audit entry to an external destination (see buildSink).
func buildProxy(policyPath, didsDir, epDID, ksPath string, statuses statusFlag, now func() time.Time, sink auditsink.AuditSink, stderr io.Writer) (*enforce.Proxy, keystore.Keystore, bool) {
	for name, v := range map[string]string{"policy": policyPath, "dids": didsDir, "enforcement-point": epDID, "keystore": ksPath} {
		if v == "" {
			fmt.Fprintf(stderr, "kessa-proxy: --%s is required\n", name)
			return nil, nil, false
		}
	}
	ks, err := keystore.Load(ksPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, nil, false
	}
	ep, err := ks.Signer(types.DID(epDID))
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: enforcement point: %v\n", err)
		return nil, nil, false
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, nil, false
	}
	statusResolver, err := statuses.resolver()
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, nil, false
	}
	px, err := enforce.NewProxy(enforce.Config{
		EnforcementPoint: ep,
		Policy:           pol,
		DIDs:             did.FileResolver{Root: didsDir},
		Status:           statusResolver,
		Now:              now,
		Sink:             sink,
	})
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, nil, false
	}
	return px, ks, true
}

// buildSink turns the --audit-log flag into a sink and a closer. The flag
// selects the seam's one configured sink (multiple sinks are out of scope):
//
//	""    forwarding disabled (nil sink)
//	"-"   stdout-JSON sink
//	path  local-file JSON-Lines sink at path (the default)
//
// The returned close func is nil when there is nothing to close.
func buildSink(auditLog string) (auditsink.AuditSink, func() error, error) {
	switch auditLog {
	case "":
		return nil, nil, nil
	case "-":
		return auditsink.NewStdoutSink(), nil, nil
	default:
		fs, err := auditsink.NewFileSink(auditLog)
		if err != nil {
			return nil, nil, err
		}
		return fs, fs.Close, nil
	}
}

// parseNow turns an optional RFC3339 string into a fixed clock; empty means wall
// clock (nil, which the engine reads as time.Now).
func parseNow(s string) (func() time.Time, error) {
	if s == "" {
		return nil, nil
	}
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("bad --now: %w", err)
	}
	return func() time.Time { return ts.UTC() }, nil
}

// ---- run: batch enforcement ------------------------------------------------

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reqPath := fs.String("requests", "", "JSON file of action requests (required)")
	policyPath := fs.String("policy", "", "policy file (required)")
	didsDir := fs.String("dids", "", "directory of published did:web documents (required)")
	epDID := fs.String("enforcement-point", "", "DID of this enforcement point (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON (required)")
	out := fs.String("out", "export.json", "where to write the signed audit export")
	nowStr := fs.String("now", "", "fixed entry timestamp (RFC3339) for deterministic runs; default wall clock")
	auditLog := fs.String("audit-log", "audit-log.jsonl", "forward each audit entry to this local JSON-Lines file; \"-\" for stdout, \"\" to disable. Best-effort and lossy: a hung/slow sink drops records rather than stalling enforcement (bound sinkMaxInFlight=64; finding R2-03)")
	var statuses statusFlag
	fs.Var(&statuses, "status", "signed status list as url=file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *reqPath == "" {
		fmt.Fprintln(stderr, "kessa-proxy: --requests is required")
		return exitUsage
	}
	now, err := parseNow(*nowStr)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	sink, closeSink, err := buildSink(*auditLog)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	if closeSink != nil {
		defer func() { _ = closeSink() }()
	}
	px, ks, ok := buildProxy(*policyPath, *didsDir, *epDID, *ksPath, statuses, now, sink, stderr)
	if !ok {
		return exitUsage
	}
	// Sink dispatch is asynchronous and best-effort (R2-03), so drain it before
	// the process exits, otherwise a one-shot run loses records that were merely
	// in flight. The timeout is the point: a hung sink must not hold up shutdown
	// any more than it holds up enforcement.
	defer func() { _ = px.FlushSink(sinkFlushTimeout) }()
	pend, err := loadRequests(*reqPath, ks)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}

	for i, pd := range pend {
		// Bind this request's PoP and approval to the slot its entry will take,
		// which we read from the proxy's live tip just before enforcing (F4).
		req, err := pd.build(px.Tip())
		if err != nil {
			fmt.Fprintf(stdout, "req %d  REJECTED  %v\n", i, err)
			continue
		}
		res, err := px.Handle(req)
		if err != nil {
			fmt.Fprintf(stdout, "req %d  REJECTED  %v\n", i, err)
			continue
		}
		fmt.Fprintf(stdout, "req %d  %s  %s -> %s  (%s)\n", i, verb(res.Decision.Allowed), pd.action.Type, pd.action.Target, res.Decision.Reason)
	}

	if err := writeExport(px, *out); err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "\nwrote %s (%d entries)\n", *out, len(px.Entries()))
	fmt.Fprintf(stdout, "verify it:\n  kessa verify --export %s --dids %s%s\n", *out, *didsDir, statuses.verifyHint())
	return exitOK
}

// ---- serve: localhost HTTP shell -------------------------------------------

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "policy file (required)")
	didsDir := fs.String("dids", "", "directory of published did:web documents (required)")
	epDID := fs.String("enforcement-point", "", "DID of this enforcement point (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON (required)")
	addr := fs.String("addr", "127.0.0.1:8181", "listen address")
	exportOut := fs.String("export", "", "if set, write the accumulated export here on shutdown")
	nowStr := fs.String("now", "", "fixed entry timestamp (RFC3339) for deterministic runs; default wall clock")
	auditLog := fs.String("audit-log", "audit-log.jsonl", "forward each audit entry to this local JSON-Lines file; \"-\" for stdout, \"\" to disable. Best-effort and lossy: a hung/slow sink drops records rather than stalling enforcement (bound sinkMaxInFlight=64; finding R2-03)")
	var statuses statusFlag
	fs.Var(&statuses, "status", "signed status list as url=file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	now, err := parseNow(*nowStr)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	sink, closeSink, err := buildSink(*auditLog)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	if closeSink != nil {
		defer func() { _ = closeSink() }()
	}
	px, _, ok := buildProxy(*policyPath, *didsDir, *epDID, *ksPath, statuses, now, sink, stderr)
	if !ok {
		return exitUsage
	}
	defer func() { _ = px.FlushSink(sinkFlushTimeout) }()

	fmt.Fprintf(stdout, "kessa-proxy serving at http://%s\n", *addr)
	fmt.Fprintf(stdout, "  POST /enforce   an enforce.Request; returns the decision\n")
	fmt.Fprintf(stdout, "  GET  /export    the signed audit export so far\n")
	if err := http.ListenAndServe(*addr, enforce.Handler(px)); err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		if *exportOut != "" {
			_ = writeExport(px, *exportOut)
		}
		return exitUsage
	}
	return exitOK
}

// ---- shared helpers --------------------------------------------------------

func verb(allowed bool) string {
	if allowed {
		return "ALLOW"
	}
	return "DENY "
}

func writeExport(px *enforce.Proxy, path string) error {
	exp, err := px.Export()
	if err != nil {
		return fmt.Errorf("build export: %w", err)
	}
	data, err := exp.Marshal()
	if err != nil {
		return fmt.Errorf("marshal export: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	return nil
}

// ---- batch request file ----------------------------------------------------

// reqSpec is the on-disk form of a batch request. The delegation chain is loaded
// from a file; the actor's PoP and any human approval are produced from the MOCK
// keystore, standing in for what a real agent and human would sign out of band.
type reqSpec struct {
	ChainFile string       `json:"chainFile"`
	Action    types.Action `json:"action"`
	Nonce     string       `json:"nonce"`
	Approver  types.DID    `json:"approver,omitempty"`
}

// pending is a request whose action-independent parts are loaded up front, but
// whose PoP and approval are signed only once the proxy's entry position is
// known (F4). build turns it into an enforce.Request bound to that tip.
type pending struct {
	chain    *chain.Chain
	action   types.Action
	nonce    string
	holder   signer.Signer
	approver signer.Signer // nil when the request carries no approval
}

func (p pending) build(tip enforce.Tip) (enforce.Request, error) {
	terminal := &p.chain.Links[len(p.chain.Links)-1].Credential
	pop, err := terminal.ProvePossession(p.holder, []byte(p.nonce), p.action, tip.Seq, tip.PrevHash)
	if err != nil {
		return enforce.Request{}, err
	}
	req := enforce.Request{Chain: p.chain, Action: p.action, PoP: pop}
	if p.approver != nil {
		sig, err := audit.SignApproval(p.approver, terminal.Subject, p.action, tip.Seq, tip.PrevHash)
		if err != nil {
			return enforce.Request{}, err
		}
		req.Approver = p.approver.DID()
		req.Approval = sig
	}
	return req, nil
}

func loadRequests(path string, ks keystore.Keystore) ([]pending, error) {
	var specs []reqSpec
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read requests %q: %w", path, err)
	}
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse requests %q: %w", path, err)
	}
	out := make([]pending, 0, len(specs))
	for i, s := range specs {
		data, err := os.ReadFile(s.ChainFile)
		if err != nil {
			return nil, fmt.Errorf("request %d: read chain %q: %w", i, s.ChainFile, err)
		}
		ch, err := chain.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i, err)
		}
		terminal := &ch.Links[len(ch.Links)-1].Credential

		holder, err := ks.Signer(terminal.Subject)
		if err != nil {
			return nil, fmt.Errorf("request %d: actor key: %w", i, err)
		}
		pd := pending{chain: ch, action: s.Action, nonce: s.Nonce, holder: holder}
		if s.Approver != "" {
			human, err := ks.Signer(s.Approver)
			if err != nil {
				return nil, fmt.Errorf("request %d: approver key: %w", i, err)
			}
			pd.approver = human
		}
		out = append(out, pd)
	}
	return out, nil
}

// ---- --status flag ---------------------------------------------------------

type statusFlag []string

func (s *statusFlag) String() string { return strings.Join(*s, ",") }
func (s *statusFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func (s *statusFlag) resolver() (export.StatusResolver, error) {
	if len(*s) == 0 {
		return nil, nil
	}
	fs := fileStatus{}
	for _, spec := range *s {
		url, path, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("--status %q must be url=file", spec)
		}
		if _, err := status.Load(path); err != nil { // validate once at startup
			return nil, fmt.Errorf("load status %q: %w", path, err)
		}
		fs[url] = path
	}
	return fs, nil
}

// fileStatus resolves a published status list from a file, re-reading it on
// EVERY lookup. That is what makes a consequential action's status check "live":
// if the issuer revokes a credential (by rewriting the signed list) while the
// proxy is running, the very next consequential request sees it. Nothing is
// cached, nothing is notified, propagation is just the filesystem.
type fileStatus map[string]string // published URL -> local file path

func (f fileStatus) ResolveStatus(listURL string) (*status.StatusList, error) {
	path, ok := f[listURL]
	if !ok {
		return nil, fmt.Errorf("no status list configured for %q", listURL)
	}
	return status.Load(path)
}

func (s *statusFlag) verifyHint() string {
	out := ""
	for _, spec := range *s {
		out += " --status \"" + spec + "\""
	}
	return out
}
