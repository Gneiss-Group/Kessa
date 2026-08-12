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
	"net"
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
	"github.com/Gneiss-Group/Kessa/internal/signerd"
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

// buildProxy assembles the shared enforcement engine around an already-resolved
// enforcement-point signer (see keystoreSigner and brokeredSigner: where that key
// comes from is a separate decision from what the engine does with it). now, if
// non-nil, fixes the audit entry timestamp for deterministic runs. sink, if
// non-nil, forwards each audit entry to an external destination (see buildSink).
func buildProxy(policyPath, didsDir string, ep signer.Signer, statuses statusFlag, now func() time.Time, sink auditsink.AuditSink, wal *enforce.WAL, stderr io.Writer) (*enforce.Proxy, bool) {
	for name, v := range map[string]string{"policy": policyPath, "dids": didsDir} {
		if v == "" {
			fmt.Fprintf(stderr, "kessa-proxy: --%s is required\n", name)
			return nil, false
		}
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, false
	}
	statusResolver, err := statuses.resolver()
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, false
	}
	px, err := enforce.NewProxy(enforce.Config{
		EnforcementPoint: ep,
		Policy:           pol,
		DIDs:             did.FileResolver{Root: didsDir},
		Status:           statusResolver,
		Now:              now,
		Sink:             sink,
		WAL:              wal,
	})
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return nil, false
	}
	return px, true
}

// keystoreSigner materializes the enforcement point's signer from the MOCK
// keystore, and returns the keystore itself because batch mode needs it for a
// second, unrelated purpose (minting the fixture requests' proof-of-possession
// and approval signatures).
//
// This path holds the enforcement point's private key as a hex seed in a file the
// proxy reads, which internal/keystore's own package doc says not to copy into
// anything real. It stays because it is what makes `make demo` and the batch
// fixtures reproducible, not because it is a deployment story.
func keystoreSigner(ksPath, epDID string, stderr io.Writer) (signer.Signer, keystore.Keystore, bool) {
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
	return ep, ks, true
}

// brokeredSigner connects to a running signing daemon and returns a signer whose
// private key never enters this process: Sign round-trips over the socket. This
// is the path a deployment should use, and the reason the mock keystore is not a
// secrets story that a config file or a Terraform variable could fix.
//
// Two things gate the socket, both on the daemon's side: 0700 directory and 0600
// socket permissions, and a per-connection peer-uid check against the daemon's
// owner. The consequence for a deployment is that the proxy must run as the same
// uid as the daemon and share the socket's filesystem, which for containers means
// one uid and a shared volume, not two unrelated service accounts.
//
// Dial round-trips immediately to confirm the daemon holds this DID, so a missing
// daemon or a daemon holding the wrong key is a startup failure rather than a
// surprise at the first request.
func brokeredSigner(sockPath, epDID string, stderr io.Writer) (signer.Signer, bool) {
	ep, err := signerd.Dial(sockPath, types.DID(epDID))
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: enforcement point: %v\n", err)
		return nil, false
	}
	return ep, true
}

// enforcementPointSigner picks the one key source `serve` will use. Exactly one
// of --keystore and --signer-sock, never both and never neither: defaulting
// either way would pick a key custody model on the operator's behalf, and the two
// have materially different properties.
func enforcementPointSigner(ksPath, sockPath, epDID string, stderr io.Writer) (signer.Signer, bool) {
	if epDID == "" {
		fmt.Fprintln(stderr, "kessa-proxy: --enforcement-point is required")
		return nil, false
	}
	switch {
	case ksPath == "" && sockPath == "":
		fmt.Fprintln(stderr, "kessa-proxy: one of --keystore or --signer-sock is required: the enforcement point needs a signing key")
		return nil, false
	case ksPath != "" && sockPath != "":
		fmt.Fprintln(stderr, "kessa-proxy: --keystore and --signer-sock are mutually exclusive; name the one key source to use")
		return nil, false
	case sockPath != "":
		return brokeredSigner(sockPath, epDID, stderr)
	default:
		ep, _, ok := keystoreSigner(ksPath, epDID, stderr)
		return ep, ok
	}
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

// buildWAL opens the durable write-ahead audit log at path, or returns a nil WAL
// (durability disabled) when path is empty. Unlike the sink, this log is the
// system of record: each entry is fsynced before its decision is returned, and the
// log is recovered from this file at startup. The returned close func is nil when
// there is nothing to close.
func buildWAL(path string) (*enforce.WAL, func() error, error) {
	if path == "" {
		return nil, nil, nil
	}
	w, err := enforce.OpenWAL(path)
	if err != nil {
		return nil, nil, err
	}
	return w, w.Close, nil
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
	walPath := fs.String("audit-wal", "", "durable write-ahead audit log path; when set, every entry is fsynced before its decision returns (log-before-act, fail-closed) and the log is recovered from it on restart. \"\" disables durability")
	var statuses statusFlag
	fs.Var(&statuses, "status", "signed status list as url=file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *reqPath == "" {
		fmt.Fprintln(stderr, "kessa-proxy: --requests is required")
		return exitUsage
	}
	// Batch mode stays on the mock keystore, and deliberately gains no
	// --signer-sock. It needs the keystore regardless: loadRequests mints each
	// fixture's proof-of-possession and human approval from it, which is the agent's
	// and the human's key, not the enforcement point's. A brokered enforcement-point
	// key here would swap one of the three for a daemon and leave the other two as
	// seeds in a file, which buys nothing.
	if *epDID == "" {
		fmt.Fprintln(stderr, "kessa-proxy: --enforcement-point is required")
		return exitUsage
	}
	if *ksPath == "" {
		fmt.Fprintln(stderr, "kessa-proxy: --keystore is required")
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
	wal, closeWAL, err := buildWAL(*walPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	if closeWAL != nil {
		defer func() { _ = closeWAL() }()
	}
	ep, ks, ok := keystoreSigner(*ksPath, *epDID, stderr)
	if !ok {
		return exitUsage
	}
	px, ok := buildProxy(*policyPath, *didsDir, ep, statuses, now, sink, wal, stderr)
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

// isLoopbackAddr reports whether a listen address is loopback-only. An empty
// address means the listener is disabled and is trivially fine. A bare port or a
// wildcard host ("", "0.0.0.0", "::") binds every interface and is NOT loopback.
func isLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true // disabled
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false // unparseable: refuse rather than guess
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false // ":8181" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// anyListenerEnabled reports whether at least one address would bind something.
//
// Takes the same address slice refuseRemoteBind does, so the set of listener
// addresses is enumerated in exactly ONE place in cmdServe. A third listener
// shape added later is picked up by both checks from that one list, rather than
// by whoever remembers there are two of them.
func anyListenerEnabled(addrs []string) bool {
	for _, a := range addrs {
		if strings.TrimSpace(a) != "" {
			return true
		}
	}
	return false
}

// refuseRemoteBind decides whether the configured listen addresses may be used.
// It returns a message to print and whether to proceed: refusing carries an
// explanation, and proceeding under the escape hatch carries a warning, because
// an operator who opted in should still see it on every start.
func refuseRemoteBind(addrs []string, allow bool) (string, bool) {
	var remote []string
	for _, a := range addrs {
		if !isLoopbackAddr(a) {
			remote = append(remote, a)
		}
	}
	if len(remote) == 0 {
		return "", true
	}
	if allow {
		return fmt.Sprintf("kessa-proxy: WARNING: serving %s without caller authentication. "+
			"Anyone who can reach this address may submit requests; an export from this "+
			"deployment is enough to have entries refused-and-recorded against it. "+
			"See the README's Known limits.\n", strings.Join(remote, ", ")), true
	}
	return fmt.Sprintf("kessa-proxy: refusing to bind non-loopback address %s: the listeners have "+
		"no caller authentication.\n"+
		"  Bind 127.0.0.1 instead, or pass --allow-unauthenticated-remote if you accept that\n"+
		"  anyone who can reach this address may submit requests (containerized serving needs\n"+
		"  this, because a container's loopback is unreachable through -p).\n", strings.Join(remote, ", ")), false
}

// ---- serve: localhost HTTP shell -------------------------------------------

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "policy file (required)")
	didsDir := fs.String("dids", "", "directory of published did:web documents (required)")
	epDID := fs.String("enforcement-point", "", "DID of this enforcement point (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON holding this enforcement point's seed in the clear; evaluation only. Exactly one of --keystore or --signer-sock is required")
	sockPath := fs.String("signer-sock", "", "Unix socket of a running `kessa-issuer daemon` that brokers this enforcement point's key. The private key stays in the daemon and never enters this process; the proxy must run as the daemon's owner uid. Exactly one of --keystore or --signer-sock is required")
	httpAddr := fs.String("http-addr", "127.0.0.1:8181", "address for the generic HTTP listener; empty to disable it")
	mcpAddr := fs.String("mcp-addr", "127.0.0.1:8182", "address for the MCP-native (Streamable HTTP JSON-RPC) listener; empty to disable it")
	exportOut := fs.String("export", "", "if set, write the accumulated export here on shutdown")
	nowStr := fs.String("now", "", "fixed entry timestamp (RFC3339) for deterministic runs; default wall clock")
	auditLog := fs.String("audit-log", "audit-log.jsonl", "forward each audit entry to this local JSON-Lines file; \"-\" for stdout, \"\" to disable. Best-effort and lossy: a hung/slow sink drops records rather than stalling enforcement (bound sinkMaxInFlight=64; finding R2-03)")
	walPath := fs.String("audit-wal", "", "durable write-ahead audit log path; when set, every entry is fsynced before its decision returns (log-before-act, fail-closed) and the log is recovered from it on restart. \"\" disables durability")
	allowRemote := fs.Bool("allow-unauthenticated-remote", false, "permit binding a NON-LOOPBACK address. The listeners have no caller authentication, so this exposes the enforcement endpoint to anyone who can reach it. Required for containerized serving, where a container's loopback is unreachable through -p. It does not add authentication; it records that you accepted its absence")
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
	// Everything refusable is checked before anything is created. buildSink and
	// buildWAL both open (and create) files, so running them first meant a serve
	// that was going to be rejected for its bind address or its key source had
	// already left an audit-log file behind on the operator's disk. Validate, then
	// act, in that order.
	//
	// A non-loopback bind is refused unless the operator explicitly accepts what it
	// means. The listeners have no caller authentication, so binding a reachable
	// address publishes the enforcement endpoint to anyone who can route to it,
	// and while a request still cannot become an ALLOW without a valid proof of
	// possession, that is a different property from who may submit at all.
	//
	// This is a fail-closed default, not a fix: it removes the accidental version
	// of the exposure, and the property is unchanged (README, Known limits).
	// Containerized serving genuinely needs it, because a container's loopback is
	// unreachable through -p, which is why the escape hatch exists and is named
	// after what it costs rather than what it enables.
	listenAddrs := []string{*httpAddr, *mcpAddr}

	if msg, ok := refuseRemoteBind(listenAddrs, *allowRemote); !ok {
		fmt.Fprint(stderr, msg)
		return exitUsage
	} else if msg != "" {
		fmt.Fprint(stderr, msg)
	}

	// A proxy with every listener closed is refused rather than started.
	//
	// This used to print a note and exit 0, on the reasoning that a
	// security-conscious operator should be able to close a port without being
	// forced to commit to a protocol, and that both-closed was therefore
	// "legitimate, if inert". That reasoning held while both-closed required
	// intent: two addresses explicitly cleared on the command line.
	//
	// It stops holding once configuration can arrive from a file where an absent
	// field means off, because then both-closed is what an INCOMPLETE file
	// produces. The result was a chokepoint that enforced nothing and exited
	// successfully, which is indistinguishable from a healthy run by the only
	// signal an unattended deployment has. Closing one listener is still
	// supported and still the way to shed a protocol; closing the last one is not
	// a configuration, it is a mistake with a success exit code.
	if !anyListenerEnabled(listenAddrs) {
		fmt.Fprint(stderr, "kessa-proxy: refusing to start with no listeners enabled: "+
			"--http-addr and --mcp-addr are both empty, so nothing would reach the enforcement engine.\n"+
			"  Close one to shed a protocol; closing both leaves a chokepoint that enforces nothing.\n")
		return exitUsage
	}

	ep, ok := enforcementPointSigner(*ksPath, *sockPath, *epDID, stderr)
	if !ok {
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
	wal, closeWAL, err := buildWAL(*walPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		return exitUsage
	}
	if closeWAL != nil {
		defer func() { _ = closeWAL() }()
	}

	px, ok := buildProxy(*policyPath, *didsDir, ep, statuses, now, sink, wal, stderr)
	if !ok {
		return exitUsage
	}
	defer func() { _ = px.FlushSink(sinkFlushTimeout) }()

	// Two independently configurable front-end listeners, both funneling into the
	// SAME enforcement engine. The MCP-native listener is a thin protocol adapter
	// (enforce.MCPHandler calls the same px.Handle/px.Tip the HTTP handler does),
	// so an MCP host can point its server address straight at Kessa.
	// Each listener is enabled by having an address and disabled by clearing it: a
	// security-conscious operator closes a port they don't want rather than being
	// forced to commit to a protocol. Both enabled is the default (lowest deployment
	// bar: a chokepoint exists); both disabled is legitimate, if inert.
	listeners := enabledListeners([]listener{
		{name: "HTTP", addr: *httpAddr, handler: enforce.Handler(px), hints: []string{
			"POST /enforce   an enforce.Request; returns the decision",
			"GET  /tip       the next entry's slot, for binding PoP/approval",
			"GET  /export    the signed audit export so far",
		}},
		{name: "MCP-native (Streamable HTTP)", addr: *mcpAddr, handler: enforce.MCPHandler(px), hints: []string{
			"POST /          an MCP JSON-RPC message (ping, tools/list, tools/call)",
			"tools           kessa/tip, kessa/enforce",
			"revision        2026-07-28 (stateless: no sessions, no initialize)",
		}},
	})
	// An ASSERTION, not the gate. anyListenerEnabled already refused this case
	// above, before anything was created, and that is where the decision is made
	// and where an operator-facing explanation lives. This only fires if the two
	// ever disagree about what "enabled" means, which is why it says so rather
	// than repeating the advice: an operator reading it cannot act on it.
	if len(listeners) == 0 {
		fmt.Fprintln(stderr, "kessa-proxy: internal error: the address check passed but no listener survived filtering")
		return exitUsage
	}
	for _, l := range listeners {
		fmt.Fprintf(stdout, "kessa-proxy %s listener at http://%s\n", l.name, l.addr)
		for _, h := range l.hints {
			fmt.Fprintf(stdout, "  %s\n", h)
		}
	}

	if err := serveAll(listeners); err != nil {
		fmt.Fprintf(stderr, "kessa-proxy: %v\n", err)
		if *exportOut != "" {
			_ = writeExport(px, *exportOut)
		}
		return exitUsage
	}
	return exitOK
}

// ---- serve: dual-listener orchestration ------------------------------------

// listener is one configured front-end. addr is the bind address; an empty addr
// means the listener is disabled (see enabledListeners). handler turns that
// listener's wire format into the same Proxy calls the others make; hints are the
// endpoint lines printed under it at startup.
type listener struct {
	name    string
	addr    string
	handler http.Handler
	hints   []string
}

// enabledListeners keeps only the listeners with a non-empty address, preserving
// order. Clearing an address is how a listener is turned off: attack-surface
// minimization for an operator who wants a port closed, not a forced up-front
// protocol commitment.
//
// This function still returns zero listeners without complaint, deliberately, so
// it does not hardcode "at least one protocol" as an assumption a future listener
// shape could break. Refusing that case is cmdServe's job (anyListenerEnabled),
// where it happens before anything is created and where it can explain itself.
func enabledListeners(ls []listener) []listener {
	out := make([]listener, 0, len(ls))
	for _, l := range ls {
		if strings.TrimSpace(l.addr) != "" {
			out = append(out, l)
		}
	}
	return out
}

// Listener timeouts (R6-02). A zero-value http.Server, which is what
// http.ListenAndServe builds and what this file used, applies NO timeout of any
// kind: not to reading headers, not to reading a body, not to writing, not to an
// idle keep-alive. A request whose headers simply never end therefore parks a
// goroutine and a connection for as long as the client cares to hold them, at a
// cost to the attacker of one TCP connection each. Two hundred of them survived
// three minutes against this handler with no server-side close.
//
// The reason this is worth more than it looks: it sits IN FRONT OF the ingress
// guards rather than behind them. checkIngress never runs on a request that never
// completes, so the Origin and Content-Type work in ingress.go defends nothing
// here. And the container documentation requires --allow-unauthenticated-remote,
// because a container's loopback is unreachable through -p, so following our own
// deployment instructions puts this on a routable address.
const (
	// readHeaderTimeout is the one that closes the attack above: headers must
	// arrive complete within it or the connection is dropped.
	readHeaderTimeout = 10 * time.Second
	// readTimeout covers headers plus body. The body is separately capped at
	// enforce.maxRequestBody (1 MiB), so this bounds a slow trickle of a legal
	// body rather than a large one.
	readTimeout = 30 * time.Second
	// writeTimeout is deliberately generous rather than tight. GET /export
	// serializes the entire audit history, so its response grows with the log and
	// a tight bound would truncate a legitimate large export rather than refuse an
	// attack. Revisit when the export path is made incremental (R6-03, UPCOMING).
	writeTimeout = 120 * time.Second
	// idleTimeout bounds a kept-alive connection between requests, so a client
	// cannot hold connections open indefinitely by going quiet after one request.
	idleTimeout = 60 * time.Second
	// maxHeaderBytes is well under net/http's 1 MiB default. Nothing this
	// transport speaks needs large headers, and the default is per-connection
	// memory an attacker chooses to spend.
	maxHeaderBytes = 64 << 10
)

// newServer builds a listener's http.Server with the timeouts above. Every
// listener in this process is constructed here, so a new one cannot be added
// with the zero-value timeouts by forgetting to set them.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// serveAll starts every listener and blocks until the FIRST one returns. Each
// shares the one Proxy, which guards its own invariants, so serving several is
// safe. Fail-fast is deliberate: a chokepoint that was asked for two ports but
// silently got one is a misconfiguration the operator must see, so the first
// listener error (a bind failure, most often) stops the process rather than being
// logged and swallowed. Crash/redundancy hardening ACROSS listeners once they are
// up is separately scoped and explicitly deferred.
func serveAll(ls []listener) error {
	errc := make(chan error, len(ls))
	for _, l := range ls {
		go func(l listener) {
			errc <- fmt.Errorf("%s listener: %w", l.name, newServer(l.addr, l.handler).ListenAndServe())
		}(l)
	}
	return <-errc
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
