// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Package perf is a measurement-only harness for Kessa's proxy decision path.
//
// It exists to SPEAK TO performance characteristics with real numbers, not to
// change behavior: nothing here is imported by a production binary, and the
// benchmarks call the same enforce.Proxy.Handle entry point the real proxy and
// mock agent drive. The ground rule is measure, don't optimize, if a benchmark
// finds a cliff, the deliverable is a written description plus a fix direction,
// never a fix. See perf/README.md for the findings.
//
// Everything below is synthetic load built from the SAME seed data the shipped
// demo uses: the real did:web documents under testdata/dids, the real
// commerce-security policy under examples/policies, and the alice -> acme ->
// worker -> helper delegation chain the demo mints. The one thing the harness
// reconstructs locally is the file-backed status resolver: the real proxy's
// status source re-reads a signed bitstring file from disk on every consequential
// request (cmd/proxy.fileStatus), and reproducing that "live re-read" is the
// whole point of Task B, so the harness must not shortcut it with an in-memory map.
package perf

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Paths are relative to this package directory (the CWD `go test` uses), matching
// the layout internal/enforce's own tests resolve against, one level up.
const (
	didsRoot    = "../testdata/dids"
	commercePol = "../examples/policies/commerce-security.json"
	acmeListURL = "https://localhost/orgs/acme/status.json"

	didAlice  = "did:web:localhost:people:alice"
	didAcme   = "did:web:localhost:orgs:acme"
	didWorker = "did:web:localhost:agents:worker"
	didHelper = "did:web:localhost:agents:helper"
	didProxy  = "did:web:localhost:proxies:gatekeeper"
)

// fixedTime keeps entry timestamps and action timestamps deterministic, mirroring
// the demo's --now. The status list uses a real revocation index of 42 on the
// worker hop, exactly as the issuer example and demo do.
var fixedTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// seeds are the fixed per-DID key seeds the demo/testdata were generated from, so
// a chain minted here verifies against the published did:web documents. These
// match internal/enforce's test constants (the source of the green fixtures).
var seeds = map[types.DID]byte{
	didAlice: 0x31, didAcme: 0x11, didWorker: 0x33, didHelper: 0x34, didProxy: 0x55,
}

func seed32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func signerFor(tb testing.TB, d types.DID) signer.Signer {
	tb.Helper()
	s, err := signer.NewSoftwareSignerFromSeed(d, seed32(seeds[d]))
	if err != nil {
		tb.Fatalf("signer %s: %v", d, err)
	}
	return s
}

// fileStatusResolver is a byte-for-byte reproduction of cmd/proxy.fileStatus: it
// re-reads (status.Load) the signed bitstring file from disk on EVERY lookup.
// Nothing is cached, that on-every-call disk read + signature verify is the
// "live status re-read" the whole harness is here to measure, so the benchmark
// must use this and not export.MapStatusResolver (which serves a pre-parsed list
// from memory and would hide exactly the cost under test).
type fileStatusResolver map[string]string // published URL -> local file path

func (f fileStatusResolver) ResolveStatus(listURL string) (*status.StatusList, error) {
	path, ok := f[listURL]
	if !ok {
		return nil, fmt.Errorf("perf: no status list configured for %q", listURL)
	}
	return status.Load(path)
}

// scenario is a fully-built, ready-to-drive proxy input set: the demo delegation
// chain, file-backed DID and status resolvers (real disk I/O, like the deployed
// proxy), and the loaded commerce policy.
type scenario struct {
	chain    *chain.Chain
	dids     did.Resolver
	statuses export.StatusResolver
	pol      *policy.Policy
	acme     signer.Signer
}

// newScenario mints the alice -> acme -> worker -> helper chain (amount<=100 at
// the worker hop, a StatusRef at index 42) and publishes a freshly-signed, floor
// -size (16 KiB) status list to a temp file the file resolver re-reads live.
func newScenario(tb testing.TB) *scenario {
	tb.Helper()
	s := &scenario{
		dids: did.FileResolver{Root: didsRoot},
		acme: signerFor(tb, didAcme),
	}

	base := macaroon.Mint(seed32(0x01), "cred-proxy-1", didAlice)
	mAcme := attenuate(tb, base, "action.type", macaroon.OpEq, "payment.transfer")
	mWorker := attenuate(tb, mAcme, "amount", macaroon.OpLe, "100")
	mHelper := attenuate(tb, mWorker, "target", macaroon.OpEq, "acct/999")

	s.chain = &chain.Chain{Links: []chain.Link{
		mkLink(tb, didAcme, didAlice, mAcme, status.Reference{}),
		mkLink(tb, didWorker, didAcme, mWorker, status.Reference{ListURL: acmeListURL, Index: 42}),
		mkLink(tb, didHelper, didWorker, mHelper, status.Reference{}),
	}}

	// Publish a signed status list to disk so the resolver performs a real live
	// re-read (file read + parse + Ed25519 verify) on every consequential request.
	path := filepath.Join(tb.TempDir(), "acme_status.json")
	writeSignedList(tb, s.acme, status.MinBits, path)
	s.statuses = fileStatusResolver{acmeListURL: path}

	pol, err := policy.Load(commercePol)
	if err != nil {
		tb.Fatalf("load policy: %v", err)
	}
	s.pol = pol
	return s
}

// writeSignedList allocates a zeroed status list of nbits, signs it with issuer,
// and saves it to path in the portable published form the resolver loads.
func writeSignedList(tb testing.TB, issuer signer.Signer, nbits int, path string) {
	tb.Helper()
	l := status.New(nbits)
	if err := l.Sign(issuer); err != nil {
		tb.Fatalf("sign status list: %v", err)
	}
	if err := status.Save(l, path); err != nil {
		tb.Fatalf("save status list: %v", err)
	}
}

func mkLink(tb testing.TB, subject, issuer types.DID, m macaroon.Macaroon, ref status.Reference) chain.Link {
	tb.Helper()
	holder := signerFor(tb, subject)
	c, err := credential.New(credential.Options{
		Subject: subject, Issuer: issuer, Macaroon: m, StatusRef: ref, HolderKey: holder.Public(),
	})
	if err != nil {
		tb.Fatalf("credential %s: %v", subject, err)
	}
	proof, err := chain.SignIssuance(signerFor(tb, issuer), c)
	if err != nil {
		tb.Fatalf("sign issuance %s: %v", subject, err)
	}
	return chain.Link{Credential: *c, IssuerProof: proof}
}

func attenuate(tb testing.TB, m macaroon.Macaroon, field string, op macaroon.Op, value string) macaroon.Macaroon {
	tb.Helper()
	out, err := macaroon.Attenuate(m, macaroon.Caveat{Field: field, Op: op, Value: value})
	if err != nil {
		tb.Fatalf("attenuate %s: %v", field, err)
	}
	return out
}

// newProxy builds a proxy over the scenario's resolvers with a fixed clock. Each
// proxy owns its own audit log, so callers that want independent (parallel-mode)
// engines just build one per goroutine.
func (s *scenario) newProxy(tb testing.TB) *enforce.Proxy {
	tb.Helper()
	px, err := enforce.NewProxy(enforce.Config{
		EnforcementPoint: signerFor(tb, didProxy),
		Policy:           s.pol,
		DIDs:             s.dids,
		Status:           s.statuses,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		tb.Fatalf("new proxy: %v", err)
	}
	return px
}

// ---- request builders ------------------------------------------------------
//
// Both bind their PoP (and, for consequential, the human approval) to seq, the
// slot the resulting entry will occupy (F4). A caller reads the proxy's live tip
// and passes it here so the request is a genuine, verifiable allow, the same
// discipline cmd/proxy.pending.build and the agent follow.

func routineAction() types.Action {
	// amount 10 is below the $100 high-value-transfer threshold -> routine allow,
	// so the consequential live-status + approval path is NOT taken.
	return types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "10"}, Timestamp: fixedTime}
}

func consequentialAction() types.Action {
	// amount 100 is exactly at the threshold -> consequential: live multi-hop
	// status check + human approval are required and exercised.
	return types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "100"}, Timestamp: fixedTime}
}

func (s *scenario) routineRequest(tb testing.TB, tip enforce.Tip) enforce.Request {
	tb.Helper()
	a := routineAction()
	return enforce.Request{Chain: s.chain, Action: a, PoP: s.pop(tb, tip, a)}
}

func (s *scenario) consequentialRequest(tb testing.TB, tip enforce.Tip) enforce.Request {
	tb.Helper()
	a := consequentialAction()
	return enforce.Request{
		Chain: s.chain, Action: a, PoP: s.pop(tb, tip, a),
		Approver: didAlice, Approval: s.approval(tb, tip, a),
	}
}

// pop and approval bind to a tip, Seq AND PrevHash (R2-04). Requests are
// therefore no longer portable across proxy instances or pre-buildable against a
// bare index: PrevHash is the previous entry's hash, so a valid request can only
// be built against the live log it is about to be submitted to. Callers read the
// tip immediately before building; see loadBench.
func (s *scenario) pop(tb testing.TB, tip enforce.Tip, a types.Action) credential.PoP {
	tb.Helper()
	terminal := &s.chain.Links[len(s.chain.Links)-1].Credential
	// A unique nonce per seq keeps every request distinct, as a real agent's would be.
	pop, err := terminal.ProvePossession(signerFor(tb, terminal.Subject), []byte(fmt.Sprintf("n-%d", tip.Seq)), a, tip.Seq, tip.PrevHash)
	if err != nil {
		tb.Fatalf("prove possession: %v", err)
	}
	return pop
}

func (s *scenario) approval(tb testing.TB, tip enforce.Tip, a types.Action) []byte {
	tb.Helper()
	terminal := &s.chain.Links[len(s.chain.Links)-1].Credential
	sig, err := audit.SignApproval(signerFor(tb, didAlice), terminal.Subject, a, tip.Seq, tip.PrevHash)
	if err != nil {
		tb.Fatalf("sign approval: %v", err)
	}
	return sig
}

// ---- percentile reporting --------------------------------------------------

// latencyStats summarizes a batch of per-operation latencies.
type latencyStats struct {
	n             int
	p50, p95, p99 time.Duration
	mean          time.Duration
}

func summarize(lat []time.Duration) latencyStats {
	if len(lat) == 0 {
		return latencyStats{}
	}
	sorted := make([]time.Duration, len(lat))
	copy(sorted, lat)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	return latencyStats{
		n:    len(sorted),
		p50:  pct(sorted, 0.50),
		p95:  pct(sorted, 0.95),
		p99:  pct(sorted, 0.99),
		mean: sum / time.Duration(len(sorted)),
	}
}

// pct returns the q-quantile of an already-sorted slice via nearest-rank.
func pct(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// reportLatency attaches p50/p95/p99 (in microseconds) as custom benchmark
// metrics so they surface in `go test -bench` output alongside ns/op.
func reportLatency(b *testing.B, s latencyStats) {
	b.ReportMetric(float64(s.p50.Nanoseconds())/1e3, "p50-us")
	b.ReportMetric(float64(s.p95.Nanoseconds())/1e3, "p95-us")
	b.ReportMetric(float64(s.p99.Nanoseconds())/1e3, "p99-us")
}
