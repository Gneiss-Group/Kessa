// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package perf

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
)

// Task A, whole-path benchmarks of the real enforce.Proxy.Handle decision path.
//
// Two shapes:
//
//   - The sequential BenchmarkHandle_* give the PRECISE per-decision service time
//     (ns/op, allocs) for a routine vs a consequential request. Their difference
//     is the marginal cost of the consequential path, the live multi-hop status
//     re-read plus human-approval verify, measured directly, not inferred.
//   - BenchmarkProxyLoad sweeps concurrency (1..500) in two modes: `serialized`
//     drives one shared engine behind a mutex held across {read tip, sign, submit}
//     in production; `parallel` gives each goroutine its own engine (the
//     hypothetical ceiling if the log weren't serialized). The contrast quantifies
//     what the global lock costs. Both report throughput (req/s) and end-to-end
//     latency percentiles (p50/p95/p99), separately for routine and consequential.

// ---- precise per-decision service time -------------------------------------

func BenchmarkHandle_Routine(b *testing.B)       { benchHandle(b, false) }
func BenchmarkHandle_Consequential(b *testing.B) { benchHandle(b, true) }

// benchHandle times only px.Handle: the PoP/approval for each iteration is built
// with the timer stopped, because that signing is the AGENT's work, not the
// proxy's decision path. Each iteration binds to the proxy's live tip, so every
// request is a genuine, verifiable allow.
func benchHandle(b *testing.B, consequential bool) {
	s := newScenario(b)
	px := s.newProxy(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tip := px.Tip()
		var req enforce.Request
		if consequential {
			req = s.consequentialRequest(b, tip)
		} else {
			req = s.routineRequest(b, tip)
		}
		b.StartTimer()
		res, err := px.Handle(req)
		if err != nil {
			b.Fatalf("handle: %v", err)
		}
		if !res.Decision.Allowed || res.Decision.Consequential != consequential {
			b.Fatalf("unexpected decision: %+v", res.Decision)
		}
	}
}

// ---- concurrency sweep -----------------------------------------------------

var concurrencyLevels = []int{1, 10, 50, 100, 500}

func BenchmarkProxyLoad(b *testing.B) {
	for _, kind := range []string{"routine", "consequential"} {
		for _, mode := range []string{"serialized", "parallel"} {
			for _, c := range concurrencyLevels {
				b.Run(fmt.Sprintf("%s/%s/conc=%d", kind, mode, c), func(b *testing.B) {
					loadBench(b, mode, kind == "consequential", c)
				})
			}
		}
	}
}

// loadBench spreads b.N operations across `concurrency` goroutines and measures
// each operation's end-to-end latency (queue wait + decision), then reports
// throughput and percentiles.
//
// Requests can no longer be pre-built (R2-04). PoP and approval now bind to the
// entry's PrevHash as well as its Seq, so a request is only valid against the
// exact log state it is submitted to: there is no such thing as "a valid allow
// for seq=i on any engine" any more. Each request is therefore built from the
// live tip immediately before it is submitted, with the timer covering only
// Handle, the signing is the AGENT's work, as in benchHandle.
//
// Building inside the worker means the helpers' b.Fatalf could fire off the test
// goroutine, so the workers use buildReq, which reports through the same fail()
// channel the Handle errors use.
func loadBench(b *testing.B, mode string, consequential bool, concurrency int) {
	s := newScenario(b)

	per := b.N / concurrency
	if per < 1 {
		per = 1
	}
	total := per * concurrency

	// Build every proxy up front, in this goroutine (newProxy may call b.Fatalf).
	var shared *enforce.Proxy
	proxies := make([]*enforce.Proxy, concurrency)
	if mode == "serialized" {
		shared = s.newProxy(b)
	} else {
		for g := range proxies {
			proxies[g] = s.newProxy(b)
		}
	}

	latencies := make([][]time.Duration, concurrency)
	// serialized: makes {read tip, sign against it, submit} atomic for one shared
	// engine. Proxy has its own lock now (R2-04) and does not need this for
	// correctness, it needs it for MEASUREMENT validity. Without it two workers
	// bind evidence to the same slot, one of them is correctly denied, and the
	// benchmark would quietly be timing the deny path.
	var mu sync.Mutex
	var errMu sync.Mutex
	var firstErr error

	fail := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	// Resolve the signing keys on THIS goroutine: signerFor may call b.Fatalf.
	terminal := &s.chain.Links[len(s.chain.Links)-1].Credential
	actorKey := signerFor(b, terminal.Subject)
	approverKey := signerFor(b, didAlice)

	// buildReq is the worker-safe request builder: same evidence as the scenario
	// helpers, but errors are reported rather than fataled off the test goroutine.
	buildReq := func(px *enforce.Proxy) (enforce.Request, error) {
		tip := px.Tip()
		a := routineAction()
		if consequential {
			a = consequentialAction()
		}
		pop, err := terminal.ProvePossession(actorKey, []byte(fmt.Sprintf("n-%d", tip.Seq)), a, tip.Seq, tip.PrevHash)
		if err != nil {
			return enforce.Request{}, err
		}
		req := enforce.Request{Chain: s.chain, Action: a, PoP: pop}
		if consequential {
			sig, err := audit.SignApproval(approverKey, terminal.Subject, a, tip.Seq, tip.PrevHash)
			if err != nil {
				return enforce.Request{}, err
			}
			req.Approver, req.Approval = didAlice, sig
		}
		return req, nil
	}

	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			lat := make([]time.Duration, 0, per)
			for i := 0; i < per; i++ {
				if mode == "serialized" {
					t0 := time.Now()
					mu.Lock()
					req, err := buildReq(shared)
					if err == nil {
						_, err = shared.Handle(req)
					}
					mu.Unlock()
					lat = append(lat, time.Since(t0))
					if err != nil {
						fail(err)
						return
					}
				} else {
					req, err := buildReq(proxies[g])
					if err != nil {
						fail(err)
						return
					}
					t0 := time.Now()
					_, err = proxies[g].Handle(req)
					lat = append(lat, time.Since(t0))
					if err != nil {
						fail(err)
						return
					}
				}
			}
			latencies[g] = lat
		}(g)
	}
	wg.Wait()
	wall := time.Since(start)
	b.StopTimer()

	if firstErr != nil {
		b.Fatalf("handle: %v", firstErr)
	}

	all := make([]time.Duration, 0, total)
	for _, l := range latencies {
		all = append(all, l...)
	}
	b.ReportMetric(float64(total)/wall.Seconds(), "req/s")
	reportLatency(b, summarize(all))
	// ns/op from the framework is meaningless here (we manage our own timing), so
	// zero it out to avoid a misleading column.
	b.ReportMetric(0, "ns/op")
}
