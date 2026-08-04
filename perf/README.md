# Kessa: performance / concurrency findings

Measurement-only harness for the proxy decision path (`enforce.Proxy.Handle`).
**Ground rule: measure, don't optimize.** Where a benchmark finds a cliff, this
document describes it and names a fix direction, no fix is implemented.

All benchmarks drive the real `enforce.Proxy.Handle` entry point over real
file-backed resolvers (`did.FileResolver`, and a re-read-on-every-call status
resolver identical to `cmd/proxy.fileStatus`), seeded from the shipped demo data:
the `testdata/dids` did:web tree, `examples/policies/commerce-security.json`, and
the `alice → acme → worker → helper` delegation chain. No production code was
touched; `make demo` still passes.

### Environment

Apple M1 Max, 10 logical CPUs, `go 1.26.3`, darwin/arm64. Numbers are from one
machine and are meant for **relative** comparison (routine vs consequential,
serialized vs parallel, cost vs depth), not as absolute SLAs.

### Reproduce

```
# Per-decision service time, status micro-benchmarks, chain depth (stable):
go test ./perf/ -run '^$' -bench 'BenchmarkHandle_|BenchmarkStatus|BenchmarkChainVerify' -benchtime=2s -benchmem

# Concurrency sweep (fixed 3000 ops per level so each runs once):
go test ./perf/ -run '^$' -bench 'BenchmarkProxyLoad' -benchtime=3000x -benchmem
```

---

## Headline findings

1. **The live status re-read is a real, measured marginal cost, confirmed.**
   A consequential request costs **581 µs** vs **318 µs** for a routine one:
   **+263 µs (+83%)** of extra work, all of it in the consequential-only path
   (one live status re-read + human-approval verify). Throughput roughly halves:
   **~1,700 vs ~3,200 req/s**.

2. **The proxy has a hard concurrency ceiling, not a cliff, by design.**
   `enforce.Handler` serializes every request behind one global mutex (the
   hash-chained audit log and dedup set are not concurrency-safe). Throughput is
   therefore **flat from concurrency 1 to 500** (~3,200 req/s routine, ~1,700
   consequential); added concurrency buys *zero* throughput and only grows queue
   latency **linearly** (p50 routine: 299 µs → 160 ms from 1 → 500 clients).
   A per-goroutine (unlocked) engine reaches **~5.4× higher throughput**, so the
   global lock (not the crypto or I/O) is what caps a loaded proxy.

3. **The single biggest per-request cost is DID-document file I/O in
   `chain.Verify`, on *every* request**: routine or consequential. Verifying the
   3-hop demo chain is ~253 µs, ~80% of the 318 µs routine decision. The status
   re-read stacks a second block of file I/O on top for consequential requests.

4. **Chain-depth cost is linear and cheap** (~85 µs/hop); at `MaxDepth = 8` a full
   verify is 676 µs. Depth is not a scaling risk.

---

## Task A: whole-path decision cost

### Per-decision service time (sequential, the true single-thread ceiling)

| Request         | Service time | Allocs/op | Bytes/op |
|-----------------|-------------:|----------:|---------:|
| Routine         |      318 µs  |       322 |    26 KB |
| Consequential   |      581 µs  |       422 |   116 KB |
| **Marginal**    |  **+263 µs** |    **+100** | **+90 KB** |

The +263 µs is the consequential-only work: one live status re-read (~196 µs,
below) plus human-approval verification (~60 µs: resolve approver DID + Ed25519
verify) plus the extra ~90 KB is the re-read + parse of the 16 KiB bitstring.

### Concurrency sweep: serialized (real proxy) vs parallel (unlocked ceiling)

Throughput (req/s) and end-to-end latency percentiles, 3000 ops per level:

**Routine**

| Concurrency | Serialized req/s | Serialized p50 | Serialized p99 | Parallel req/s | Parallel p50 | Parallel p99 |
|------------:|-----------------:|---------------:|---------------:|---------------:|-------------:|-------------:|
| 1   | 3,244 |   299 µs |   465 µs | 3,267 |  299 µs |   446 µs |
| 10  | 3,157 |  3.14 ms |  3.65 ms | 13,194 | 637 µs |  2.03 ms |
| 50  | 3,139 |  15.9 ms |  16.7 ms | 14,680 | 617 µs |  42.1 ms |
| 100 | 3,120 |  32.0 ms |  33.9 ms | 15,326 | 529 µs |  99.7 ms |
| 500 | 3,108 |   160 ms |   162 ms | 16,750 | 462 µs |   149 ms |

**Consequential**

| Concurrency | Serialized req/s | Serialized p50 | Serialized p99 | Parallel req/s | Parallel p50 | Parallel p99 |
|------------:|-----------------:|---------------:|---------------:|---------------:|-------------:|-------------:|
| 1   | 1,746 |   554 µs |   826 µs | 1,734 |  559 µs |   827 µs |
| 10  | 1,704 |  5.82 ms |  6.34 ms | 6,594 | 1.41 ms |  3.19 ms |
| 50  | 1,693 |  29.5 ms |  31.0 ms | 7,408 | 1.59 ms |  52.6 ms |
| 100 | 1,693 |  59.0 ms |  60.1 ms | 8,193 | 1.31 ms |   111 ms |
| 500 | 1,687 |   295 ms |   298 ms | 9,061 | 1.16 ms |   279 ms |

**Reading this:** serialized throughput is flat, the mutex admits one decision
at a time, so `throughput = 1 / service_time` and p50 ≈ `concurrency ×
service_time` (textbook single-server queue). The parallel column is the *upper
bound* if the engine didn't serialize: throughput scales with cores to ~5.4× and
plateaus near the 10-core count, while p50 stays flat. (Parallel gives each
goroutine its own log, so it is a ceiling to size the opportunity, not a drop-in
design, and its p95/p99 balloon past ~50 goroutines because 500 threads doing
file I/O on 10 cores oversubscribe the machine. Any real fix should bound
concurrency, not remove it blindly.)

---

## Task B: live status re-read, in isolation

Per consequential request, `enforce.anyHopRevoked` re-reads and re-verifies the
signed bitstring for each hop with a `StatusRef` (one hop in the demo chain).
Decomposed at the real 16 KiB list size:

| Step                                   | Cost    | % of re-read | Allocs |
|----------------------------------------|--------:|-------------:|-------:|
| `status.Load` (disk read + JSON parse) | 123 µs  |   63%        |   18   |
| `StatusList.Verify` (Ed25519 / 16 KiB) |  58 µs  |   30%        |    1   |
| issuer DID resolve + `Lookup`          | ~15 µs  |    7%        |  ~38   |
| **Full live re-read**                  | **196 µs** | 100%      |   57   |
| in-memory `Lookup` (cached alt.)       | **2.6 ns** |, |    0   |

**Does list size matter?** No, in practice. `status.New` floors every list at
the herd-privacy minimum (131072 bits = 16 KiB) and the size is **fixed** there,
it does not grow with credential count or usage. The sweep below is only to show
*how* it would scale if an issuer published a larger list; the operating point is
and stays the 16 KiB row.

| List size     | Full re-read | Load only | Verify only |
|---------------|-------------:|----------:|------------:|
| 16 KiB (real) |      196 µs  |   123 µs  |     58 µs   |
| 32 KiB        |      316 µs  |   228 µs  |     70 µs   |
| 64 KiB        |      546 µs  |   433 µs  |     97 µs   |
| 128 KiB       |     1018 µs  |   848 µs  |    149 µs   |

Both the disk read and the signature verify scale linearly with size; the disk
read/parse dominates at every size.

---

## Task C: chain-depth cost

`chain.Verify` per depth (2 DID resolves + 1 Ed25519 verify + attenuation check
per hop):

| Depth | Verify | Allocs |
|------:|-------:|-------:|
| 1 |  83 µs |  77 |
| 2 | 168 µs | 156 |
| 3 | 253 µs | 235 |
| 4 | 337 µs | 314 |
| 5 | 419 µs | 393 |
| 6 | 505 µs | 472 |
| 7 | 584 µs | 551 |
| 8 | 676 µs | 630 |

**Linear**, ~85 µs/hop, no worse-than-linear behavior across the 1-8 range. The
`MaxDepth = 8` cap keeps a worst-case verify under 1 ms. Cost is dominated by the
two DID-document file reads per hop, the same file-I/O term that dominates
routine request cost above.

---

## The cliff, and the fix direction (NOT implemented)

There is **no sharp cliff at a concurrency level**: instead there is a **hard
throughput ceiling by construction**: the global mutex in `enforce.Handler` caps a
loaded proxy at its single-thread service rate (~1,700 req/s consequential),
regardless of client concurrency, and turns extra load into linearly growing
latency. Two cost centers set that single-thread rate:

- **The live status re-read (~196 µs)**: re-read + re-verified on every
  consequential request even when the list has not changed. An in-memory lookup
  is ~75,000× cheaper (2.6 ns).
- **DID-document file I/O in `chain.Verify` (~85 µs/hop)**: repeated on every
  request for the same handful of documents.

The fix direction already identified in the project's own notes is **caching the
status-list result with a freshness bound** (and the same idea applies to DID
documents): serve a parsed, already-verified list from memory within a short TTL,
re-reading only when the freshness bound expires. At the measured numbers that
would remove essentially all of the 196 µs status cost and the ~90 KB/op it
allocates, roughly doubling consequential throughput on the current serialized
engine, and would matter even more if the global lock were later relaxed.

**Both are left as separate, future tasks.** This harness only measures.

A related observation surfaced while building genuine concurrent load: PoP and
approval bind to the audit-log `seq` a request will occupy (F4), which a client
reads from `/tip` *before* submitting. Under real concurrency against the shared
log, two clients can read the same tip and one will land at a different `seq`,
failing its binding. It does not bite the sequential demo, and it is a
correctness/semantics note rather than a performance one, flagged here only
because it constrains how a future concurrent client must be written.
