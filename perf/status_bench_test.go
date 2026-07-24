// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package perf

import (
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/status"
)

// Task B, the live status re-read in isolation.
//
// On every CONSEQUENTIAL request the proxy runs enforce.anyHopRevoked, which for
// each hop carrying a StatusRef performs four steps against a freshly re-read,
// issuer-signed bitstring:
//
//	status.Load(path): read + JSON-parse the published list from disk
//	did.ResolveKey(issuer): read + parse the issuer's DID document
//	list.Verify(issuerKey): Ed25519 verify over the ENTIRE bitstring (>=16 KiB)
//	list.Lookup(index): O(1) bit test
//
// Nothing is cached between requests. These benchmarks measure the whole re-read
// and each component separately, and sweep the bitstring size, so the dominant
// term is visible rather than inferred from Task A's aggregate.
//
// Is the list size a real variable? The published list is fixed at the
// herd-privacy floor: status.New rounds anything below MinBits (131072 bits = 16
// KiB) up to it, and the demo/testdata list sits exactly at the floor. It does
// NOT grow with the number of credentials or with usage, one 16 KiB list covers
// 131072 credentials by design. So 16 KiB is the realistic operating point; the
// larger sizes below exist only to show HOW the cost scales if an issuer ever
// published a bigger list.

// listSizes are bitstring sizes to sweep: the real floor plus multiples, to
// expose the scaling of the signature verify (the only size-dependent step).
var listSizes = []struct {
	name string
	bits int
}{
	{"16KiB_floor", status.MinBits}, // the real, shipped size
	{"32KiB", status.MinBits * 2},
	{"64KiB", status.MinBits * 4},
	{"128KiB", status.MinBits * 8},
}

// BenchmarkStatusReRead_Full is the whole per-request, per-hop live check exactly
// as anyHopRevoked performs it: disk re-read + parse + issuer-key resolve +
// full-bitstring signature verify + bit lookup. This is the number that shows up
// as the consequential path's marginal cost in Task A.
func BenchmarkStatusReRead_Full(b *testing.B) {
	s := newScenario(b)
	dids := did.FileResolver{Root: didsRoot}
	for _, sz := range listSizes {
		path := filepath.Join(b.TempDir(), "status.json")
		writeSignedList(b, s.acme, sz.bits, path)
		res := fileStatusResolver{acmeListURL: path}
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				list, err := res.ResolveStatus(acmeListURL)
				if err != nil {
					b.Fatalf("resolve: %v", err)
				}
				key, err := did.ResolveKey(dids, list.Issuer)
				if err != nil {
					b.Fatalf("resolve issuer key: %v", err)
				}
				if err := list.Verify(key); err != nil {
					b.Fatalf("verify: %v", err)
				}
				if _, err := list.Lookup(42); err != nil {
					b.Fatalf("lookup: %v", err)
				}
			}
		})
	}
}

// BenchmarkStatusReRead_LoadOnly isolates the disk read + JSON parse of the
// published list (status.Load), with no signature verify, the I/O half of the
// re-read.
func BenchmarkStatusReRead_LoadOnly(b *testing.B) {
	s := newScenario(b)
	for _, sz := range listSizes {
		path := filepath.Join(b.TempDir(), "status.json")
		writeSignedList(b, s.acme, sz.bits, path)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := status.Load(path); err != nil {
					b.Fatalf("load: %v", err)
				}
			}
		})
	}
}

// BenchmarkStatusReRead_VerifyOnly isolates the Ed25519 signature verify over the
// bitstring, on an already-parsed in-memory list, the crypto half of the
// re-read, and the only step whose cost scales with list size.
func BenchmarkStatusReRead_VerifyOnly(b *testing.B) {
	s := newScenario(b)
	dids := did.FileResolver{Root: didsRoot}
	key, err := did.ResolveKey(dids, didAcme)
	if err != nil {
		b.Fatalf("resolve issuer key: %v", err)
	}
	for _, sz := range listSizes {
		path := filepath.Join(b.TempDir(), "status.json")
		writeSignedList(b, s.acme, sz.bits, path)
		list, err := status.Load(path)
		if err != nil {
			b.Fatalf("load: %v", err)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := list.Verify(key); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

// staticVsLive documents the alternative that Task B's finding points at WITHOUT
// implementing it: an in-memory (already-parsed, already-verified) lookup is what
// a freshness-bounded cache would collapse the per-request cost to. Measuring it
// here quantifies the headroom a cache would recover; it changes no production code.
func BenchmarkStatusLookup_InMemory(b *testing.B) {
	l := status.New(status.MinBits)
	if err := l.Sign(newScenario(b).acme); err != nil {
		b.Fatalf("sign: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Lookup(42); err != nil {
			b.Fatalf("lookup: %v", err)
		}
	}
}
