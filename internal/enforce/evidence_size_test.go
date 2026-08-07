// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/policy"
)

// proxyWithWAL builds a harness proxy backed by a durable log, so a test can
// assert what did (and did not) reach stable storage.
func (h *harness) proxyWithWAL(t *testing.T, wal *WAL) *Proxy {
	t.Helper()
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{
		EnforcementPoint: sign(t, didProxy),
		Policy:           pol,
		DIDs:             h.resolver,
		Status:           h.statuses,
		Now:              func() time.Time { return fixedTime },
		WAL:              wal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return px
}

// R6-04. Caller-supplied evidence (the PoP nonce, the PoP signature, the human
// approval) is recorded verbatim into the sealed entry, so it must be bounded
// BEFORE anything is sealed, persisted or appended, not merely rejected somewhere
// downstream.
//
// These tests assert WHEN the gate fires, not just that it fires: after each
// refusal the log must be exactly as it was, because the whole failure mode this
// closes is attacker-chosen bytes reaching durable, permanently-retained state.

// oversizedCases are the three fields and the value that must be refused. Each
// is one byte over its own limit, so the test pins the boundary rather than
// merely proving that something enormous is rejected.
//
// The nonce case is signed HONESTLY over the oversized nonce, which is the whole
// point: the nonce is inside popInput, so an oversized one verifies perfectly and
// every downstream gate lets it through. Building it the lazy way (overwrite
// .Nonce on an already-signed PoP) makes the proof invalid, and then the
// possession gate refuses the request for an unrelated reason: the test still goes
// red when the cap is removed, but for the wrong reason, and it would keep passing
// if the cap were replaced with something that does not work. Confirmed by
// mutation: with the cap removed, this case appends an entry carrying the
// oversized nonce.
func oversizedCases(t *testing.T, h *harness) []struct {
	name string
	req  Request
	want string
} {
	t.Helper()
	a := action("10")
	base := h.pop(t, tip0, a, "n-0")

	// A genuine proof over a 129-byte nonce: valid in every respect except size.
	bigNonce := h.pop(t, tip0, a, strings.Repeat("n", maxPoPNonceBytes+1))

	// An oversized SIGNATURE cannot be produced honestly (length is fixed by the
	// algorithm), so this case is refused by the size cap and would also be
	// refused by the possession gate behind it. It pins the attribution, not the
	// only line of defence: see maxSignatureBytes.
	bigSig := base
	bigSig.Signature = make([]byte, maxSignatureBytes+1)

	return []struct {
		name string
		req  Request
		want string
	}{
		{"nonce", Request{Chain: h.chain, Action: a, PoP: bigNonce}, "proof-of-possession nonce"},
		{"popSignature", Request{Chain: h.chain, Action: a, PoP: bigSig}, "proof-of-possession signature"},
		// Routine action: nothing verifies this approval, and before the cap Handle
		// recorded it anyway. This is the case that appended an entry when the guard
		// was removed.
		{"approval", Request{Chain: h.chain, Action: a, PoP: base,
			Approver: didAlice, Approval: make([]byte, maxSignatureBytes+1)}, "approval signature"},
	}
}

func TestR6_04_OversizedEvidenceRefusedBeforeAnyAppend(t *testing.T) {
	h := newHarness(t)
	for _, tc := range oversizedCases(t, h) {
		t.Run(tc.name, func(t *testing.T) {
			px := h.proxy(t)
			before := px.Tip()

			res, err := px.Handle(tc.req)
			if err == nil {
				t.Fatalf("oversized %s was accepted: %+v", tc.name, res.Decision)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name the offending field %q: %v", tc.want, err)
			}

			// The gate is only worth anything if it fired ahead of the side effect.
			// A "the request was rejected" assertion cannot tell an early gate from
			// a late one, which is the bug class this repo keeps reintroducing
			// (R2-01/R3-01/R4-03).
			if got := len(px.Entries()); got != 0 {
				t.Fatalf("refusal still appended %d entr(ies); the gate is behind the append", got)
			}
			if after := px.Tip(); after.Seq != before.Seq {
				t.Fatalf("tip moved from seq %d to %d on a refused request", before.Seq, after.Seq)
			}
			exp, err := px.Export()
			if err != nil {
				t.Fatal(err)
			}
			if n := len(exp.Credentials); n != 0 {
				t.Fatalf("refusal admitted %d credential(s) to the evidence set", n)
			}
		})
	}
}

// The durable log is the half that matters most: an entry that reached the WAL
// is on stable storage and survives the refusal, so the gate must be in front of
// the fsync too, not merely in front of the in-memory commit.
func TestR6_04_OversizedEvidenceWritesNothingDurable(t *testing.T) {
	h := newHarness(t)
	for _, tc := range oversizedCases(t, h) {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.wal")
			wal, err := OpenWAL(path)
			if err != nil {
				t.Fatal(err)
			}
			defer wal.Close()

			px := h.proxyWithWAL(t, wal)
			if _, err := px.Handle(tc.req); err == nil {
				t.Fatalf("oversized %s was accepted", tc.name)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != 0 {
				t.Fatalf("refused request wrote %d bytes to the durable log:\n%s", len(data), data)
			}
		})
	}
}

// A value AT the limit is legitimate and must still work, so the cap cannot be
// satisfied by refusing everything.
func TestR6_04_EvidenceAtTheLimitIsAccepted(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	a := action("10")

	// A nonce of exactly maxPoPNonceBytes, signed properly, is a valid request.
	nonce := strings.Repeat("n", maxPoPNonceBytes)
	pop := h.pop(t, tip0, a, nonce)
	if len(pop.Nonce) != maxPoPNonceBytes {
		t.Fatalf("test set up a %d-byte nonce, want %d", len(pop.Nonce), maxPoPNonceBytes)
	}

	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: pop})
	if err != nil {
		t.Fatalf("a nonce exactly at the limit was refused: %v", err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("expected allow, got %+v", res.Decision)
	}
	if got := len(px.Entries()); got != 1 {
		t.Fatalf("expected 1 entry, got %d", got)
	}
	// And it still verifies end to end, so the cap did not corrupt the evidence.
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("export with a limit-sized nonce does not verify: %+v", v.Entries)
	}
}
