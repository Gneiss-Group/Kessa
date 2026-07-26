// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// rec is a minimal routine record for the Seal/Commit/Load tests.
func rec(target string) Record {
	return Record{
		Action:        types.Action{Type: "payment.transfer", Target: target},
		ResolvedChain: []types.DID{"did:web:localhost:people:alice", "did:web:localhost:agents:worker"},
		Decision:      types.Decision{Allowed: true},
		Timestamp:     time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

// TestSealThenCommitAppends confirms Seal produces an entry without advancing the
// tip, and Commit then appends it, i.e. Append == Seal + Commit.
func TestSealThenCommitAppends(t *testing.T) {
	l := NewLog(enforcementSigner(t))
	e, err := l.Seal(rec("acct/1"))
	if err != nil {
		t.Fatal(err)
	}
	// Sealing must NOT have advanced the log: the tip is still the empty-log slot.
	if seq, _ := l.Tip(); seq != 0 {
		t.Fatalf("Seal advanced the tip to %d; it must not commit", seq)
	}
	if err := l.Commit(e); err != nil {
		t.Fatal(err)
	}
	if seq, _ := l.Tip(); seq != 1 {
		t.Fatalf("after Commit the tip should be 1, got %d", seq)
	}
	if got := l.Entries(); len(got) != 1 || got[0].EntryHash == nil {
		t.Fatalf("committed entry not stored/sealed: %+v", got)
	}
}

// TestCommitRejectsStaleSeal is the guard that makes Seal -> persist -> Commit
// safe: an entry sealed against one tip cannot be committed once the tip has moved.
func TestCommitRejectsStaleSeal(t *testing.T) {
	l := NewLog(enforcementSigner(t))
	stale, err := l.Seal(rec("acct/1")) // sealed against slot 0
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(rec("acct/2")); err != nil { // slot 0 is now taken
		t.Fatal(err)
	}
	if err := l.Commit(stale); err == nil {
		t.Fatal("committing an entry whose slot was taken must fail")
	}
}

// TestLoadLogResumesVerifiedChain confirms a log rebuilt from prior entries
// verifies, resumes the tip, and links a new entry onto the recovered history.
func TestLoadLogResumesVerifiedChain(t *testing.T) {
	l := NewLog(enforcementSigner(t))
	for _, target := range []string{"acct/1", "acct/2"} {
		if _, err := l.Append(rec(target)); err != nil {
			t.Fatal(err)
		}
	}
	prior := l.Entries()

	l2, err := LoadLog(enforcementSigner(t), prior)
	if err != nil {
		t.Fatalf("recover a valid chain: %v", err)
	}
	if seq, _ := l2.Tip(); seq != 2 {
		t.Fatalf("recovered tip should be 2, got %d", seq)
	}
	next, err := l2.Append(rec("acct/3"))
	if err != nil {
		t.Fatal(err)
	}
	// The resumed entry links onto the recovered history.
	if _, err := VerifyEntries(append(prior, next), enforcementSigner(t).Public()); err != nil {
		t.Fatalf("resumed chain must verify end to end: %v", err)
	}
}

// TestLoadLogRejectsTamper confirms recovery refuses a chain whose contents were
// altered, rather than silently resuming onto a history that does not verify.
func TestLoadLogRejectsTamper(t *testing.T) {
	l := NewLog(enforcementSigner(t))
	if _, err := l.Append(rec("acct/1")); err != nil {
		t.Fatal(err)
	}
	entries := l.Entries()
	entries[0].Action.Target = "acct/evil" // hash no longer matches

	_, err := LoadLog(enforcementSigner(t), entries)
	if err == nil {
		t.Fatal("recovery must reject a tampered chain")
	}
	if !strings.Contains(err.Error(), "verification") {
		t.Fatalf("error should name the verification failure: %v", err)
	}
}
