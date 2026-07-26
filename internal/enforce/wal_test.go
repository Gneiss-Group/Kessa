// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/policy"
)

// walProxy builds a proxy backed by wal, otherwise identical to harness.proxy.
func walProxy(t *testing.T, h *harness, wal *WAL) *Proxy {
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

// TestDurableWAL_EntryDurableBeforeReturn is the log-before-act guarantee: by the
// time Handle returns an ALLOW, the entry (and its evidence) is already fsynced to
// the durable log, so a crash the instant after cannot lose the record of the
// action that ALLOW authorizes.
func TestDurableWAL_EntryDurableBeforeReturn(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "audit.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wal.Close() }()
	px := walProxy(t, h, wal)

	a := action("10")
	res, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "w1")})
	if err != nil || !res.Decision.Allowed {
		t.Fatalf("expected a routine allow, got %+v err=%v", res, err)
	}

	// Read the file back independently: the record is on disk already.
	got, err := readWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Entry.Seq != 0 {
		t.Fatalf("WAL should hold the entry before the allow returned; got %d records", len(got))
	}
	if got[0].Entry.Action.Attributes["amount"] != "10" {
		t.Fatalf("durable entry does not match the decision: %+v", got[0].Entry.Action)
	}
	if len(got[0].Credentials) != len(h.chain.Links) {
		t.Fatalf("durable record should carry the chain's evidence (%d creds), got %d", len(h.chain.Links), len(got[0].Credentials))
	}
}

// TestDurableWAL_RecoverResumeVerify drives a proxy, then rebuilds a fresh proxy
// from the same WAL and confirms the recovered log verifies, resumes the tip, and
// accepts a new decision that chains onto the recovered history.
func TestDurableWAL_RecoverResumeVerify(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "audit.wal")

	// Proxy 1: a routine allow, then a consequential allow (status + approval).
	wal1, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	px1 := walProxy(t, h, wal1)
	a1 := action("10")
	if _, err := px1.Handle(Request{Chain: h.chain, Action: a1, PoP: h.pop(t, tip0, a1, "r1")}); err != nil {
		t.Fatal(err)
	}
	tip1 := px1.Tip()
	a2 := action("100")
	if _, err := px1.Handle(Request{
		Chain: h.chain, Action: a2, PoP: h.pop(t, tip1, a2, "r2"),
		Approver: didAlice, Approval: h.approval(t, tip1, didAlice, a2),
	}); err != nil {
		t.Fatal(err)
	}
	if err := wal1.Close(); err != nil {
		t.Fatal(err)
	}

	// Proxy 2 recovers from the same file.
	wal2, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wal2.Close() }()
	px2 := walProxy(t, h, wal2)

	if tip := px2.Tip(); tip.Seq != 2 {
		t.Fatalf("recovered tip seq = %d, want 2", tip.Seq)
	}
	exp, err := px2.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Entries) != 2 {
		t.Fatalf("recovered export has %d entries, want 2", len(exp.Entries))
	}
	if v := h.verify(t, px2); !v.Pass() {
		t.Fatalf("recovered export failed independent verification: %s", v.Entries[0].Reason)
	}

	// A new decision on the recovered proxy chains onto the recovered history.
	tip2 := px2.Tip()
	a3 := action("20")
	if _, err := px2.Handle(Request{Chain: h.chain, Action: a3, PoP: h.pop(t, tip2, a3, "r3")}); err != nil {
		t.Fatal(err)
	}
	exp2, err := px2.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(exp2.Entries) != 3 {
		t.Fatalf("after resume the export should have 3 entries, got %d", len(exp2.Entries))
	}
	if v := h.verify(t, px2); !v.Pass() {
		t.Fatalf("post-recovery export failed verification: %s", v.Entries[0].Reason)
	}
}

// TestDurableWAL_FailClosedOnWriteError confirms that when the durable log cannot
// be written, the decision is refused (no ALLOW returned) and nothing is committed.
func TestDurableWAL_FailClosedOnWriteError(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "audit.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	px := walProxy(t, h, wal)

	a := action("10")
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "ok")}); err != nil {
		t.Fatal(err)
	}

	// The durable log is now unavailable.
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	a2 := action("11")
	_, err = px.Handle(Request{Chain: h.chain, Action: a2, PoP: h.pop(t, px.Tip(), a2, "fail")})
	if err == nil {
		t.Fatal("a durable-write failure must fail closed: return an error, not an allow")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("error should name the fail-closed refusal: %v", err)
	}
	// Nothing committed: the log still holds exactly the one good entry.
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Entries) != 1 {
		t.Fatalf("a fail-closed decision must not be committed; log has %d entries, want 1", len(exp.Entries))
	}
}

// TestDurableWAL_RejectsTamperedRecovery confirms recovery refuses a WAL whose
// contents were altered, catching it by re-deriving the hash (the record still
// parses as JSON), not merely by failing to read it.
func TestDurableWAL_RejectsTamperedRecovery(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "audit.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	px := walProxy(t, h, wal)
	a := action("10")
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "t1")}); err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}

	// Flip the entry's action target, keeping the JSON valid so it still parses.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte("acct/999"), []byte("acct/000"), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("expected the action target to be present to tamper")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	wal2, err := OpenWAL(path) // reads fine: the record is still valid JSON
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wal2.Close() }()

	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewProxy(Config{
		EnforcementPoint: sign(t, didProxy),
		Policy:           pol,
		DIDs:             h.resolver,
		Status:           h.statuses,
		Now:              func() time.Time { return fixedTime },
		WAL:              wal2,
	})
	if err == nil {
		t.Fatal("recovery must reject a tampered WAL")
	}
	if !strings.Contains(err.Error(), "recover") {
		t.Fatalf("error should surface as a recovery failure: %v", err)
	}
}
