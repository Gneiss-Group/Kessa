// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

var update = flag.Bool("update", false, "update golden files")

const goldenPath = "../../testdata/audit_export.golden.json"

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

// enforcementSigner is the deterministic enforcement point (proxy) that signs
// the golden log. Seed 0x55, so the golden signatures are reproducible.
func enforcementSigner(t *testing.T) signer.Signer {
	t.Helper()
	s, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:proxies:gatekeeper", seed32(0x55))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// buildGoldenLog constructs a fixed three-entry log: a routine allow, a
// consequential allow with a live status check, and a consequential deny.
// Everything is fixed (keys, timestamps, nonces) so Export() is byte-stable.
func buildGoldenLog(t *testing.T) *Log {
	t.Helper()
	l := NewLog(enforcementSigner(t))
	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	chain := []types.DID{
		"did:web:localhost:people:alice",
		"did:web:localhost:orgs:acme",
		"did:web:localhost:agents:worker",
	}
	records := []EntryDraft{
		{
			Action:        types.Action{Type: "post.publish", Target: "blog/hello", Attributes: map[string]string{"audience": "external"}, Timestamp: base},
			ResolvedChain: chain,
			Decision:      types.Decision{Allowed: true, RuleFired: "default-allow", PolicyVersion: "legal-v1", Reason: "below consequential threshold"},
			PoPNonce:      []byte("nonce-0001"),
			Timestamp:     base,
		},
		{
			Action:        types.Action{Type: "payment.transfer", Target: "acct/999", Attributes: map[string]string{"amount": "50", "currency": "USD"}, Timestamp: base.Add(time.Minute)},
			ResolvedChain: chain,
			Decision:      types.Decision{Allowed: true, Consequential: true, RuleFired: "amount-threshold", PolicyVersion: "commerce-v1", StatusCheckedHops: 1, Reason: "status live-checked, not revoked"},
			PoPNonce:      []byte("nonce-0002"),
			Timestamp:     base.Add(time.Minute),
		},
		{
			Action:        types.Action{Type: "payment.transfer", Target: "acct/999", Attributes: map[string]string{"amount": "5000", "currency": "USD"}, Timestamp: base.Add(2 * time.Minute)},
			ResolvedChain: chain,
			Decision:      types.Decision{Allowed: false, Consequential: true, RuleFired: "amount-threshold", PolicyVersion: "commerce-v1", StatusCheckedHops: 1, Reason: "exceeds attenuated ceiling"},
			PoPNonce:      []byte("nonce-0003"),
			Timestamp:     base.Add(2 * time.Minute),
		},
	}
	for i, r := range records {
		if _, err := l.Append(r); err != nil {
			t.Fatalf("Append entry %d: %v", i, err)
		}
	}
	return l
}

// TestGoldenExport freezes the export format. Run `go test -run TestGoldenExport
// -update ./internal/audit` to regenerate after an intentional format change.
func TestGoldenExport(t *testing.T) {
	got, err := buildGoldenLog(t).Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote golden fixture %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("export does not match golden fixture %s\n--- got ---\n%s", goldenPath, got)
	}
}

// TestExportIsDeterministic guards the determinism directive: two builds must
// produce identical bytes (Ed25519 is deterministic, JSON map keys are sorted).
func TestExportIsDeterministic(t *testing.T) {
	a, err := buildGoldenLog(t).Export()
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildGoldenLog(t).Export()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two identical builds produced different exports")
	}
}

func TestAppend_LinksHashChain(t *testing.T) {
	l := buildGoldenLog(t)
	entries := l.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if !bytes.Equal(entries[0].PrevHash, GenesisHash) {
		t.Fatal("entry 0 should link to the genesis hash")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq != uint64(i) {
			t.Fatalf("entry %d has seq %d", i, entries[i].Seq)
		}
		if !bytes.Equal(entries[i].PrevHash, entries[i-1].EntryHash) {
			t.Fatalf("entry %d prevHash does not match entry %d entryHash", i, i-1)
		}
	}
}

func TestVerifyChain_ValidGolden(t *testing.T) {
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	exp, err := ParseExport(data)
	if err != nil {
		t.Fatalf("ParseExport: %v", err)
	}
	pub := enforcementSigner(t).Public()
	failIdx, err := VerifyChain(exp, pub)
	if err != nil {
		t.Fatalf("valid golden should verify: fail@%d %v", failIdx, err)
	}
	if failIdx != -1 {
		t.Fatalf("expected failIdx -1, got %d", failIdx)
	}
}

func TestVerifyChain_WrongSignerKeyFails(t *testing.T) {
	exp := &Export{Version: ExportVersion, Signer: "x", Entries: buildGoldenLog(t).Entries()}
	other, _ := signer.NewSoftwareSignerFromSeed("did:web:localhost:orgs:acme", seed32(0x11))
	if failIdx, err := VerifyChain(exp, other.Public()); err == nil {
		t.Fatal("verification against the wrong key should fail")
	} else if failIdx != 0 {
		t.Fatalf("expected failure at entry 0, got %d", failIdx)
	}
}

// TestVerifyChain_TamperBreaksAtExactEntry is spec scenario 7 / §4: flipping one
// entry's content must fail at exactly that entry, with everything before it
// still passing.
func TestVerifyChain_TamperBreaksAtExactEntry(t *testing.T) {
	pub := enforcementSigner(t).Public()

	tamperers := []struct {
		name   string
		mutate func(e *Entry)
	}{
		{"content (decision reason)", func(e *Entry) { e.Decision.Reason = "totally fine, trust me" }},
		{"action target", func(e *Entry) { e.Action.Target = "acct/attacker" }},
		{"prevHash link", func(e *Entry) { e.PrevHash = bytes.Repeat([]byte{0xAA}, 32) }},
		{"entryHash", func(e *Entry) { e.EntryHash = bytes.Repeat([]byte{0xBB}, 32) }},
		{"signature", func(e *Entry) { e.Signature[0] ^= 0xff }},
	}
	for _, tc := range tamperers {
		t.Run(tc.name, func(t *testing.T) {
			exp := &Export{Version: ExportVersion, Signer: "did:web:localhost:proxies:gatekeeper", Entries: buildGoldenLog(t).Entries()}
			// Tamper the middle entry; entry 0 must still pass.
			tc.mutate(&exp.Entries[1])
			failIdx, err := VerifyChain(exp, pub)
			if err == nil {
				t.Fatal("tampered chain should fail verification")
			}
			if failIdx != 1 {
				t.Fatalf("expected failure at entry 1, got %d (%v)", failIdx, err)
			}
		})
	}
}

// buildEvidenceLog builds a log whose entries populate the v2 evidence fields.
func buildEvidenceLog(t *testing.T) *Log {
	t.Helper()
	l := NewLog(enforcementSigner(t))
	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	for i := range 2 {
		if _, err := l.Append(EntryDraft{
			Action:             types.Action{Type: "payment.transfer", Target: "acct/999", Timestamp: base},
			ResolvedChain:      []types.DID{"did:web:localhost:orgs:acme", "did:web:localhost:agents:worker"},
			ChainCredentialIDs: []string{"cred-narrow-100"},
			Decision:           types.Decision{Allowed: true, PolicyVersion: "commerce-v1"},
			PoPNonce:           []byte("nonce"),
			PoPSignature:       []byte("popsig-abcdefgh"),
			Timestamp:          base,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return l
}

// TestEvidenceFieldsChangeTheHash proves the fields are actually inside the
// hashed payload, that omitempty hides them when nil but does not exclude them
// when populated.
func TestEvidenceFieldsChangeTheHash(t *testing.T) {
	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	rec := EntryDraft{
		Action:        types.Action{Type: "payment.transfer", Timestamp: base},
		ResolvedChain: []types.DID{"a", "b"},
		Decision:      types.Decision{Allowed: true},
		Timestamp:     base,
	}
	bare, err := NewLog(enforcementSigner(t)).Append(rec)
	if err != nil {
		t.Fatal(err)
	}

	withIDs := rec
	withIDs.ChainCredentialIDs = []string{"cred-a"}
	gotIDs, err := NewLog(enforcementSigner(t)).Append(withIDs)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bare.EntryHash, gotIDs.EntryHash) {
		t.Fatal("ChainCredentialIDs is NOT hash-covered — the B3 substitution attack would be possible")
	}

	withPoP := rec
	withPoP.PoPSignature = []byte("popsig")
	gotPoP, err := NewLog(enforcementSigner(t)).Append(withPoP)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bare.EntryHash, gotPoP.EntryHash) {
		t.Fatal("PoPSignature is NOT hash-covered")
	}
}

// TestEvidenceFieldsAreTamperEvident is the B3 guarantee end to end: repointing
// an entry at a different credential, or swapping the PoP signature, breaks the
// entry hash at exactly that entry. Had these lived in an envelope side-map
// (rev 1), this test could not exist.
func TestEvidenceFieldsAreTamperEvident(t *testing.T) {
	pub := enforcementSigner(t).Public()
	tamperers := []struct {
		name   string
		mutate func(e *Entry)
	}{
		{"repoint to a broader credential", func(e *Entry) {
			e.ChainCredentialIDs = []string{"cred-broad-1000"}
		}},
		{"swap the PoP signature", func(e *Entry) { e.PoPSignature[0] ^= 0xff }},
		{"drop the evidence entirely", func(e *Entry) {
			e.ChainCredentialIDs = nil
			e.PoPSignature = nil
		}},
	}
	for _, tc := range tamperers {
		t.Run(tc.name, func(t *testing.T) {
			exp := &Export{Version: ExportVersion, Signer: "did:web:localhost:proxies:gatekeeper", Entries: buildEvidenceLog(t).Entries()}
			tc.mutate(&exp.Entries[1])
			failIdx, err := VerifyChain(exp, pub)
			if err == nil {
				t.Fatal("tampering with hash-covered evidence must fail verification")
			}
			if failIdx != 1 {
				t.Fatalf("expected failure at entry 1, got %d (%v)", failIdx, err)
			}
		})
	}
}

func TestVerifyChain_UnknownVersionRejected(t *testing.T) {
	exp := &Export{Version: "kessa-audit-export/v999", Entries: buildGoldenLog(t).Entries()}
	if _, err := VerifyChain(exp, enforcementSigner(t).Public()); err == nil {
		t.Fatal("unknown export version should be rejected")
	}
}
