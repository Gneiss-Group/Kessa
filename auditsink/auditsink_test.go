// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleRecord(seq uint64) AuditRecord {
	return AuditRecord{
		Seq:           seq,
		Timestamp:     time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		Actor:         "did:web:localhost:agents:helper",
		ActionType:    "payment.transfer",
		ActionTarget:  "acct/999",
		Allowed:       true,
		Consequential: true,
		Reason:        "within delegated authority",
		EntryHash:     []byte{0xde, 0xad, 0xbe, 0xef},
	}
}

// decodeJSONL splits JSON-Lines bytes back into records.
func decodeJSONL(t *testing.T, data []byte) []AuditRecord {
	t.Helper()
	var out []AuditRecord
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r AuditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// TestJSONSink_WritesOneLinePerRecord: the trivial sink emits valid JSON Lines.
func TestJSONSink_WritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	for i := uint64(0); i < 3; i++ {
		if err := sink.Write(sampleRecord(i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := decodeJSONL(t, buf.Bytes())
	if len(got) != 3 {
		t.Fatalf("wrote %d lines, want 3", len(got))
	}
	for i, r := range got {
		if r.Seq != uint64(i) {
			t.Fatalf("line %d has seq %d", i, r.Seq)
		}
	}
}

// TestFileSink_AppendsAndRoundTrips: the default sink appends records to a file
// and reopening it appends rather than truncates.
func TestFileSink_AppendsAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	s1, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Write(sampleRecord(0)); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// A second sink over the same path must append (O_APPEND), not overwrite.
	s2, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Write(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeJSONL(t, data)
	if len(got) != 2 || got[0].Seq != 0 || got[1].Seq != 1 {
		t.Fatalf("file did not accumulate both records: %+v", got)
	}
	if !bytes.Equal(got[1].EntryHash, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("entry hash did not round-trip: %x", got[1].EntryHash)
	}
}

// TestSinksSatisfyInterface is a compile-time guard that both shipped sinks
// implement AuditSink.
func TestSinksSatisfyInterface(t *testing.T) {
	var _ AuditSink = (*FileSink)(nil)
	var _ AuditSink = (*JSONSink)(nil)
	var _ AuditSink = NewStdoutSink()
}
