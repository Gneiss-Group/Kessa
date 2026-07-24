// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// JSONSink writes each record as a JSON object (one per line) to an io.Writer.
// It is the trivial second implementation of the seam, NewJSONSink(os.Stdout)
// is the stdout-JSON sink, and doubles as an easy target for tests, which point
// it at a bytes.Buffer.
type JSONSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONSink returns a sink that encodes records to w. Writes are serialized, so
// records from concurrent callers never interleave mid-line.
func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{enc: json.NewEncoder(w)}
}

// NewStdoutSink is the stdout-JSON sink: JSONSink over os.Stdout.
func NewStdoutSink() *JSONSink { return NewJSONSink(os.Stdout) }

// Write encodes one record as a JSON line.
func (s *JSONSink) Write(record AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(record); err != nil {
		return fmt.Errorf("auditsink: encode record %d: %w", record.Seq, err)
	}
	return nil
}
