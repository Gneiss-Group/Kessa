// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// FileSink is the default sink: it appends each record as one JSON object per
// line (JSON Lines) to a local file. Append-only and line-delimited so the file
// can be tailed live and streamed to another tool without waiting for a close.
//
// This is a demo-grade sink (per its package's scope): no rotation, no fsync
// policy, no delivery guarantee. The signed audit export remains the system of
// record; this file is a convenience forward.
type FileSink struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

// NewFileSink opens (creating if absent) path for appending and returns a sink
// that writes JSON Lines to it. Close it when done.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("auditsink: open %q: %w", path, err)
	}
	return &FileSink{f: f, enc: json.NewEncoder(f)}, nil
}

// Write appends one record as a JSON line. Encoder.Encode terminates each object
// with a newline, so the file is valid JSON Lines.
func (s *FileSink) Write(record AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(record); err != nil {
		return fmt.Errorf("auditsink: write record %d: %w", record.Seq, err)
	}
	return nil
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
