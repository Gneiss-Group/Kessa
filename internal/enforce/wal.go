// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/export"
)

// The durable write-ahead audit log. It is what makes "the signed export is the
// system of record" true across a crash rather than true-until-a-crash.
//
// The guarantee it underwrites is LOG-BEFORE-ACT: the proxy seals an entry, writes
// it here and fsyncs, and only then commits the entry and returns the decision the
// caller acts on (see Proxy.decideAndAppend). So a crash the instant after an ALLOW
// is returned cannot lose the record of the action that ALLOW authorized, the
// entry is already on stable storage. A write failure here is fail-closed: the
// decision is refused rather than returned, because an action Kessa cannot durably
// record is exactly the action Kessa exists to prevent.
//
// This is system-of-record, deliberately NOT the auditsink seam: auditsink is a
// best-effort, post-decision, drop-under-load forwarder (an additive copy), and a
// before-act guarantee cannot be delivered by a seam defined to run after the act
// and permitted to drop. The two live on opposite sides of the trust boundary.
//
// Format: one JSON walRecord per entry, appended. Each record carries the sealed
// entry AND the credentials newly seen for it, so replaying the file rebuilds both
// the hash-chained entry log and the evidence set, making the WAL a self-sufficient,
// independently re-verifiable record with no companion artifact.

// walRecord is one durable line: a sealed audit entry plus the evidence first seen
// at that entry (credentials already recorded by an earlier entry are omitted, so
// the file does not re-store a chain's credentials on every request).
type walRecord struct {
	Entry       audit.Entry               `json:"entry"`
	Credentials []export.CredentialRecord `json:"credentials,omitempty"`
}

// WAL is an append-only, fsync-on-write durable audit log backing one proxy.
type WAL struct {
	mu        sync.Mutex
	f         *os.File
	recovered []walRecord
}

// OpenWAL opens (creating if absent) a durable audit log at path, first reading any
// existing records so the proxy can recover the log at startup, then holding the
// file open in append mode for syncing writes. The 0o600 mode keeps the record,
// which contains actions and credential evidence, readable only by its owner.
func OpenWAL(path string) (*WAL, error) {
	recovered, err := readWAL(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open %q: %w", path, err)
	}
	return &WAL{f: f, recovered: recovered}, nil
}

// readWAL reads every record from an existing WAL file. A missing file is not an
// error (a first run). A malformed file IS an error: half a record on disk means
// the durability contract was already broken, and silently discarding it would
// resume onto a truncated history, so recovery refuses rather than guesses.
func readWAL(path string) ([]walRecord, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("wal: read %q: %w", path, err)
	}
	var out []walRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var r walRecord
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("wal: parse %q (record %d): %w", path, len(out), err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Recovered returns the records read at open time, for the proxy to rebuild its
// log and evidence set from. It reflects the file as it was at OpenWAL; it does not
// include records Appended since.
func (w *WAL) Recovered() []walRecord { return w.recovered }

// Append writes one record and fsyncs it before returning, so the entry is on
// stable storage before the caller learns the action may proceed. Any error
// (including a closed WAL) is returned so the caller fails closed. The proxy holds
// its enforcement lock across the Seal/Append/Commit sequence, so records reach the
// file in seq order; the mutex here keeps the WAL independently safe regardless.
func (w *WAL) Append(entry audit.Entry, creds []export.CredentialRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("wal: append to closed log")
	}
	line, err := json.Marshal(walRecord{Entry: entry, Credentials: creds})
	if err != nil {
		return fmt.Errorf("wal: marshal entry %d: %w", entry.Seq, err)
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("wal: write entry %d: %w", entry.Seq, err)
	}
	// The fsync is the whole point: without it the write sits in the OS page cache
	// and a crash loses it, which is precisely the gap this exists to close.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("wal: sync entry %d: %w", entry.Seq, err)
	}
	return nil
}

// Close closes the underlying file. Appends after Close fail closed.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
