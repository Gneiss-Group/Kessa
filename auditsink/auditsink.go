// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package auditsink defines the seam for forwarding Kessa audit records to an
// external destination, a local file, stdout, a log shipper, eventually a SIEM.
//
// This is a DESIGNATED PLUGIN INTERFACE. It lives in its own top-level package,
// separate from the enforcement/issuer/verifier code around it, and is licensed
// Apache-2.0 (see the SPDX header above) rather than under the core's license, so
// a third party can implement a sink against this package alone. To keep that
// promise real, this package depends on NOTHING but the standard library:
// AuditRecord is a plain, self-contained value, so implementing AuditSink never
// forces an importer to link against the core.
//
// Deliberately minimal: one method, one plain record. It is meant to be genuinely
// easy to implement. AuditRecord is authorization-oriented today (who did what,
// and whether it was allowed); it is shaped so that a future payload-carrying
// record, e.g. the tool-call body an action actually sent, could be added as a
// new field and flow through this same seam without changing the interface or
// breaking existing sinks.
package auditsink

import "time"

// AuditRecord is one audit event handed to a sink. It summarizes an enforcement
// decision and carries EntryHash as a back-reference to the signed, hash-chained
// audit entry it was derived from, the authoritative artifact remains the proxy's
// signed export; a sink is a forwarding/observability seam, not the system of
// record.
//
// Every field is a standard-library type on purpose (see the package doc): a sink
// implementation depends on this struct and nothing else.
type AuditRecord struct {
	Seq           uint64    `json:"seq"`           // entry position in the append-only log
	Timestamp     time.Time `json:"timestamp"`     // when the decision was recorded
	Actor         string    `json:"actor"`         // terminal principal (the DID that acted)
	ActionType    string    `json:"actionType"`    // e.g. "payment.transfer"
	ActionTarget  string    `json:"actionTarget"`  // resource identifier the action names
	Allowed       bool      `json:"allowed"`       // did the proxy allow the action?
	Consequential bool      `json:"consequential"` // was it classified consequential?
	Reason        string    `json:"reason"`        // human-readable decision reason
	EntryHash     []byte    `json:"entryHash"`     // hash of the signed audit entry this record mirrors
}

// AuditSink receives audit records as an enforcement point produces them. It is
// intentionally thin: one method, synchronous, returning an error the caller may
// surface or (for a best-effort forwarder) ignore. Implementations should be safe
// for the caller's concurrency model; the sinks in this package guard themselves
// with a mutex.
type AuditSink interface {
	Write(record AuditRecord) error
}
