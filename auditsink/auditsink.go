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
//
// The directive line below is the designation itself, and it is load-bearing
// rather than decorative. It says: the exported interface types declared in THIS
// file are a designated plug point, so an independent implementation of them may
// be licensed on its own terms even when compiled into the same binary as the
// AGPL core. That permission is conditional, and the condition is mechanical: a
// designated package may reach nothing but the standard library and other
// designated packages, so implementing the interface can never force an importer
// to link the core. Delete the line and the package stops being designated;
// import the core from here and the designation stops being true; delete the
// notice below and a copy of this file carries a designation whose grant the
// reader cannot locate. scripts/license-check.sh fails the build on all three.
// LICENSING.md carries the canonical statement of the marker's syntax and
// meaning.
//
// ADDITIONAL PERMISSION: An additional permission under section 7 of the
// AGPL-3.0 applies to independent implementations of the interfaces declared in
// this file.
//
// The authoritative text is the section headed "KESSA ADDITIONAL PERMISSION
// UNDER SECTION 7" at the end of the LICENSE file in the Kessa distribution
// you received (also available at https://github.com/Gneiss-Group/Kessa),
// and is not reproduced here.
//
// Note to downstream developers: This notice is intended to travel with this
// file. The interface designation marker below relies on the Section 7
// permission; retaining this header ensures the legal context is preserved
// if this file is copied outside the core distribution.
//
//kessa:plugin-interface
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
	Seq           uint64    `json:"seq"`           // entry position; ZERO when Outcome is Unattributable (no entry exists)
	Timestamp     time.Time `json:"timestamp"`     // when the decision was recorded
	Actor         string    `json:"actor"`         // terminal principal; CLAIMED, not established, when Unattributable
	ActionType    string    `json:"actionType"`    // e.g. "payment.transfer"
	ActionTarget  string    `json:"actionTarget"`  // resource identifier the action names
	Allowed       bool      `json:"allowed"`       // did the proxy allow the action?
	Consequential bool      `json:"consequential"` // was it classified consequential?
	Reason        string    `json:"reason"`        // human-readable decision reason
	EntryHash     []byte    `json:"entryHash"`     // hash of the signed entry; NIL when Outcome is Unattributable
	Outcome       string    `json:"outcome"`       // Recorded or Unattributable; see below
}

// Outcome values. This field is the one the package doc anticipated: added
// rather than replacing anything, so a sink written before it existed still
// compiles and still receives every record it used to.
//
// A sink that ignores Outcome sees exactly what it saw before, because every
// record that used to exist is Recorded. What is NEW is Unattributable, and the
// distinction matters for the reason the whole seam exists:
//
//	Recorded        The request was attributed to a principal (its proof of
//	                possession verified), a decision was made about it, and that
//	                decision is in the signed export. Seq and EntryHash point at
//	                it. This is a mirror of evidence.
//	Unattributable  The request could not be attributed to anyone: the chain or
//	                the proof of possession did not verify, so no decision was
//	                made and NOTHING was appended. Seq is zero and EntryHash is
//	                nil because there is no entry to point at. Actor is what the
//	                caller CLAIMED to be. This is telemetry, not evidence.
//
// The second kind is deliberately not in the signed log: an entry there asserts
// something about an identified principal, and an unattributable attempt asserts
// nothing about anyone. But an operator still needs to see it, because a refused
// attempt is exactly what an attack looks like, which is why it comes here.
const (
	OutcomeRecorded       = "recorded"
	OutcomeUnattributable = "unattributable"
)

// AuditSink receives audit records as an enforcement point produces them. It is
// intentionally thin: one method, synchronous, returning an error the caller may
// surface or (for a best-effort forwarder) ignore. Implementations should be safe
// for the caller's concurrency model; the sinks in this package guard themselves
// with a mutex.
type AuditSink interface {
	Write(record AuditRecord) error
}
