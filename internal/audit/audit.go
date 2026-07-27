// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package audit implements the hash-chained, signed, append-only log and its
// portable export format, the single most important contract in Kessa, because
// the independent verifier consumes an export with nothing but the export
// itself, public DID documents, and the signed status list. No database, no
// server, no call back to us.
//
// Each entry commits to the previous entry's hash, so the log is tamper-evident:
// altering any entry breaks the chain from that point forward, and re-deriving
// the hashes (which the verifier does independently) pinpoints exactly where.
// The enforcement point signs every entry, so entries cannot be forged without
// its key.
//
// Canonicalization matches the rest of Kessa: an entry's hash is SHA-256 over a
// domain-tagged, compact JSON encoding of the entry with the entryHash and
// signature fields cleared, deterministic, stdlib-only, no JSON-LD/JCS
// dependency. The export format is frozen at v1; testdata/audit_export.golden.json
// is the golden fixture. Verification takes a bare public key (the caller
// resolves it from the signer's DID document), keeping this package a pure leaf
// with no did dependency, same discipline as macaroon/status/vc.
package audit

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	// ExportVersion is the frozen export-format version. Bump it (and the golden
	// fixture) only on an intentional, documented format change.
	ExportVersion = "kessa-audit-export/v1"

	// hashDomain namespaces the entry hash. Bumped to v2 when the entry payload
	// changed shape (Decision.statusChecked -> statusCheckedHops, R2-01), so a
	// pre-fix entry can never collide with a post-fix one under the same tag.
	hashDomain = "kessa/audit-entry/v2"
	sigDomain  = "kessa/audit-sig/v1"
)

// GenesisHash is the PrevHash of the first entry: 32 zero bytes.
var GenesisHash = make([]byte, sha256.Size)

// Entry is one record in the append-only log.
//
// ChainCredentialIDs, PoPSignature, and PolicyID are the v2 evidence fields
// (spec §3.1 rev 2, plus the F1 policy binding). They are inside the hashed
// payload on purpose: the hash boundary is the trust boundary, so anything the
// verifier relies on to reach a verdict must be hash-covered and signed. In
// particular, hash-covering the credential IDs binds an entry to the *specific*
// credentials it was decided against, without that, a tamperer could repoint an
// entry at a different but legitimately-issued credential with broader caveats
// and flip a correct DENY into a false PASS. Hash-covering PolicyID likewise
// pins the entry to the exact policy it was classified under, so the verifier
// can re-derive consequentiality against that policy and a proxy cannot swap in a
// more permissive one after the fact (F1).
//
// Both are omitempty and nil on v1 entries, so v1 entries serialize to identical
// bytes and the frozen step-7 golden fixture still passes. One struct serves both
// versions; they differ only in whether the evidence fields are populated.
//
// Note for verifiers: because these are omitempty, an entry can simply *omit*
// them. Absence of evidence on an allowed entry is a FAILURE, never a skip.
type Entry struct {
	Seq                uint64         `json:"seq"`
	PrevHash           []byte         `json:"prevHash"`
	Action             types.Action   `json:"action"`
	ResolvedChain      []types.DID    `json:"resolvedChain"`                // human -> org -> agent -> ... -> actor
	ChainCredentialIDs []string       `json:"chainCredentialIDs,omitempty"` // [i] = credential issued by ResolvedChain[i] to ResolvedChain[i+1]
	Decision           types.Decision `json:"decision"`
	PolicyID           string         `json:"policyID,omitempty"`     // content address of the policy this entry was classified under (F1)
	PoPNonce           []byte         `json:"popNonce,omitempty"`     // proof-of-possession nonce used at action time
	PoPSignature       []byte         `json:"popSignature,omitempty"` // holder's signature over popInput (action + entry position)
	ApprovedBy         types.DID      `json:"approvedBy,omitempty"`   // human who approved a consequential action
	Approval           []byte         `json:"approval,omitempty"`     // that human's signature over the action + entry position
	Timestamp          time.Time      `json:"timestamp"`
	EntryHash          []byte         `json:"entryHash,omitempty"` // H(domain || canonical(entry without hash/sig))
	Signature          []byte         `json:"signature,omitempty"` // enforcement point signs EntryHash
}

// Export is the self-contained, portable log envelope.
type Export struct {
	Version string    `json:"version"`
	Signer  types.DID `json:"signer"` // enforcement point whose key signs every entry
	Entries []Entry   `json:"entries"`
}

// Record is the caller-supplied content of a new entry; the log fills in Seq,
// PrevHash, EntryHash, and Signature. It is never serialized (only Entry is)
// so it carries no JSON tags.
type Record struct {
	Action             types.Action
	ResolvedChain      []types.DID
	ChainCredentialIDs []string
	Decision           types.Decision
	PolicyID           string
	PoPNonce           []byte
	PoPSignature       []byte
	ApprovedBy         types.DID
	Approval           []byte
	Timestamp          time.Time
}

// Log is an append-only, hash-chained, signed log held by one enforcement point.
type Log struct {
	signer  signer.Signer
	entries []Entry
}

// NewLog starts an empty log signed by s (the enforcement point).
func NewLog(s signer.Signer) *Log {
	return &Log{signer: s}
}

// Append seals r into a new entry and commits it: it links to the previous
// entry's hash, computes this entry's hash, signs it, and appends. The stored
// entry is returned by value (a copy) so callers cannot mutate the log's
// internals. It is exactly Seal followed by Commit.
func (l *Log) Append(r Record) (Entry, error) {
	e, err := l.Seal(r)
	if err != nil {
		return Entry{}, err
	}
	if err := l.Commit(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Seal produces the next entry from r WITHOUT appending it: it fixes the entry's
// position (Seq + PrevHash) against the current tip, computes its hash, and signs
// it. The returned entry is not yet part of the log.
//
// Seal exists so a caller can interpose a step between producing an entry and
// admitting it, specifically, making the entry durable before it is committed
// (log-before-act). Sealing does not advance the tip, so a sealed entry that is
// never Committed simply never happened; the same slot is produced again next
// time. Under a single writer (the proxy holds its lock across Seal+Commit) this
// is exact; Commit re-checks the slot regardless.
func (l *Log) Seal(r Record) (Entry, error) {
	seq, prev := l.Tip()
	e := Entry{
		Seq:                seq,
		PrevHash:           prev,
		Action:             r.Action,
		ResolvedChain:      r.ResolvedChain,
		ChainCredentialIDs: r.ChainCredentialIDs,
		Decision:           r.Decision,
		PolicyID:           r.PolicyID,
		PoPNonce:           r.PoPNonce,
		PoPSignature:       r.PoPSignature,
		ApprovedBy:         r.ApprovedBy,
		Approval:           r.Approval,
		Timestamp:          r.Timestamp,
	}
	hash, err := entryHash(&e)
	if err != nil {
		return Entry{}, err
	}
	e.EntryHash = hash
	sig, err := l.signer.Sign(sigInput(hash))
	if err != nil {
		return Entry{}, fmt.Errorf("audit: sign entry %d: %w", e.Seq, err)
	}
	e.Signature = sig
	return e, nil
}

// Commit appends a previously Sealed entry, after re-checking that it still lands
// in exactly the slot it was sealed for: its Seq and PrevHash must match the
// current tip. This is what makes the Seal -> (durably persist) -> Commit sequence
// safe, a stale or foreign entry, or one produced against a tip that has since
// moved, is refused rather than creating a gap or an out-of-order link.
func (l *Log) Commit(e Entry) error {
	seq, prev := l.Tip()
	if e.Seq != seq || !bytes.Equal(e.PrevHash, prev) {
		return fmt.Errorf("audit: commit entry seq %d does not match current tip seq %d (concurrent append or stale seal)", e.Seq, seq)
	}
	l.entries = append(l.entries, e)
	return nil
}

// LoadLog reconstructs a log from previously sealed entries, e.g. read from a
// durable write-ahead log on restart, so appending resumes from where it left off
// with the hash chain, seq, and approval-position binding all intact across the
// restart (closing the replay gap ApprovalInput documents).
//
// It VERIFIES the whole chain against s's public key before accepting it: a
// truncated, reordered, or tampered WAL is rejected here rather than silently
// resumed, because resuming onto a broken prefix would sign new entries over a
// history that does not verify. s must be the same enforcement point that sealed
// the entries.
func LoadLog(s signer.Signer, entries []Entry) (*Log, error) {
	if fi, err := VerifyEntries(entries, s.Public()); err != nil {
		return nil, fmt.Errorf("audit: recover: entry %d failed verification: %w", fi, err)
	}
	return &Log{signer: s, entries: append([]Entry(nil), entries...)}, nil
}

// Tip reports the position the NEXT appended entry will occupy: its Seq and the
// PrevHash it will link to (GenesisHash for an empty log). Callers that must
// produce evidence bound to an entry's chain position, a proof-of-possession or
// a human approval, both of which now commit to Seq+PrevHash (F4): read the tip
// before signing, so the signature covers exactly the slot the entry lands in.
func (l *Log) Tip() (seq uint64, prevHash []byte) {
	if n := len(l.entries); n > 0 {
		return uint64(n), l.entries[n-1].EntryHash
	}
	return 0, GenesisHash
}

// Entries returns a copy of the log's entries.
func (l *Log) Entries() []Entry {
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Export serializes the whole log into its portable, frozen JSON form.
func (l *Log) Export() ([]byte, error) {
	return json.MarshalIndent(Export{
		Version: ExportVersion,
		Signer:  l.signer.DID(),
		Entries: l.entries,
	}, "", "  ")
}

// ParseExport reads an export from JSON. It performs no verification.
func ParseExport(data []byte) (*Export, error) {
	var exp Export
	if err := json.Unmarshal(data, &exp); err != nil {
		return nil, fmt.Errorf("audit: parse export: %w", err)
	}
	return &exp, nil
}

// VerifyChain verifies a v1 export envelope. It is strict: any version other
// than v1 is rejected here, so a future format can never be silently accepted
// through this door. The v2 envelope has its own dispatcher in internal/export.
func VerifyChain(exp *Export, pub crypto.PublicKey) (failIndex int, err error) {
	if exp.Version != ExportVersion {
		return 0, fmt.Errorf("audit: unsupported export version %q", exp.Version)
	}
	return VerifyEntries(exp.Entries, pub)
}

// VerifyEntries independently re-derives every entry hash, checks that each
// entry links to the previous one, and verifies each entry's signature against
// pub. It returns the index of the first failing entry (and a descriptive
// error), or -1 and nil if the whole chain is intact. Everything before the
// failure verifies, the caller can trust entries [0, failIndex).
//
// It knows nothing of envelope versions by design, so that internal/export can
// reuse it for v2. CONTRACT: callers MUST have validated the envelope version
// before calling. Every caller is a version-checking parser (audit.VerifyChain
// for v1, export.Parse for v1/v2); do not add a caller that skips that check.
func VerifyEntries(entries []Entry, pub crypto.PublicKey) (failIndex int, err error) {
	prev := GenesisHash
	for i := range entries {
		e := entries[i]
		if e.Seq != uint64(i) {
			return i, fmt.Errorf("audit: entry %d has out-of-order seq %d", i, e.Seq)
		}
		if !bytes.Equal(e.PrevHash, prev) {
			return i, fmt.Errorf("audit: entry %d prevHash does not link to entry %d", i, i-1)
		}
		want, err := entryHash(&e)
		if err != nil {
			return i, err
		}
		if !bytes.Equal(want, e.EntryHash) {
			return i, fmt.Errorf("audit: entry %d hash mismatch (tampered content)", i)
		}
		if !signer.Verify(pub, sigInput(e.EntryHash), e.Signature) {
			return i, fmt.Errorf("audit: entry %d signature invalid", i)
		}
		prev = e.EntryHash
	}
	return -1, nil
}

// entryHash computes SHA-256 over the domain-tagged canonical encoding of e with
// the entryHash and signature fields cleared.
func entryHash(e *Entry) ([]byte, error) {
	c := *e
	c.EntryHash = nil
	c.Signature = nil
	body, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("audit: canonicalize entry %d: %w", e.Seq, err)
	}
	h := sha256.New()
	h.Write([]byte(hashDomain))
	h.Write([]byte{0x00})
	h.Write(body)
	return h.Sum(nil), nil
}

// ---- human approval of consequential actions -------------------------------

// approvalDomain namespaces a human's approval signature so it can never be
// replayed as any other Kessa signature. Bumped to v2 when PrevHash joined the
// signed material (R2-04).
const approvalDomain = "kessa/action-approval/v2"

// ApprovalInput is the exact byte string a human signs to approve one action by
// one actor at one chain position. Binding the actor prevents an approval issued
// for one agent from being reused by another; binding the whole action prevents
// it from being reused for a different amount, target, or moment; and binding the
// entry's position prevents one approval from being lifted onto a sibling entry
// or replayed into a later append, so one approval authorizes exactly one entry
// (F4).
//
// "Position" is Seq AND PrevHash. This file's Tip doc claimed both since F4 while
// only Seq was actually bound (R2-04), and the gap was real: Seq is unique only
// within one log instance, so an approval minted for the first run's slot 5
// replayed into a restarted proxy's slot 5. PrevHash is the previous entry's
// hash, which transitively commits to the whole log before it, so the same slot
// number in two different logs is two different signing inputs.
//
// Honest limit, stated because the fix does not cover it: at Seq 0 both logs
// share GenesisHash, so an approval minted for a fresh log's very first slot
// still replays into another fresh log's very first slot. Closing that needs a
// per-log identifier in the signed material, which is out of scope for this pass.
func ApprovalInput(actor types.DID, a types.Action, seq uint64, prevHash []byte) ([]byte, error) {
	body, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("audit: canonicalize action for approval: %w", err)
	}
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	out := make([]byte, 0, len(approvalDomain)+len(actor)+len(body)+len(seqb)+len(prevHash)+4)
	out = append(out, approvalDomain...)
	out = append(out, 0x00)
	out = append(out, actor...)
	out = append(out, 0x00)
	out = append(out, body...)
	out = append(out, 0x00)
	out = append(out, seqb[:]...)
	out = append(out, 0x00)
	out = append(out, prevHash...)
	return out, nil
}

// SignApproval produces a human's approval of actor performing action a at the
// entry position (Seq + PrevHash) that will record it.
func SignApproval(human signer.Signer, actor types.DID, a types.Action, seq uint64, prevHash []byte) ([]byte, error) {
	input, err := ApprovalInput(actor, a, seq, prevHash)
	if err != nil {
		return nil, err
	}
	return human.Sign(input)
}

// VerifyApproval checks an approval signature against the approver's key, which
// the caller resolves from the approver's DID document. seq and prevHash are the
// recorded entry's own position, so an approval minted for a different slot, or
// for the same slot number in a different log, fails.
func VerifyApproval(pub crypto.PublicKey, actor types.DID, a types.Action, seq uint64, prevHash []byte, sig []byte) error {
	input, err := ApprovalInput(actor, a, seq, prevHash)
	if err != nil {
		return err
	}
	// signer.Verify dispatches on the approver key's algorithm. A human approver's
	// key is exactly the kind that may be a hardware-minted P-256 key, so this path
	// must be algorithm-agile too, not Ed25519-only.
	if !signer.Verify(pub, input, sig) {
		return fmt.Errorf("audit: approval signature is invalid for actor %q", actor)
	}
	return nil
}

// sigInput is the domain-separated message the enforcement point signs: the tag
// followed by the entry hash (which already commits to the entry's content).
func sigInput(entryHash []byte) []byte {
	out := make([]byte, 0, len(sigDomain)+1+len(entryHash))
	out = append(out, sigDomain...)
	out = append(out, 0x00)
	out = append(out, entryHash...)
	return out
}
