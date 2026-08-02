// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Package enforce is the enforcement engine: the single code path that turns an
// action attempt into an allow/deny decision plus a signed audit entry. Both the
// proxy server (cmd/proxy) and the mock agent's in-process driver (cmd/agent)
// call it, so there is exactly one place where authority, revocation, possession,
// and approval are composed, and exactly one thing the independent verifier
// mirrors. Transport (in-process call vs localhost HTTP) is a shell over this;
// the guarantees live here.
package enforce

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Gneiss-Group/Kessa/auditsink"
	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Proxy is the enforcement chokepoint. Every consequential guarantee the
// verifier later re-derives is composed HERE, in one place, before any
// Decision.Allowed is written.
//
// The load-bearing rule of this whole file: policy.Evaluate is a CLASSIFIER, not
// an authorization. It answers "is this consequential, and does a policy rule
// forbid it?", nothing about delegated authority, revocation, possession, or
// approval. Allowed is set to true ONLY after the request has passed, in order:
// chain verification, caveat satisfaction, policy (not denied), a live status
// check with no revoked hop (if consequential), proof of possession, and a valid
// human approval (if consequential). Any failure denies. The independent
// verifier re-checks every one of these for each allowed entry, so a proxy that
// skips a step does not get away with it, it gets caught.
type Proxy struct {
	// mu guards the read-tip-through-append critical section and every read of
	// the log and evidence set. It lives HERE, not in the HTTP shell (R2-04).
	//
	// It used to live in enforce.Handler, which meant Proxy, an exported type
	// with an exported Handle method, driven in-process by cmd/agent and by the
	// perf harness, was safe only by the accident of who happened to call it. Two
	// concurrent Handle calls raced between Tip() and Append() three ways: both
	// read the same Seq and both verified the same single-use human approval
	// against it, so ONE approval authorized TWO consequential real-world actions;
	// both appended at the same index, so the second action silently overwrote the
	// first in the log and left no trace of itself at all; and both wrote the
	// evidence map unguarded, which is not a recoverable panic but a runtime kill.
	//
	// The middle one is the reason the lock belongs to the type rather than the
	// transport. A wedged or lying proxy is at least detectable after the fact; an
	// action that executed and was never recorded is not. A type whose invariants
	// span several of its own fields owns their synchronization; it cannot delegate
	// that to whoever calls it and still claim the invariants hold.
	mu               sync.Mutex
	enforcementPoint signer.Signer
	policy           policy.Evaluator
	// carriedPolicy is the concrete ruleset embedded in the export so the verifier
	// can re-derive consequentiality (F1); policyID is its content address, stamped
	// (hash-covered) into every entry. Non-nil whenever policy is an Option-B
	// *policy.Policy, which is the only evaluator the POC ships.
	carriedPolicy *policy.Policy
	policyID      string
	dids          did.Resolver
	status        export.StatusResolver
	log           *audit.Log
	set           *export.CredentialSet
	now           func() time.Time
	// sink, if non-nil, receives every appended audit entry as a forwarded
	// AuditRecord. It is a best-effort observability seam: a sink error never
	// changes a decision or discards the sealed entry, because the signed export
	// remains the system of record (see Handle).
	//
	// sinkSlots bounds how many sink writes may be in flight at once, so a slow or
	// hostile sink cannot backpressure enforcement or accumulate work without
	// limit (R2-03). Non-nil exactly when sink is.
	sink      auditsink.AuditSink
	sinkSlots chan struct{}
	// wal, if non-nil, is the durable write-ahead audit log. Unlike sink, it is on
	// the enforcement path and load-bearing: an entry is written here and fsynced
	// BEFORE it is committed and the decision returned (log-before-act), and a write
	// failure fails the decision closed. nil disables durability.
	wal *WAL
}

// Config assembles a Proxy.
type Config struct {
	EnforcementPoint signer.Signer
	Policy           policy.Evaluator
	DIDs             did.Resolver
	Status           export.StatusResolver
	// Now supplies entry timestamps; nil defaults to time.Now. Tests inject a
	// fixed clock for determinism.
	Now func() time.Time
	// Sink, if set, forwards each appended audit entry to an external destination
	// (local file, stdout, ...). Optional; nil disables forwarding.
	Sink auditsink.AuditSink
	// WAL, if set, makes the audit log durable: every entry (with its new evidence)
	// is written and fsynced before Handle returns, and the log is recovered from it
	// at startup. A write failure fails closed. Optional; nil disables durability.
	WAL *WAL
}

// NewProxy builds a proxy with an empty audit log and evidence set.
func NewProxy(c Config) (*Proxy, error) {
	if c.EnforcementPoint == nil {
		return nil, errors.New("proxy: enforcement point signer is required")
	}
	if c.Policy == nil {
		return nil, errors.New("proxy: policy evaluator is required")
	}
	if c.DIDs == nil {
		return nil, errors.New("proxy: DID resolver is required")
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	p := &Proxy{
		enforcementPoint: c.EnforcementPoint,
		policy:           c.Policy,
		dids:             c.DIDs,
		status:           c.Status,
		log:              audit.NewLog(c.EnforcementPoint),
		set:              export.NewCredentialSet(),
		now:              now,
		sink:             c.Sink,
		wal:              c.WAL,
	}
	if c.Sink != nil {
		p.sinkSlots = make(chan struct{}, sinkMaxInFlight)
	}
	// Carry the concrete policy so the verifier can re-derive consequentiality
	// (F1). The POC's only evaluator is the Option-B *policy.Policy; a future
	// OPA-backed evaluator would need its own carriage mechanism, and until it has
	// one the verifier would (correctly, fail-closed) reject allowed entries it
	// cannot re-derive.
	if pol, ok := c.Policy.(*policy.Policy); ok {
		id, err := export.PolicyID(pol)
		if err != nil {
			return nil, fmt.Errorf("proxy: content-address policy: %w", err)
		}
		p.carriedPolicy = pol
		p.policyID = id
	}
	// Recover any durable log at startup, AFTER policyID is known so the guard below
	// can run. This resumes the hash chain (and its seq/approval-position binding)
	// across a restart instead of starting a fresh, colliding log.
	if c.WAL != nil {
		if err := p.recoverFrom(c.WAL); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// recoverFrom rebuilds the proxy's log and evidence set from a durable WAL. It is
// fail-closed: LoadLog cryptographically verifies the recovered chain first (a
// tampered or truncated WAL is refused, not resumed), and then a continuity guard
// refuses to resume a log under a policy whose content-address differs from the one
// it was written under.
//
// On that guard's status, stated so it is not mistaken for more than it is: the
// signed-policy invariant is NOT enforced here. It is enforced, unbypassably, by the
// verifier, which re-derives the carried policy's content-address and rejects any
// allowed entry whose hash-covered PolicyID does not equal it ("policy substituted",
// export/verify.go). Recovery cannot steer that check. This guard is therefore
// defense-in-depth and an operator convenience, turning "resume, then emit an export
// the verifier rejects" into "refuse to start now, with a clear message".
//
// It is NOT a building block for hot-reloadable policy (§7 of the deployment note),
// and must not be extended into one. Its semantics are the opposite of what a reload
// needs (it REFUSES a differing policy rather than accepting a newly authorized one),
// and it encodes the current single-policy-per-export assumption, which is exactly
// the assumption a reload has to dismantle: because one export carries one policy and
// every entry must pin it, a log that spans two policies needs the export format and
// the verifier to carry multiple content-addressed policies and pin per entry. That
// is a format-and-verifier change, not a loader tweak, and it is where §7 must
// actually be designed. This guard's refusal to resume under a changed policy is that
// constraint surfacing, not a solution to it.
func (p *Proxy) recoverFrom(w *WAL) error {
	recs := w.Recovered()
	if len(recs) == 0 {
		return nil
	}
	entries := make([]audit.Entry, 0, len(recs))
	for _, r := range recs {
		entries = append(entries, r.Entry)
	}
	// Verify the chain BEFORE reading anything off the entries: the PolicyID the
	// continuity guard compares must be EP-signed material, not raw bytes off disk.
	log, err := audit.LoadLog(p.enforcementPoint, entries)
	if err != nil {
		return fmt.Errorf("proxy: recover audit log: %w", err)
	}
	for i, e := range entries {
		if e.PolicyID != "" && e.PolicyID != p.policyID {
			return fmt.Errorf("proxy: WAL entry %d was written under policy %s but this proxy loaded %s; refusing to resume (would produce an inconsistent export)", i, e.PolicyID, p.policyID)
		}
	}
	p.log = log
	for _, r := range recs {
		for _, cr := range r.Credentials {
			if _, err := p.set.Add(cr.Credential, cr.IssuerProof); err != nil {
				return fmt.Errorf("proxy: recover evidence: %w", err)
			}
		}
	}
	return nil
}

// Request is one action attempt arriving at the chokepoint. Its JSON form is the
// wire protocol between the agent and an HTTP proxy, the same struct crosses the
// process boundary unchanged, so there is no second request type to keep in sync.
type Request struct {
	// Chain is the delegation chain presented by the caller, root -> actor.
	Chain *chain.Chain `json:"chain"`
	// Action is what the actor wants to do.
	Action types.Action `json:"action"`
	// PoP is the actor's proof it controls the terminal credential's holder key.
	PoP credential.PoP `json:"pop"`
	// Approver / Approval carry a human's approval token, required for
	// consequential actions. Empty for routine ones.
	Approver types.DID `json:"approver,omitempty"`
	Approval []byte    `json:"approval,omitempty"`
}

// Result is the enforcement outcome for a request. Every allowed OR denied
// request that got far enough to be attributable produces an audit Entry; a
// malformed request that cannot even be logged returns an error and no entry.
type Result struct {
	Decision types.Decision `json:"decision"`
	Entry    *audit.Entry   `json:"entry"`
}

// Handle runs the full enforcement pipeline for one request and appends exactly
// one audit entry describing the outcome (allow or deny). It returns an error
// only when the request is too malformed to attribute, in which case nothing is
// logged, because an unverifiable chain in an entry would read to the verifier as
// verifier failure, not as a decision.
func (p *Proxy) Handle(req Request) (*Result, error) {
	if req.Chain == nil || len(req.Chain.Links) == 0 {
		return nil, errors.New("proxy: request has no delegation chain")
	}

	// Gate 0 (pre-log): the chain must verify against public DID docs. This is
	// what the verifier's steps 3-4 will re-derive; if it does not hold, the
	// request is not attributable and must not be logged at all.
	if err := req.Chain.Verify(p.dids); err != nil {
		return nil, fmt.Errorf("proxy: unattributable chain: %w", err)
	}

	entry, dec, err := p.decideAndAppend(req)
	if err != nil {
		return nil, err
	}

	// Forward the sealed entry to the configured sink, AFTER the lock is released
	// (R2-03). Best-effort by design: the entry is already committed to the signed,
	// hash-chained log (the system of record), so a forwarding failure must neither
	// undo the decision nor drop the entry. Delivery guarantees are explicitly out
	// of scope for this seam; a sink that needs them owns that responsibility.
	p.forward(&entry)
	return &Result{Decision: dec, Entry: &entry}, nil
}

// decideAndAppend is Handle's critical section: read the tip, decide against it,
// and seal the entry at exactly that position, with nothing able to interleave.
//
// Tip and Append must be one atomic step, not two. The PoP and approval the
// caller presents are bound to the position the entry will occupy, so a decision
// made against a tip that has moved by the time Append runs is a decision made
// against evidence for a slot the entry does not land in (R2-04).
func (p *Proxy) decideAndAppend(req Request) (audit.Entry, types.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	principals := req.Chain.Principals()
	// Compute the chain's credential IDs and which of them are NEW, without yet
	// committing them to the evidence set: nothing about this decision, evidence
	// included, is admitted until the entry is durable.
	newCreds, credIDs, err := p.evidenceFor(req.Chain)
	if err != nil {
		return audit.Entry{}, types.Decision{}, err
	}
	terminal := &req.Chain.Links[len(req.Chain.Links)-1].Credential

	// The proof-of-possession and approval this request carries are bound to the
	// position the resulting entry will occupy, its Seq and PrevHash (F4, R2-04).
	// Read the tip before deciding, so the same position the caller signed over is
	// the one we verify against and the one the entry seals.
	seq, prevHash := p.log.Tip()

	// From here every path produces an entry. deny() and allow() below fill in
	// the Decision; the entry is sealed, made durable, then committed, once.
	dec, popRecorded := p.decide(req, terminal, seq, prevHash)

	rec := audit.EntryDraft{
		Action:             req.Action,
		ResolvedChain:      principals,
		ChainCredentialIDs: credIDs,
		Decision:           dec,
		PolicyID:           p.policyID,
		Timestamp:          p.now().UTC(),
	}
	// Evidence is recorded whenever it was actually produced/consumed, so a denial
	// still carries the PoP and approval that were checked. (The verifier only
	// *requires* them on allows, but recording them on denials keeps the log a
	// faithful account of what was authorized.)
	if popRecorded {
		rec.PoPNonce = req.PoP.Nonce
		rec.PoPSignature = req.PoP.Signature
	}
	if len(req.Approval) > 0 {
		rec.ApprovedBy = req.Approver
		rec.Approval = req.Approval
	}

	// Log-before-act, in three steps under the lock:
	//   1. Seal the entry (hash + sign) WITHOUT committing it.
	//   2. If durability is enabled, write it and its new evidence to the WAL and
	//      fsync. Fail-closed: a durable-write failure refuses the decision here,
	//      before anything is committed, so nothing is admitted, no in-memory entry,
	//      no evidence, and above all no ALLOW returned, against a record that would
	//      vanish on the next crash.
	//   3. Only once the record is durable (or durability is off) commit the entry
	//      to the chain and its evidence to the set.
	entry, err := p.log.Seal(rec)
	if err != nil {
		return audit.Entry{}, types.Decision{}, fmt.Errorf("proxy: seal audit entry: %w", err)
	}
	if p.wal != nil {
		if err := p.wal.Append(entry, newCreds); err != nil {
			return audit.Entry{}, types.Decision{}, fmt.Errorf("proxy: durable audit write failed, refusing action (fail-closed): %w", err)
		}
	}
	if err := p.log.Commit(entry); err != nil {
		return audit.Entry{}, types.Decision{}, fmt.Errorf("proxy: commit audit entry: %w", err)
	}
	for _, cr := range newCreds {
		if _, err := p.set.Add(cr.Credential, cr.IssuerProof); err != nil {
			return audit.Entry{}, types.Decision{}, fmt.Errorf("proxy: record evidence: %w", err)
		}
	}
	return entry, dec, nil
}

// sinkMaxInFlight caps how many sink writes may be outstanding at once. It is
// the "bounded" in bounded dispatch: a sink that blocks forever costs at most
// this many parked goroutines, after which records are dropped rather than
// queued, so a hostile plugin cannot turn the enforcement path into an unbounded
// buffer. 64 is comfortably more than any realistic burst against a sink doing
// local I/O, and small enough that saturation is a bounded resource cost.
const sinkMaxInFlight = 64

// forward hands a sealed entry to the sink, isolated three ways (R2-03).
//
// auditsink is a DESIGNATED PLUGIN INTERFACE, licensed permissively precisely so
// third parties will implement it. That makes "a sink cannot affect the path that
// calls it" a boundary, not a nicety, and the AUTHORITY half of it was already
// true: the sink runs after the entry is sealed, sees no credentials or keys, and
// its return value is discarded. The LIVENESS half was not. A sink that panicked
// escaped through Handle and, with the transport's mutex held and no deferred
// unlock, wedged every later request forever. A sink that merely blocked, a full
// pipe, a stalled network share, stalled the whole chokepoint for as long as it
// blocked, because Write ran synchronously inside the decision path.
//
// The three isolations, all matching the seam's stated best-effort/additive
// intent rather than inventing a stronger one:
//
//   - Off the enforcement lock. The entry is already sealed; the sink has nothing
//     to say about it.
//   - Off the request goroutine, into a bounded pool. A sink that blocks now
//     delays nothing at all: not the chokepoint, not even the request it was
//     attached to. Saturating the pool drops records, which is the correct
//     failure for a best-effort seam, losing observability is survivable, losing
//     availability of enforcement is not.
//   - recover() at the call boundary. A panicking sink fails to record and
//     nothing else. It must not fail the request it is attached to, because the
//     decision was already made: letting an observability plugin deny an action
//     is precisely the direction this seam must never run in.
//
// What this costs, stated rather than glossed: delivery is now lossy under
// saturation, and concurrent requests may reach the sink out of order. Both are
// acceptable because the signed export is the system of record and the sink is
// not; records carry Seq and EntryHash so a consumer can reorder and reconcile
// against it. Callers that need every record before exit call FlushSink.
func (p *Proxy) forward(e *audit.Entry) {
	if p.sink == nil {
		return
	}
	rec := auditRecord(e)
	select {
	case p.sinkSlots <- struct{}{}:
	default:
		return // saturated: drop rather than block enforcement
	}
	go func() {
		defer func() {
			<-p.sinkSlots
			// A panicking sink is a broken plugin, not a broken decision. Swallow it
			// exactly as a returned error is swallowed: best-effort means best-effort.
			_ = recover()
		}()
		_ = p.sink.Write(rec)
	}()
}

// FlushSink waits for outstanding sink writes to finish, up to timeout. It
// reports whether the sink drained; false means at least one write is still
// outstanding, which for a hostile or hung sink is the expected answer and the
// reason this takes a timeout instead of blocking.
//
// Sink dispatch is asynchronous (see forward), so a process that exits right
// after its last decision would otherwise lose records that were merely in
// flight. Call this before closing the sink. It is not a delivery guarantee,
// nothing here is, it is the difference between "dropped because we exited" and
// "dropped because the sink could not keep up".
func (p *Proxy) FlushSink(timeout time.Duration) bool {
	if p.sink == nil {
		return true
	}
	deadline := time.After(timeout)
	held := 0
	defer func() {
		for range held {
			<-p.sinkSlots
		}
	}()
	// Acquiring every slot means no writer holds one, so none is in flight.
	for held < cap(p.sinkSlots) {
		select {
		case p.sinkSlots <- struct{}{}:
			held++
		case <-deadline:
			return false
		}
	}
	return true
}

// auditRecord projects a sealed audit entry onto the license-clean AuditRecord a
// sink consumes. The projection lives here (not in auditsink) so that package can
// stay free of any core dependency, the plugin seam only ever depends on stdlib.
func auditRecord(e *audit.Entry) auditsink.AuditRecord {
	actor := ""
	if n := len(e.ResolvedChain); n > 0 {
		actor = string(e.ResolvedChain[n-1])
	}
	return auditsink.AuditRecord{
		Seq:           e.Seq,
		Timestamp:     e.Timestamp,
		Actor:         actor,
		ActionType:    e.Action.Type,
		ActionTarget:  e.Action.Target,
		Allowed:       e.Decision.Allowed,
		Consequential: e.Decision.Consequential,
		Reason:        e.Decision.Reason,
		EntryHash:     e.EntryHash,
	}
}

// decide is the pure composition. It returns the Decision and whether a PoP was
// consumed (so the caller records it). It NEVER sets Allowed:true without having
// passed every applicable check.
func (p *Proxy) decide(req Request, terminal *credential.Credential, seq uint64, prevHash []byte) (types.Decision, bool) {
	// Policy classifies: consequential? denied by a rule?
	dec, err := p.policy.Evaluate(req.Action)
	if err != nil {
		return deny(dec, "policy evaluation failed: "+err.Error()), false
	}
	if !dec.Allowed {
		// A policy hard-deny (e.g. forbidden-wire). Authority was never consulted.
		return dec, false
	}

	// Authority: the action must satisfy the terminal credential's caveats. The
	// context is built by the SAME types.Action.Context() the verifier uses, so
	// enforcement and verification cannot disagree.
	ctx := macaroon.Context(req.Action.Context())
	for k, v := range terminal.HolderContext() {
		ctx[k] = v
	}
	if err := macaroon.Satisfies(terminal.Macaroon, ctx); err != nil {
		return deny(dec, "action exceeds delegated authority: "+err.Error()), false
	}

	// Consequential actions demand a live status check (no revoked hop) AND a
	// human approval, one knob, two jobs (§10).
	if dec.Consequential {
		if p.status == nil {
			return deny(dec, "consequential action requires a status check, but no status source is configured"), false
		}
		revoked, where, checked, err := p.anyHopRevoked(req.Chain)
		if err != nil {
			return deny(dec, "status check failed: "+err.Error()), false
		}
		// Record how many hops were ACTUALLY checked, not that checking happened.
		// The old boolean was set here unconditionally and was therefore true even
		// when the sweep examined zero hops (R2-01); a count the verifier can
		// re-derive from the credential evidence cannot be vacuous.
		dec.StatusCheckedHops = checked
		if revoked {
			return deny(dec, "credential revoked: "+where), false
		}
		if err := p.verifyApproval(req, terminal.Subject, seq, prevHash); err != nil {
			return deny(dec, err.Error()), false
		}
	}

	// Possession: the caller must control the terminal holder key. Required for
	// every allow (routine or consequential): a copied credential fails here.
	if err := terminal.VerifyPossession(req.PoP, req.Action, seq, prevHash); err != nil {
		return deny(dec, "proof of possession failed: "+err.Error()), true
	}

	dec.Allowed = true
	if dec.Reason == "" {
		dec.Reason = "within delegated authority"
	}
	return dec, true
}

// verifyApproval requires and checks a human approval token for a consequential
// action.
func (p *Proxy) verifyApproval(req Request, actor types.DID, seq uint64, prevHash []byte) error {
	if req.Approver == "" || len(req.Approval) == 0 {
		return errors.New("consequential action requires human approval, none presented")
	}
	key, err := did.ResolveKey(p.dids, req.Approver)
	if err != nil {
		return fmt.Errorf("resolve approver %q: %w", req.Approver, err)
	}
	if err := audit.VerifyApproval(key, actor, req.Action, seq, prevHash, req.Approval); err != nil {
		return err
	}
	return nil
}

// anyHopRevoked performs the live status check across every hop that carries a
// StatusRef (S2). It returns which hop, if any, is revoked, and (crucially)
// how many hops it actually resolved and verified a signed list for. That count
// becomes Decision.StatusCheckedHops, which the verifier re-derives from the same
// evidence (R2-01). A hop whose StatusRef is empty publishes no revocation list
// and is not counted: it is skipped honestly, and the verifier says so in its
// output rather than letting the skip disappear into a true boolean.
func (p *Proxy) anyHopRevoked(ch *chain.Chain) (revoked bool, where string, checked int, err error) {
	for i := range ch.Links {
		c := &ch.Links[i].Credential
		if c.StatusRef.ListURL == "" {
			continue
		}
		list, err := p.status.ResolveStatus(c.StatusRef.ListURL)
		if err != nil {
			return false, "", checked, err
		}
		key, err := did.ResolveKey(p.dids, list.Issuer)
		if err != nil {
			return false, "", checked, fmt.Errorf("resolve status issuer %q: %w", list.Issuer, err)
		}
		if err := list.Verify(key); err != nil {
			return false, "", checked, err
		}
		isRevoked, err := list.Lookup(c.StatusRef.Index)
		if err != nil {
			return false, "", checked, err
		}
		checked++
		if isRevoked {
			return true, fmt.Sprintf("hop %d (%s -> %s) at index %d", i, c.Issuer, c.Subject, c.StatusRef.Index), checked, nil
		}
	}
	return false, "", checked, nil
}

// evidenceFor computes a chain's per-hop credential IDs (in ResolvedChain order)
// and the subset of credentials NOT already in the evidence set, WITHOUT mutating
// the set. The caller commits the new credentials only after the entry is durable,
// so evidence and the entry it belongs to are admitted together or not at all.
// Credentials already recorded by an earlier entry are omitted from newCreds, so
// the durable log does not re-store a chain's credentials on every request.
func (p *Proxy) evidenceFor(ch *chain.Chain) (newCreds []export.CredentialRecord, ids []string, err error) {
	ids = make([]string, 0, len(ch.Links))
	seen := make(map[string]bool)
	for i := range ch.Links {
		l := ch.Links[i]
		id, err := export.CredentialID(&l.Credential)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy: record hop %d evidence: %w", i, err)
		}
		ids = append(ids, id)
		if !p.set.Has(id) && !seen[id] {
			seen[id] = true
			newCreds = append(newCreds, export.CredentialRecord{CredentialID: id, Credential: l.Credential, IssuerProof: l.IssuerProof})
		}
	}
	return newCreds, ids, nil
}

// Export builds the audit export from everything the proxy has enforced,
// including the carried policy and the enforcement point's envelope signature.
func (p *Proxy) Export() (*export.Export, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return export.Build(p.enforcementPoint, p.log.Entries(), p.set, p.carriedPolicy)
}

// Entries returns a copy of the audit entries appended so far.
func (p *Proxy) Entries() []audit.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.Entries()
}

// Tip reports the position the next entry will occupy: its Seq and the PrevHash
// it will link to. A caller reads it before signing a proof-of-possession or
// approval so the signature binds to that exact chain slot (F4). Over HTTP this
// is served by GET /tip.
//
// PrevHash is part of the reported position, and was not before (R2-04): the
// doc comments on audit.Log.Tip and on GET /tip both claimed the evidence
// committed to Seq+PrevHash while only Seq was ever bound or even carried.
func (p *Proxy) Tip() Tip {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq, prevHash := p.log.Tip()
	return Tip{Seq: seq, PrevHash: prevHash}
}

// Tip is the position the next appended entry will occupy.
//
// Reading a tip and acting on it is inherently advisory: another request can land
// in that slot first, and then the evidence bound to it no longer matches. That is
// correct and fail-closed, the proxy verifies the PoP and approval against the
// position the entry ACTUALLY lands in, inside the same critical section as the
// append, so a caller whose slot was taken is denied rather than squeezed in.
type Tip struct {
	Seq      uint64 `json:"seq"`
	PrevHash []byte `json:"prevHash"`
}

// StatusResolver exposes the proxy's status source (used by the CLI to publish
// a static resolver from files).
func (p *Proxy) StatusResolver() export.StatusResolver { return p.status }

// deny stamps a Decision as denied with a reason, preserving the policy
// classification fields already set.
func deny(dec types.Decision, reason string) types.Decision {
	dec.Allowed = false
	dec.Reason = reason
	return dec
}
