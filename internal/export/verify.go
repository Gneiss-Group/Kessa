// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"crypto"
	"fmt"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// WhatIsProven states, precisely, the claim a clean verdict supports. It is
// deliberately narrow: overstating it would be a lie, and this is trust
// infrastructure.
const WhatIsProven = "For every ALLOWED action: it was within the delegated authority (caveats " +
	"satisfied against the recorded action); the issuance chain is valid, reproduces the recorded " +
	"principals, and covers each credential IN FULL, so no field of a presented credential differs " +
	"from what its issuer signed; holder possession was proven (bound to the action and entry " +
	"position); consequentiality, the rule that fired, and the policy version were all RE-DERIVED " +
	"from the export's carried, signed policy and match the entry's own claims; and if that " +
	"re-derivation says the action is consequential, every hop whose issuer published a status list " +
	"was checked, none is currently revoked, and a valid human approval (bound to the action and " +
	"entry position) was obtained. The export's version, signer, policy identity, ENTRY COUNT and " +
	"LOG TIP are covered by the enforcement point's envelope signature, so entries cannot be removed " +
	"from a signed export after the fact."

// KnownCaveats are the limits of the above claim, surfaced in verifier output.
// They are deliberate POC decisions, not oversights.
var KnownCaveats = []string{
	// R2-05. This one is first because it conditions every other line of output:
	// a reader who takes the verdict at face value without knowing where the keys
	// came from has misunderstood what the tool did, not merely missed a detail.
	"The verdict is RELATIVE TO THE DID DOCUMENTS YOU SUPPLIED. Every signature this tool checks is " +
		"checked against a key read from --dids (or fetched with --fetch-dids). That directory is the " +
		"trust root and its provenance is YOUR problem: a fully fabricated export passes clean when the " +
		"DID documents it names are fabricated to match. This is by design: anchoring to a Kessa " +
		"service would defeat the point, but it means a PASS says 'consistent with these keys', not " +
		"'genuine'. If the export and the DID documents came from the same party, you have verified " +
		"that party's internal consistency and nothing more. Obtain the DID documents independently.",
	"Consequentiality is re-derived from the policy CARRIED in the export (F1), not trusted as a bare " +
		"bit, but that policy is an environment-defined, disclosed artifact. The verifier proves the " +
		"allows are consistent with the policy the enforcement point published and signed; it cannot " +
		"prove that policy is the 'right' one for the environment. Inspect the carried policy to judge that.",
	"Status is checked against the CURRENT status list, not the list as of action time (S1, deferred). " +
		"Re-verifying an old export after a later revocation will flip previously-legitimate entries " +
		"PASS -> FAIL.",
	// R2-02, stated as a limit rather than left implied by the fix.
	"COMPLETENESS is bounded. The envelope signature covers the entry count and log tip, so nobody can " +
		"shorten a signed export after the fact (R2-02). It does not prove the enforcement point logged " +
		"everything it decided: a short log signed honestly and a short log signed by a proxy that " +
		"declined to record something are indistinguishable from the file alone. Detecting that needs " +
		"the tip anchored somewhere the enforcement point does not control, which this tool does not do.",
	"Denials are not independently re-derivable. A denial can stem from policy, so a denied entry " +
		"PASSes when its hash, signature, and chain evidence are intact.",
	"The recorded action is what the caller ASSERTED it was about to do. Nothing binds an audit entry " +
		"to a tool call that actually executed, so this proves what was authorized, not what happened.",
}

// Outcome is the per-entry verdict.
type Outcome string

const (
	OutcomePass          Outcome = "PASS"
	OutcomePassDeny      Outcome = "PASS (deny: evidence intact)"
	OutcomeIntegrityOnly Outcome = "PASS (integrity-only, no evidence, NOT an evidence-backed pass)"
	OutcomeFail          Outcome = "FAIL"
	OutcomeUnverified    Outcome = "UNVERIFIED (hash chain broken at an earlier entry)"
)

// EntryResult is the verdict for one audit entry.
type EntryResult struct {
	Seq     uint64
	Outcome Outcome
	Reason  string
	Chain   []types.DID // the chain re-resolved from evidence (nil if not reached)
	// Limitations are things this entry's PASS does NOT establish, stated per
	// entry rather than left to the reader. A hop that publishes no revocation
	// list is the motivating case (R2-01): the verifier cannot check what the
	// issuer never made checkable, and silently skipping it produced a clean PASS
	// whose revocation claim was empty. A limitation is not a failure; it is the
	// part of the claim that is missing, printed alongside the part that holds.
	Limitations []string
}

// Result is the whole-export verdict.
type Result struct {
	Version         string
	EvidenceCarried bool // false for v1 envelopes: integrity only, authority NOT re-derivable
	// FatalReason, when non-empty, is a whole-export failure that precedes any
	// per-entry verdict: a bad envelope signature (version/signer/policy tampered).
	// It is security-relevant and is surfaced regardless of --quiet.
	FatalReason string
	Entries     []EntryResult
}

// Pass reports whether the export is a full, evidence-backed clean pass. It is
// deliberately strict on two counts beyond "no entry failed":
//
//   - A fatal envelope error (version/signer/policy tampering) never passes.
//   - A v1 (integrity-only) export never returns a clean pass. Integrity is not
//     authority; presenting an integrity-only check as a clean PASS is exactly the
//     downgrade F2 closes. A v1 export therefore reports a distinct verdict and a
//     non-zero exit, never a bare PASS a caller could mistake for evidence-backed.
func (r *Result) Pass() bool {
	if r.FatalReason != "" || !r.EvidenceCarried {
		return false
	}
	for _, e := range r.Entries {
		if e.Outcome == OutcomeFail || e.Outcome == OutcomeUnverified {
			return false
		}
	}
	return true
}

// StatusResolver maps a credential's published status-list URL to the signed
// list. A local-file implementation is the default (self-hostable first); an
// HTTPS fetch of the public list is an acceptable alternative.
type StatusResolver interface {
	ResolveStatus(listURL string) (*status.StatusList, error)
}

// MapStatusResolver resolves status lists from an in-memory map, keyed by URL.
type MapStatusResolver map[string]*status.StatusList

func (m MapStatusResolver) ResolveStatus(listURL string) (*status.StatusList, error) {
	l, ok := m[listURL]
	if !ok {
		return nil, fmt.Errorf("no status list provided for %q", listURL)
	}
	return l, nil
}

// Inputs are everything the verifier is allowed to consult: public DID documents
// and published status lists. Nothing of ours as a trusted service.
type Inputs struct {
	DIDs   did.Resolver
	Status StatusResolver
}

// Verify runs §4's per-entry checks and returns a structured verdict.
//
// Checks 1-2 (hash chain, entry signature) run on every entry. A break in the
// hash chain is terminal: entries after it cannot be trusted and are reported
// UNVERIFIED rather than PASS.
//
// Checks 3-4 (evidence lookup, chain re-resolution) run on every entry of a v2
// export.
//
// Checks 5-7 (caveat satisfaction, revocation, proof-of-possession) run ONLY for
// entries whose Decision.Allowed is true. This is not a shortcut, it is the
// correct semantics. A correct denial is *proven* by exactly one of these checks
// failing: a scope-exceeded action has unsatisfiable caveats, a revoked
// credential is revoked, a loaned credential cannot answer the PoP challenge.
// Running 5-7 unconditionally would make "correctly denied" and "verifier
// failure" indistinguishable, and would fail the enforcement point for doing its
// job. What the verifier proves is that every ALLOW was justified.
func Verify(exp *Export, in Inputs) (*Result, error) {
	res := &Result{Version: exp.Version, EvidenceCarried: !exp.IsV1()}

	// The enforcement point's key, resolved from its published DID document.
	signerKey, err := did.ResolveKey(in.DIDs, exp.Signer)
	if err != nil {
		return nil, fmt.Errorf("export: resolve enforcement point %q: %w", exp.Signer, err)
	}

	// F2: for a v2 export, the envelope signature over {version, signer, policyID}
	// must verify before any entry is trusted. This is what makes the format
	// version (and thus which verdict rules apply) tamper-evident. A v1 export
	// carries no such signature; its downgrade is closed instead by never
	// returning a clean pass (see Pass and verifyEntry).
	if !exp.IsV1() {
		if err := verifyEnvelope(exp, signerKey); err != nil {
			res.FatalReason = err.Error()
			return res, nil
		}
	}

	// Steps 1-2, in bulk: hash chain + entry signatures.
	failIdx, chainErr := audit.VerifyEntries(exp.Entries, signerKey)

	for i := range exp.Entries {
		e := &exp.Entries[i]
		switch {
		case failIdx >= 0 && i == failIdx:
			res.Entries = append(res.Entries, EntryResult{Seq: e.Seq, Outcome: OutcomeFail, Reason: chainErr.Error()})
			continue
		case failIdx >= 0 && i > failIdx:
			res.Entries = append(res.Entries, EntryResult{Seq: e.Seq, Outcome: OutcomeUnverified,
				Reason: fmt.Sprintf("hash chain broke at entry %d; nothing after it can be trusted", failIdx)})
			continue
		}
		res.Entries = append(res.Entries, verifyEntry(exp, e, in))
	}
	return res, nil
}

// verifyEntry runs steps 3-7 for one integrity-verified entry.
func verifyEntry(exp *Export, e *audit.Entry, in Inputs) EntryResult {
	fail := func(format string, a ...any) EntryResult {
		return EntryResult{Seq: e.Seq, Outcome: OutcomeFail, Reason: fmt.Sprintf(format, a...)}
	}

	// A v1 entry carries no evidence. Integrity is all we can assert, and an
	// integrity-only result is explicitly NOT a clean evidence-backed pass, see
	// OutcomeIntegrityOnly and Pass. Saying so, with a non-zero overall exit, is
	// what stops a v2 export from being relabelled v1 to win a false clean pass (F2).
	if exp.IsV1() {
		return EntryResult{Seq: e.Seq, Outcome: OutcomeIntegrityOnly,
			Reason: "integrity verified; v1 export carries no evidence, authority NOT re-derived", Chain: e.ResolvedChain}
	}

	// Evidence must be PRESENT. Because the evidence fields are omitempty, a
	// producer can simply omit them; treating absence as "nothing to check" would
	// make omission a free pass. Absence is a failure.
	if len(e.ResolvedChain) < 2 {
		return fail("entry records a chain of %d principals; expected at least 2", len(e.ResolvedChain))
	}
	if want := len(e.ResolvedChain) - 1; len(e.ChainCredentialIDs) != want {
		return fail("entry carries %d credential IDs for a %d-principal chain; expected %d (evidence withheld?)",
			len(e.ChainCredentialIDs), len(e.ResolvedChain), want)
	}

	// Step 3: look up each hop's credential and self-check its content address.
	links := make([]chain.Link, 0, len(e.ChainCredentialIDs))
	for hop, id := range e.ChainCredentialIDs {
		rec, ok := exp.Credentials[id]
		if !ok {
			return fail("hop %d references credential %q, which is missing from the export's credential set", hop, id)
		}
		if rec.CredentialID != id {
			return fail("hop %d: credential record's own ID %q does not match its map key %q", hop, rec.CredentialID, id)
		}
		got, err := CredentialID(&rec.Credential)
		if err != nil {
			return fail("hop %d: %v", hop, err)
		}
		if got != id {
			return fail("hop %d: credential content hash %q does not match its ID %q (evidence substituted)", hop, got, id)
		}
		links = append(links, chain.Link{Credential: rec.Credential, IssuerProof: rec.IssuerProof})
	}

	// Step 4: re-resolve the delegation chain from the evidence, and confirm it
	// reproduces exactly the principals the entry claims.
	resolved := &chain.Chain{Links: links}
	if err := resolved.Verify(in.DIDs); err != nil {
		return fail("delegation chain does not verify: %v", err)
	}
	principals := resolved.Principals()
	if len(principals) != len(e.ResolvedChain) {
		return fail("re-resolved chain has %d principals; entry records %d", len(principals), len(e.ResolvedChain))
	}
	for i := range principals {
		if principals[i] != e.ResolvedChain[i] {
			return fail("re-resolved chain differs at position %d: evidence says %q, entry records %q",
				i, principals[i], e.ResolvedChain[i])
		}
	}

	// Steps 5-7 assert that every ALLOW was justified. A denial is proven by one
	// of them failing, so running them here would invert their meaning.
	if !e.Decision.Allowed {
		return EntryResult{Seq: e.Seq, Outcome: OutcomePassDeny,
			Reason: fmt.Sprintf("action was denied (%q); hash, signature, and chain evidence intact", e.Decision.Reason),
			Chain:  principals}
	}

	terminal := &links[len(links)-1].Credential

	// Step 4.5 (F1): re-derive consequentiality from the carried, pinned policy,
	// never trust the entry's asserted `consequential` bit. A lying proxy that
	// marks a genuinely consequential action non-consequential would otherwise skip
	// the revocation sweep AND the approval requirement. The carried policy is
	// content-addressed and pinned by the entry's hash-covered PolicyID, so a proxy
	// cannot swap in a permissive policy after the fact.
	if exp.Policy == nil {
		return fail("action was ALLOWED but the export carries no policy to re-derive consequentiality from (evidence withheld?)")
	}
	wantPID, err := PolicyID(exp.Policy)
	if err != nil {
		return fail("cannot content-address the carried policy: %v", err)
	}
	if e.PolicyID == "" {
		return fail("action was ALLOWED but the entry pins no policy id (evidence withheld?)")
	}
	if e.PolicyID != wantPID {
		return fail("entry pins policy %q but the carried policy hashes to %q (policy substituted)", e.PolicyID, wantPID)
	}
	derived, err := exp.Policy.Evaluate(e.Action)
	if err != nil {
		return fail("policy re-derivation failed: %v", err)
	}
	// A policy hard-deny that the proxy allowed anyway is a straight violation.
	if !derived.Allowed {
		return fail("action was ALLOWED but the carried policy denies it (rule %q)", derived.RuleFired)
	}
	// The proxy's asserted bit must match what the policy derives. A mismatch, in
	// either direction, means the entry was misclassified (by bug or malice) and
	// is not trustworthy.
	if derived.Consequential != e.Decision.Consequential {
		return fail("consequentiality mismatch: entry asserts consequential=%t but the carried policy derives %t (misclassified)",
			e.Decision.Consequential, derived.Consequential)
	}
	// R2-07: the attribution fields are re-derived too. They are hash-covered and
	// signed, so they cannot be edited after the fact, but signed is not the same
	// as true, and nothing stopped the enforcement point from recording a decision
	// attributed to a rule that never fired. That cannot produce an unjustified
	// allow (the security-relevant bit above is re-derived), but it can produce an
	// audit trail whose stated REASON is false while the verdict verifies clean.
	// Re-deriving where derivation is possible is the second half of the round-1
	// rule, and it is possible here.
	if derived.RuleFired != e.Decision.RuleFired {
		return fail("rule attribution mismatch: entry records rule %q but the carried policy fires %q",
			e.Decision.RuleFired, derived.RuleFired)
	}
	if derived.PolicyVersion != e.Decision.PolicyVersion {
		return fail("policy version mismatch: entry records %q but the carried policy declares %q",
			e.Decision.PolicyVersion, derived.PolicyVersion)
	}
	consequential := derived.Consequential

	// Step 5: the recorded action must actually satisfy the terminal credential's
	// caveats. The terminal macaroon carries the full accumulated caveat set,
	// because every hop Extends its parent.
	ctx := macaroon.Context(e.Action.Context())
	// The holder caveat, if any, is satisfied from the credential's own bound key.
	// That is tautological here by design: real holder binding comes from the
	// issuance signature over HolderKey, the subject-DID-key match in chain.Verify,
	// and the proof-of-possession check in step 7 below.
	for k, v := range terminal.HolderContext() {
		ctx[k] = v
	}
	if err := macaroon.Satisfies(terminal.Macaroon, ctx); err != nil {
		return fail("action was ALLOWED but exceeds the delegated authority: %v", err)
	}

	// Step 6: consequential actions must have had a status check, and no hop may
	// be revoked. Every hop carrying a StatusRef is checked (S2): a mid-chain
	// revocation is just as fatal as revoking the actor's own credential. The
	// gate is the verifier-DERIVED consequentiality (F1), not the entry's bit.
	var limitations []string
	if consequential {
		// How many hops SHOULD have been checked is re-derived from the evidence,
		// not read off the entry (R2-01). Each hop's StatusRef now sits inside the
		// issuance signature, so "this hop publishes a revocation list" is an
		// issuer-signed fact the holder cannot edit, and the count of such hops is
		// something the verifier computes for itself.
		want := 0
		for hop := range links {
			if links[hop].Credential.StatusRef.ListURL != "" {
				want++
			}
		}
		if e.Decision.StatusCheckedHops != want {
			return fail("action was ALLOWED and consequential, but the entry records %d status-checked hop(s) where the signed evidence requires %d",
				e.Decision.StatusCheckedHops, want)
		}
		for hop := range links {
			c := &links[hop].Credential
			if c.StatusRef.ListURL == "" {
				continue // this hop publishes no revocation list
			}
			revoked, err := hopRevoked(c, in)
			if err != nil {
				return fail("hop %d (%s): %v", hop, c.Subject, err)
			}
			if revoked {
				return fail("action was ALLOWED but hop %d's credential (%s -> %s) is revoked at index %d",
					hop, c.Issuer, c.Subject, c.StatusRef.Index)
			}
		}
		// An issuer may mint a hop with no StatusRef at all (the issuer spec makes
		// statusIndex a per-hop option), and such a credential is permanently
		// unrevocable. That is the issuer's choice to make, not a verification
		// failure, but it must not vanish. Before this was surfaced, a chain whose
		// every hop lacked a StatusRef produced a clean PASS whose revocation claim
		// covered nothing at all, with no signal anywhere in the output.
		if skipped := len(links) - want; skipped > 0 {
			limitations = append(limitations, fmt.Sprintf(
				"revocation NOT checkable for %d of %d hops: those credentials carry no status list reference, so their issuer published no way to revoke them",
				skipped, len(links)))
		}
	}

	// Step 7: proof of possession. The recorded nonce must have been signed by the
	// holder key bound in the terminal credential.
	if len(e.PoPNonce) == 0 || len(e.PoPSignature) == 0 {
		return fail("action was ALLOWED but carries no proof of possession (evidence withheld?)")
	}
	// The PoP is re-checked against the entry's own action and position, Seq and
	// PrevHash, both hash-covered, so a proof captured for one action, one slot,
	// or one log cannot be replayed onto a fabricated entry (F3/F4, R2-04).
	if err := terminal.VerifyPossession(credential.PoP{Nonce: e.PoPNonce, Signature: e.PoPSignature}, e.Action, e.Seq, e.PrevHash); err != nil {
		return fail("proof of possession failed: %v", err)
	}

	// Step 8: human approval. A consequential allow MUST carry a valid human
	// approval, symmetric with the status and proof-of-possession requirements,
	// and matching what the enforcement proxy enforces. Because ApprovedBy and
	// Approval are omitempty, absence is treated as withheld evidence and fails,
	// never as a skip. A non-consequential allow need not carry approval, but any
	// approval it does carry is still verified.
	if consequential && (e.ApprovedBy == "" || len(e.Approval) == 0) {
		return fail("action was ALLOWED and consequential, but carries no human approval (evidence withheld?)")
	}
	if e.ApprovedBy != "" || len(e.Approval) > 0 {
		if e.ApprovedBy == "" || len(e.Approval) == 0 {
			return fail("action carries a partial approval (approver or signature missing)")
		}
		approverKey, err := did.ResolveKey(in.DIDs, e.ApprovedBy)
		if err != nil {
			return fail("resolve approver %q: %v", e.ApprovedBy, err)
		}
		// Bound to the entry's own action and position (Seq + PrevHash), so an
		// approval cannot be lifted from one entry onto a sibling, a later append,
		// or the same slot number in a different log (F4, R2-04).
		if err := audit.VerifyApproval(approverKey, terminal.Subject, e.Action, e.Seq, e.PrevHash, e.Approval); err != nil {
			return fail("recorded approval does not verify: %v", err)
		}
	}

	return EntryResult{Seq: e.Seq, Outcome: OutcomePass, Reason: "allow justified by evidence",
		Chain: principals, Limitations: limitations}
}

// verifyEnvelope checks the enforcement point's signature over the evidence-era
// envelope header, {version, signer, policyID, entryCount, tipHash}. It is the
// F2 binding plus the R2-02 completeness binding: relabelling the version,
// swapping the signer, substituting the carried policy, or deleting entries from
// the end of the log all invalidate this signature, so the verifier can establish
// which verdict rules apply AND that it is looking at the whole log, before it
// reads a single entry.
//
// The count and tip are recomputed here from the entries actually present, so the
// check is a re-derivation and not a comparison against a number the file states
// about itself.
func verifyEnvelope(exp *Export, pub crypto.PublicKey) error {
	pid := ""
	if exp.Policy != nil {
		var err error
		if pid, err = PolicyID(exp.Policy); err != nil {
			return fmt.Errorf("cannot content-address the carried policy: %w", err)
		}
	}
	if len(exp.EnvelopeSignature) == 0 {
		return fmt.Errorf("export carries no envelope signature over its version/signer/policy/length")
	}
	input := envelopeSigningInput(exp.Version, exp.Signer, pid, uint64(len(exp.Entries)), logTip(exp.Entries))
	if !signer.Verify(pub, input, exp.EnvelopeSignature) {
		return fmt.Errorf("envelope signature invalid (version, signer, policy, or the log's length/tip tampered: entries may have been removed)")
	}
	return nil
}

// hopRevoked fetches the hop's published status list, verifies the issuer signed
// it, and reads the credential's bit.
func hopRevoked(c *credential.Credential, in Inputs) (bool, error) {
	if in.Status == nil {
		return false, fmt.Errorf("credential references status list %q but no status list was provided", c.StatusRef.ListURL)
	}
	list, err := in.Status.ResolveStatus(c.StatusRef.ListURL)
	if err != nil {
		return false, err
	}
	issuerKey, err := did.ResolveKey(in.DIDs, list.Issuer)
	if err != nil {
		return false, fmt.Errorf("resolve status list issuer %q: %w", list.Issuer, err)
	}
	if err := verifyList(list, issuerKey); err != nil {
		return false, err
	}
	return list.Lookup(c.StatusRef.Index)
}

func verifyList(l *status.StatusList, pub crypto.PublicKey) error {
	if err := l.Verify(pub); err != nil {
		return fmt.Errorf("status list does not verify: %w", err)
	}
	return nil
}
