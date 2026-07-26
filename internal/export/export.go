// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package export defines the v2 audit export envelope: the audit entry chain
// plus the deduplicated, content-addressed set of credentials that constitutes
// the *evidence* for those entries.
//
// Why this package exists (spec §3.1 rev 2). The v1 entry records the results of
// enforcement (the resolved chain, the decision, the PoP nonce) but not the
// credentials those results were derived from. A verifier given only v1 entries
// can confirm the log is internally consistent and untampered, but it must then
// take the enforcement point's word for *what authority existed*. That is exactly
// what the verifier is supposed to never do. v2 carries the evidence inside the
// same single file, so the verifier re-derives the verdict instead of trusting it.
//
// The trust boundary is the hash boundary. The credential IDs each entry was
// decided against live inside the hashed, signed entry (audit.Entry), so an entry
// is bound to the *specific* credentials it used. The credential set itself sits
// outside the entry hash chain (enabling dedup and a later redaction seam) but
// is integrity-checked two ways: each record is content-addressed (its ID is a
// hash of its own bytes), and the re-resolved chain must reproduce the entry's
// recorded ResolvedChain exactly.
//
// This package is the single place that dispatches on envelope version. audit
// deliberately knows nothing about v2.
package export

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	// Version is the current evidence-envelope version string.
	//
	// The envelope has exactly two real shapes: the integrity-only v1 form
	// (audit.ExportVersion, no evidence) and this evidence-carrying form, v2. That
	// is the whole version history, there is no v3, and no different v2 was ever
	// released.
	//
	// Security review round 2 changed what several signing inputs cover (the
	// issuance signature now covers the whole credential, R2-01; the envelope
	// signature now covers the entry count and log tip, R2-02; the entry payload
	// carries statusCheckedHops rather than a statusChecked bool). Those are
	// format-affecting, but they were finalized PRE-RELEASE: nothing has shipped,
	// so there are no v2 exports in the field to protect, and the evidence format
	// settles at v2 with its round-2 contents rather than minting a v3 for a v2
	// nobody ever saw. See the security review (docs/README.md).
	//
	// Consequence, stated because it is the pre-release trade: a hypothetical
	// evidence export from an intermediate pre-round-2 build carries the same "v2"
	// label but different signed contents, so it fails at hash/signature
	// re-derivation rather than at a clean version refusal. Acceptable only because
	// no such export exists outside regenerable goldens.
	Version = "kessa-audit-export/v2"

	// credIDDomain namespaces the content-addressed credential id so it can never
	// collide with any other Kessa hash.
	credIDDomain = "kessa/credential-id/v1"

	// policyIDDomain namespaces the content-addressed policy id (F1).
	policyIDDomain = "kessa/policy-id/v1"

	// envelopeSigDomain namespaces the enforcement point's signature over the
	// envelope header, the version, signer, carried-policy identity (F2/F1), and
	// the log's length and tip (R2-02). This is the domain tag's second iteration
	// (round 1 signed only version/signer/policyID), so it is /v2 regardless of the
	// envelope's own version string, a round-1 envelope signature cannot be lifted
	// onto a round-2 one.
	envelopeSigDomain = "kessa/audit-export-envelope/v2"
)

// CredentialRecord is one credential in the deduplicated evidence set. It is
// stored exactly once regardless of how many entries reference it.
type CredentialRecord struct {
	CredentialID string                `json:"credentialID"` // content-addressed; see CredentialID
	Credential   credential.Credential `json:"credential"`
	IssuerProof  []byte                `json:"issuerProof"` // the issuer's Ed25519 signature granting this credential
}

// Export is the self-contained v2 envelope: one file, no companion artifacts.
//
// EnvelopeSignature closes F2: the format version is a verdict-relevant field
// (the v1 code path is integrity-only), so it must sit inside signed material.
// The enforcement point signs {version, signer, policyID} at the envelope level,
// and the verifier checks that signature before it processes a single entry, so
// relabelling or a signer/policy swap invalidates it rather than downgrading to a
// weaker path. Policy carries the ruleset the verifier re-runs to derive
// consequentiality (F1); it is content-addressed and pinned per-entry via
// Entry.PolicyID, and its identity is folded into the envelope signature.
type Export struct {
	Version           string                      `json:"version"`
	Signer            types.DID                   `json:"signer"` // enforcement point whose key signs every entry
	Entries           []audit.Entry               `json:"entries"`
	Credentials       map[string]CredentialRecord `json:"credentials,omitempty"` // keyed by CredentialID
	Policy            *policy.Policy              `json:"policy,omitempty"`      // the ruleset entries were classified under (F1)
	EnvelopeSignature []byte                      `json:"envelopeSignature,omitempty"`
}

// CredentialID is the content address of a credential: base64url(SHA-256(domain
// || 0x00 || compact-JSON(credential))).
//
// IssuerProof is excluded by construction, it lives on CredentialRecord, not on
// the credential, because the ID is the credential's stable identity, while a
// signature is verified separately and would otherwise make the ID change on
// re-signing.
//
// Determinism note: json.Marshal emits compact JSON and, because json.RawMessage
// is a Marshaler, encoding/json compacts its contents too. So the nested
// VCWrapper.CredentialSubject cannot smuggle producer whitespace into the hash,
// and a parse/re-emit round trip yields the same ID.
func CredentialID(c *credential.Credential) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("export: canonicalize credential: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(credIDDomain))
	h.Write([]byte{0x00})
	h.Write(body)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// PolicyID is the content address of a policy: base64url(SHA-256(domain || 0x00
// || compact-JSON(policy))). It is what an entry's PolicyID field pins to, so a
// verifier can confirm the carried policy is byte-for-byte the one the entry was
// classified under and a proxy cannot swap in a more permissive ruleset (F1).
func PolicyID(p *policy.Policy) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("export: canonicalize policy: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(policyIDDomain))
	h.Write([]byte{0x00})
	h.Write(body)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// envelopeSigningInput is the exact byte string the enforcement point signs to
// bind the envelope header into the trust boundary: the domain tag, the version,
// the signer DID, the carried policy's content id (empty when none), and the
// log's length and tip.
//
// entryCount and tipHash close R2-02. Every entry is individually signed and
// hash-chained to its predecessor, and VerifyEntries requires Seq == index from
// the genesis hash, which makes insertion, reordering and in-place modification
// detectable. It did not make TRUNCATION detectable, because nothing signed
// committed to how long the log was. Anyone holding the export file, with no key
// material at all, could delete trailing entries: the survivors still formed an
// unbroken chain from seq 0, every signature still verified, and the envelope
// signature was untouched. An operator could hand an auditor an export with the
// inconvenient tail removed and `kessa verify` would endorse it.
//
// Committing to the count and the tip hash means the shortened file no longer
// matches what the enforcement point signed. Deleting from the MIDDLE was already
// closed, and by a different mechanism: removing entry k leaves entry k+1 with the
// wrong Seq and a PrevHash pointing at a hash no longer present, both of which
// VerifyEntries rejects, and re-linking the survivors requires re-signing every
// one of them. The count/tip binding is what closes deletion from the END.
//
// What this does NOT close, stated plainly because the difference matters: an
// enforcement point can still decline to log something in the first place, and a
// short log signed FRESH by a dishonest proxy is indistinguishable from a short
// honest one. Detecting that needs the tip anchored somewhere the proxy does not
// control, which is out of scope here. This fix makes a genuine export
// untruncatable by a third party; it does not make an enforcement point honest.
func envelopeSigningInput(version string, signerDID types.DID, policyID string, entryCount uint64, tipHash []byte) []byte {
	var countb [8]byte
	binary.BigEndian.PutUint64(countb[:], entryCount)
	out := make([]byte, 0, len(envelopeSigDomain)+len(version)+len(signerDID)+len(policyID)+len(countb)+len(tipHash)+5)
	out = append(out, envelopeSigDomain...)
	out = append(out, 0x00)
	out = append(out, version...)
	out = append(out, 0x00)
	out = append(out, signerDID...)
	out = append(out, 0x00)
	out = append(out, policyID...)
	out = append(out, 0x00)
	out = append(out, countb[:]...)
	out = append(out, 0x00)
	out = append(out, tipHash...)
	return out
}

// logTip returns the hash the envelope signature commits to as the log's final
// state: the last entry's hash, or the genesis hash for an empty log. Pairing it
// with the count pins both ends, the count alone would let an attacker swap the
// tail for a same-length forgery it could not sign, and the tip alone would not
// notice a log that had been shortened to end on an earlier genuine entry.
func logTip(entries []audit.Entry) []byte {
	if n := len(entries); n > 0 {
		return entries[n-1].EntryHash
	}
	return audit.GenesisHash
}

// CredentialSet accumulates evidence with deduplication. Adding the same
// credential twice returns the same ID and stores one copy.
type CredentialSet struct {
	records map[string]CredentialRecord
}

// NewCredentialSet returns an empty evidence set.
func NewCredentialSet() *CredentialSet {
	return &CredentialSet{records: make(map[string]CredentialRecord)}
}

// Add inserts a credential and its issuance proof, returning its content ID. If
// the credential is already present, it is not stored again.
func (s *CredentialSet) Add(c credential.Credential, issuerProof []byte) (string, error) {
	id, err := CredentialID(&c)
	if err != nil {
		return "", err
	}
	if _, ok := s.records[id]; !ok {
		s.records[id] = CredentialRecord{CredentialID: id, Credential: c, IssuerProof: issuerProof}
	}
	return id, nil
}

// Has reports whether a credential with this content ID is already stored. It
// lets a caller decide what is NEW in a chain (e.g. to persist only the newly
// seen credentials to a durable log) without mutating the set.
func (s *CredentialSet) Has(id string) bool { _, ok := s.records[id]; return ok }

// Len reports how many distinct credentials are stored.
func (s *CredentialSet) Len() int { return len(s.records) }

// Records returns the underlying map (used to build an Export).
func (s *CredentialSet) Records() map[string]CredentialRecord { return s.records }

// Build assembles a v2 export from a signed entry chain, an evidence set, and the
// policy the entries were classified under, then signs the envelope header. The
// enforcement point's own signer produces both the entry signatures and this
// envelope signature, so version, signer identity, and policy identity are all
// bound into signed material the verifier re-checks (F1/F2).
func Build(ep signer.Signer, entries []audit.Entry, set *CredentialSet, pol *policy.Policy) (*Export, error) {
	e := &Export{
		Version:     Version,
		Signer:      ep.DID(),
		Entries:     entries,
		Credentials: set.Records(),
		Policy:      pol,
	}
	pid := ""
	if pol != nil {
		var err error
		if pid, err = PolicyID(pol); err != nil {
			return nil, err
		}
	}
	sig, err := ep.Sign(envelopeSigningInput(e.Version, e.Signer, pid, uint64(len(entries)), logTip(entries)))
	if err != nil {
		return nil, fmt.Errorf("export: sign envelope: %w", err)
	}
	e.EnvelopeSignature = sig
	return e, nil
}

// Marshal serializes the envelope. Go marshals maps with sorted keys, so the
// output is byte-deterministic.
func (e *Export) Marshal() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// IsV1 reports whether this is a legacy v1 envelope carrying no evidence.
func (e *Export) IsV1() bool { return e.Version == audit.ExportVersion }

// Parse reads an export and dispatches on version. This is the ONLY place that
// decides which envelope versions are acceptable, an unknown version (a future
// v3) is rejected here rather than silently flowing into verification.
//
// The accepted set is exactly {v1 integrity-only, v2 evidence}. There is
// deliberately no v3; see Version.
func Parse(data []byte) (*Export, error) {
	var e Export
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("export: parse: %w", err)
	}
	switch e.Version {
	case Version:
		// v2: evidence expected. A carried policy must satisfy exactly the same
		// validation a proxy applies when it LOADS that policy (policy.Validate).
		// Without this, encoding/json accepts a policy that policy.Parse rejects,
		// and a malformed rule (a typo'd operator, say) silently never fires and
		// falls through to the default at both enforcement and verification time,
		// with no warning at any point in the pipeline.
		//
		// This is a hard error, not a warning: an export whose policy is not
		// meaningful cannot support a meaningful re-derivation of consequentiality,
		// and failing loudly is the same discipline F1/F2 applied elsewhere.
		//
		// DELIBERATE NO-GRANDFATHERING DECISION. This check is retroactive: it
		// applies to already-signed exports, so an export whose carried policy would
		// fail today's validation becomes unverifiable even though it verified
		// before. That is acceptable *now*, there are no field deployments, and the
		// only policies in existence carry a valid default, and it is preferable to
		// a permanently-forked "old exports are validated differently" code path.
		//
		// REVISIT once real customer exports exist. At that point tightening policy
		// validation stops being a free change and becomes a compatibility event:
		// it needs a versioned migration (validate against the rules in force when
		// the export was signed, keyed off the envelope version) rather than another
		// silent retroactive tightening here. Adding a rule to policy.Validate after
		// that point WILL invalidate exports in the field, treat this comment as the
		// tripwire for that.
		if e.Policy != nil {
			if err := e.Policy.Validate(); err != nil {
				return nil, fmt.Errorf("export: carried policy is invalid: %w", err)
			}
		}
	case audit.ExportVersion:
		// v1: legacy, integrity-only. It must not carry any v2 evidence, a
		// credential set, a policy, or an envelope signature. Rejecting them here
		// stops a v2 export from being trimmed down and relabelled to masquerade as
		// a genuine v1 while still smuggling v2 structure (F2).
		if len(e.Credentials) > 0 {
			return nil, fmt.Errorf("export: v1 envelope must not carry a credential set")
		}
		if e.Policy != nil {
			return nil, fmt.Errorf("export: v1 envelope must not carry a policy")
		}
		if len(e.EnvelopeSignature) > 0 {
			return nil, fmt.Errorf("export: v1 envelope must not carry an envelope signature")
		}
	default:
		return nil, fmt.Errorf("export: unsupported export version %q", e.Version)
	}
	return &e, nil
}
