// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package chain resolves and verifies a delegation chain: the ordered sequence
// of credentials from a trust anchor (a human or org) down to the actor that
// attempts an action (human -> org -> agent -> sub-agent).
//
// Each hop is a credential plus an Ed25519 issuance signature by that
// credential's issuer. Verifying a hop is three offline checks, exactly the
// ones spec §4 step 3 requires of the independent verifier:
//
//  1. Issuance signature: the issuer's key, resolved from its DID document,
//     signed this credential, the WHOLE credential, every field of it, so a
//     holder cannot edit its own blob and still present something that verifies
//     (see IssuanceInput).
//  2. Continuity: a hop's issuer is the previous hop's subject, so the chain is
//     an unbroken parent->child line.
//  3. Attenuation: the child's macaroon strictly narrows the parent's (macaroon
//     Extends), so authority only ever shrinks down the chain.
//
// It additionally ties each credential's bound holder key to the subject's
// published DID key, which is what makes proof-of-possession meaningful.
//
// Nothing here verifies a macaroon's HMAC: the verifier holds no root key. The
// whole chain is anchored by public-key signatures and structural subset checks,
// so it can be re-verified offline with only public DID documents, the spine of
// the "trust nothing of ours" design.
package chain

import (
	"encoding/json"
	"fmt"

	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// issuanceDomain namespaces issuance signatures. Bumped to v2 when the signature
// moved from an enumerated field subset to the whole credential (R2-01), so a v1
// issuance signature can never be replayed as a v2 one.
const issuanceDomain = "kessa/issuance/v2"

// MaxDepth caps how many hops a delegation chain may contain (human -> org ->
// agent -> sub-agent -> ...). A hop is one Link (one issuer->subject edge) so a
// chain of N hops names N+1 principals.
//
// The cap bounds two things at once, both in the spirit of the rest of this
// codebase:
//
//   - Verification cost: an independent verifier can never be handed an
//     unbounded chain to walk. Every hop is a signature verify plus two DID
//     resolutions, so an attacker-supplied 10,000-hop chain would otherwise be a
//     cheap way to make a verifier do a lot of work.
//   - Abuse surface: a buggy or malicious agent cannot mint an ever-deeper
//     delegation subtree beneath itself.
//
// It is a single global constant on purpose, per-org / per-policy limits are
// explicitly out of scope for now. 8 hops is comfortably more than double the
// deepest chain any shipped demo scenario builds (alice -> acme -> worker ->
// helper is 3 hops), while keeping the walk bounded and small. Enforced at
// issuance (the issuer refuses to mint a chain past the cap) AND here at
// verification (a chain past the cap is rejected even if a cap was bypassed or
// lowered after issuance): the same "trust nothing, re-derive everything"
// discipline the verifier applies to every other property.
const MaxDepth = 8

// Link is one hop: a credential and the issuer's signature that granted it.
type Link struct {
	Credential  credential.Credential `json:"credential"`
	IssuerProof []byte                `json:"issuerProof"` // issuer's Ed25519 signature over IssuanceInput
}

// Chain is a delegation chain, ordered root (index 0) to actor (last).
type Chain struct {
	Links []Link `json:"links"`
}

// IssuanceInput is the exact byte string an issuer signs to grant a credential:
// the domain tag followed by the credential's whole canonical encoding.
//
// It signs the WHOLE credential rather than an enumerated subset of its fields,
// and that is the load-bearing detail (R2-01). The v1 form named five fields,
// issuer, subject, holder key, macaroon identifier, macaroon caveats, which left
// StatusRef, and any field added later, outside signed material. A credential
// holder holds its own blob, so it could edit an unbound field (drop StatusRef to
// skip the revocation sweep, or repoint its index at an un-revoked bit) and
// present a credential whose issuance signature still verified byte for byte.
// Both the proxy and the independent verifier then reached a verdict from a field
// the issuer never signed.
//
// An enumerated list is the wrong shape for this: it fails open, silently, every
// time a field is added. Signing the whole credential fails closed instead, a new
// field is covered the moment it exists, and any edit to any field, present or
// future, invalidates the signature. The verifier's job is to re-derive, and this
// is what makes "what was presented is what was issued" re-derivable at all.
//
// Determinism: json.Marshal emits compact JSON and compacts nested
// json.RawMessage, so a parse/re-emit round trip of the credential reproduces
// these bytes exactly, the same property CredentialID relies on.
func IssuanceInput(c *credential.Credential) ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("chain: canonicalize issuance: %w", err)
	}
	out := make([]byte, 0, len(issuanceDomain)+1+len(body))
	out = append(out, issuanceDomain...)
	out = append(out, 0x00)
	out = append(out, body...)
	return out, nil
}

// SignIssuance produces the issuer's signature granting credential c. The
// issuer's DID must match c.Issuer.
func SignIssuance(issuer signer.Signer, c *credential.Credential) ([]byte, error) {
	if issuer.DID() != c.Issuer {
		return nil, fmt.Errorf("chain: issuer %q does not match credential issuer %q", issuer.DID(), c.Issuer)
	}
	input, err := IssuanceInput(c)
	if err != nil {
		return nil, err
	}
	return issuer.Sign(input)
}

// Verify walks the chain and checks every hop. It returns nil only if the whole
// chain is intact; otherwise it names the hop that failed and why. DID documents
// are resolved through r, the only external input, and only public documents.
func (ch *Chain) Verify(r did.Resolver) error {
	if len(ch.Links) == 0 {
		return fmt.Errorf("chain: empty chain")
	}
	// Depth cap, re-derived here rather than trusted from issuance: a chain deeper
	// than MaxDepth is rejected before any hop is walked, bounding both verifier
	// work and delegation abuse surface (see MaxDepth).
	if len(ch.Links) > MaxDepth {
		return fmt.Errorf("chain: depth %d exceeds max delegation depth %d", len(ch.Links), MaxDepth)
	}
	for i := range ch.Links {
		c := &ch.Links[i].Credential

		// 1. Issuance signature, verified against the issuer's DID-resolved key.
		issuerKey, err := did.ResolveKey(r, c.Issuer)
		if err != nil {
			return fmt.Errorf("chain: hop %d: resolve issuer %q: %w", i, c.Issuer, err)
		}
		input, err := IssuanceInput(c)
		if err != nil {
			return fmt.Errorf("chain: hop %d: %w", i, err)
		}
		// signer.Verify dispatches on the issuer key's algorithm (Ed25519 or
		// P-256), so a chain rooted at a human whose device key is a hardware
		// P-256 key verifies through the same loop as an all-Ed25519 chain.
		if !signer.Verify(issuerKey, input, ch.Links[i].IssuerProof) {
			return fmt.Errorf("chain: hop %d: issuance signature invalid for %q", i, c.Subject)
		}

		// 2. The bound holder key must be the subject's published DID key. Both are
		// resolved/parsed as crypto.PublicKey and compared with KeysEqual, which
		// also fails a cross-algorithm mismatch.
		subjectKey, err := did.ResolveKey(r, c.Subject)
		if err != nil {
			return fmt.Errorf("chain: hop %d: resolve subject %q: %w", i, c.Subject, err)
		}
		if c.HolderKey == nil {
			return fmt.Errorf("chain: hop %d: credential has no bound holder key", i)
		}
		holderKey, err := c.HolderKey.PublicKey()
		if err != nil {
			return fmt.Errorf("chain: hop %d: parse bound holder key: %w", i, err)
		}
		if !signer.KeysEqual(subjectKey, holderKey) {
			return fmt.Errorf("chain: hop %d: holder key does not match subject %q DID key", i, c.Subject)
		}

		// 3. Continuity + strict attenuation relative to the parent hop.
		if i > 0 {
			parent := &ch.Links[i-1].Credential
			if c.Issuer != parent.Subject {
				return fmt.Errorf("chain: hop %d: continuity broken (issuer %q != parent subject %q)", i, c.Issuer, parent.Subject)
			}
			if err := c.Macaroon.Extends(parent.Macaroon); err != nil {
				return fmt.Errorf("chain: hop %d: not a valid attenuation of parent: %w", i, err)
			}
		}
	}
	return nil
}

// Principals returns the resolved chain of DIDs in human-readable order:
// the root issuer followed by each hop's subject (anchor -> ... -> actor).
func (ch *Chain) Principals() []types.DID {
	if len(ch.Links) == 0 {
		return nil
	}
	out := make([]types.DID, 0, len(ch.Links)+1)
	out = append(out, ch.Links[0].Credential.Issuer)
	for i := range ch.Links {
		out = append(out, ch.Links[i].Credential.Subject)
	}
	return out
}

// Root returns the trust anchor (the first hop's issuer).
func (ch *Chain) Root() types.DID {
	if len(ch.Links) == 0 {
		return ""
	}
	return ch.Links[0].Credential.Issuer
}

// Actor returns the terminal principal that attempts actions (the last subject).
func (ch *Chain) Actor() types.DID {
	if len(ch.Links) == 0 {
		return ""
	}
	return ch.Links[len(ch.Links)-1].Credential.Subject
}

// Marshal serializes the chain to portable JSON.
func (ch *Chain) Marshal() ([]byte, error) {
	return json.MarshalIndent(ch, "", "  ")
}

// Parse reads a chain from JSON. It performs no verification.
func Parse(data []byte) (*Chain, error) {
	var c Chain
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("chain: parse: %w", err)
	}
	return &c, nil
}
