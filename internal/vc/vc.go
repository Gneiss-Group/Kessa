// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package vc implements the cross-org outer layer: a W3C-shaped Verifiable
// Credential that an organization signs over an arbitrary credential subject
// (in Kessa, the composed macaroon credential). When an agent credentialed by
// Org A presents to a proxy run by Org B (with no shared configuration) B
// verifies A's signature on this wrapper against A's published DID document and
// accepts the chain. That is the whole job of this layer.
//
// This is deliberately NOT the full VC-DATA-MODEL / JSON-LD / RDF-canonicalization
// machinery (spec §1). It is a fixed JSON structure plus an Ed25519 proof, with
// a simple, deterministic canonicalization: the signature covers the compact
// JSON encoding of the credential with the proof's value cleared. Both sides run
// this same code, so re-encoding reproduces the signed bytes exactly.
//
// Like internal/macaroon and internal/status, verification here takes only a
// public key, the caller resolves it from the issuer's DID document via
// internal/did, so this package stays a pure leaf with no did dependency.
package vc

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// signingDomain namespaces the proof so a VC signature can never be confused
// with a signature over some other Kessa artifact (a status list, an audit
// entry, a proof-of-possession nonce).
const signingDomain = "kessa/vc/v1"

// ProofType is the only proof suite this POC produces or accepts.
const ProofType = "Ed25519Signature2020"

// VerifiableCredential is the signed cross-org wrapper.
type VerifiableCredential struct {
	Context           []string        `json:"@context"`
	Type              []string        `json:"type"`
	Issuer            types.DID       `json:"issuer"`
	IssuanceDate      time.Time       `json:"issuanceDate"`
	ExpirationDate    *time.Time      `json:"expirationDate,omitempty"`
	CredentialSubject json.RawMessage `json:"credentialSubject"`
	Proof             *Proof          `json:"proof,omitempty"`
}

// Proof is a minimal Ed25519 data-integrity proof.
type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"` // e.g. did:web:...#key-1
	ProofPurpose       string    `json:"proofPurpose"`       // "assertionMethod"
	ProofValue         string    `json:"proofValue"`         // base64url(Ed25519 signature)
}

// IssueOptions carries the non-required inputs to Issue.
type IssueOptions struct {
	// IssuedAt sets issuanceDate and the proof's created time. Zero means
	// time.Now().UTC(); pass a fixed value for deterministic demos/tests.
	IssuedAt time.Time
	// Expires, if set, populates expirationDate (checked by Valid).
	Expires *time.Time
	// ExtraTypes are appended after the mandatory "VerifiableCredential" type.
	ExtraTypes []string
	// VerificationMethod overrides the default "<issuer>#key-1".
	VerificationMethod string
}

// Issue builds and signs a Verifiable Credential wrapping credentialSubject
// (any JSON-marshalable value) on behalf of the signer's org.
func Issue(s signer.Signer, credentialSubject any, opts IssueOptions) (*VerifiableCredential, error) {
	cs, err := json.Marshal(credentialSubject)
	if err != nil {
		return nil, fmt.Errorf("vc: marshal credentialSubject: %w", err)
	}
	issuedAt := opts.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	vm := opts.VerificationMethod
	if vm == "" {
		vm = string(s.DID()) + "#key-1"
	}

	c := &VerifiableCredential{
		Context:           []string{"https://www.w3.org/2018/credentials/v1"},
		Type:              append([]string{"VerifiableCredential"}, opts.ExtraTypes...),
		Issuer:            s.DID(),
		IssuanceDate:      issuedAt,
		ExpirationDate:    opts.Expires,
		CredentialSubject: cs,
		Proof: &Proof{
			Type:               ProofType,
			Created:            issuedAt,
			VerificationMethod: vm,
			ProofPurpose:       "assertionMethod",
		},
	}

	input, err := c.signingInput()
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(input)
	if err != nil {
		return nil, fmt.Errorf("vc: sign: %w", err)
	}
	c.Proof.ProofValue = base64.RawURLEncoding.EncodeToString(sig)
	return c, nil
}

// Verify checks the Ed25519 proof against pub (which the caller resolves from
// the issuer's DID document). It authenticates the issuer and guarantees the
// credential (including its subject and issuer fields) has not been altered.
// It does NOT check the validity window; call Valid for that.
func (c *VerifiableCredential) Verify(pub crypto.PublicKey) error {
	if c.Proof == nil {
		return errors.New("vc: credential has no proof")
	}
	if c.Proof.Type != ProofType {
		return fmt.Errorf("vc: unsupported proof type %q", c.Proof.Type)
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("vc: decode proofValue: %w", err)
	}
	input, err := c.signingInput()
	if err != nil {
		return err
	}
	if !signer.Verify(pub, input, sig) {
		return errors.New("vc: proof verification failed (forged or tampered)")
	}
	return nil
}

// Valid checks the issuance/expiration window at time at. It is independent of
// signature verification so a verifier can report the two failures distinctly.
func (c *VerifiableCredential) Valid(at time.Time) error {
	if at.Before(c.IssuanceDate) {
		return fmt.Errorf("vc: not yet valid (issued %s, now %s)", c.IssuanceDate, at)
	}
	if c.ExpirationDate != nil && at.After(*c.ExpirationDate) {
		return fmt.Errorf("vc: expired at %s (now %s)", *c.ExpirationDate, at)
	}
	return nil
}

// UnmarshalSubject decodes the wrapped credentialSubject into v.
func (c *VerifiableCredential) UnmarshalSubject(v any) error {
	if len(c.CredentialSubject) == 0 {
		return errors.New("vc: empty credentialSubject")
	}
	return json.Unmarshal(c.CredentialSubject, v)
}

// signingInput is the deterministic byte string that is signed and verified: a
// domain tag followed by the compact JSON of the credential with the proof's
// value cleared (but the proof's metadata retained, so created/verificationMethod
// are covered by the signature).
func (c *VerifiableCredential) signingInput() ([]byte, error) {
	cp := *c
	if c.Proof != nil {
		p := *c.Proof
		p.ProofValue = ""
		cp.Proof = &p
	}
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil, fmt.Errorf("vc: canonicalize: %w", err)
	}
	out := make([]byte, 0, len(signingDomain)+1+len(b))
	out = append(out, signingDomain...)
	out = append(out, 0x00)
	out = append(out, b...)
	return out, nil
}

// Marshal serializes the credential to its JSON form.
func (c *VerifiableCredential) Marshal() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// Parse reads a credential from JSON. It does not verify the proof.
func Parse(data []byte) (*VerifiableCredential, error) {
	var c VerifiableCredential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("vc: parse: %w", err)
	}
	return &c, nil
}
