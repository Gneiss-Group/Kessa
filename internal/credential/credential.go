// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package credential composes the pieces that actually travel down a delegation
// chain into one unit: the attenuated macaroon (authority), a reference into the
// issuer's status list (revocation), the holder's public key (binding), and,
// on the outermost cross-org credential, the VC wrapper (issuer authenticity
// across orgs).
//
// Holder-binding is enforced two independent ways, so a copied credential blob
// is useless to a thief who lacks the holder's private key (spec scenario 5):
//
//   - At rest, by the issuance signature. chain.IssuanceInput covers the whole
//     credential, HolderKey included, so swapping the bound key invalidates the
//     issuer's Ed25519 signature and chain.Verify rejects the hop. chain.Verify
//     additionally requires the bound key to equal the subject's published DID
//     key, so a swap must also compromise the subject's DID document to survive.
//   - At use time, by proof-of-possession. The presenter signs a fresh challenge
//     nonce with the holder private key, and VerifyPossession checks it against
//     the bound public key. A copied blob cannot produce a valid signature.
//
// Both checks are re-runnable offline by the independent verifier from public
// material, which is the point: a defense the verifier cannot re-run is a defense
// only the enforcement point can attest to.
//
// Corrected in round 2: this doc previously named the macaroon's HMAC chain as
// the first defense, on the reasoning that a swapped HolderKey would stop the
// macaroon verifying. Nothing ever verifies it, macaroon.Verify needs the root
// key, which neither the proxy nor the verifier holds, and both call
// macaroon.Satisfies instead. The property was real; the stated mechanism was
// not. BindHolder still commits the key into the caveat chain, and that caveat is
// covered by the issuance signature above, which is the mechanism that actually
// carries the weight. See macaroon.Verify for the full reasoning. R2-01 is what
// this correction is for: a field whose protection is assumed rather than checked
// is exactly how a bypass survives review.
//
// The PoP nonce recorded at action time is what the independent verifier later
// re-checks against the holder key bound in the credential (spec §4, step 6).
package credential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/internal/vc"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// HolderField is the macaroon caveat field that binds a credential to a holder
// public key. popDomain namespaces proof-of-possession signatures.
const (
	HolderField = "holder"
	// popDomain namespaces proof-of-possession signatures. Bumped to v2 when
	// PrevHash joined the signed material (R2-04).
	popDomain = "kessa/pop/v2"
)

// Credential is the composed unit that travels down a chain.
//
// VCWrapper is NOT load-bearing (F7). Cross-org trust rests entirely on the
// per-hop Ed25519 issuance signature (chain.IssuanceInput / chain.Verify), which
// binds issuer, subject, holder key, and the macaroon's authority and is resolved
// against the issuer's public DID document with no shared config. Neither the
// proxy nor the independent verifier ever calls VCWrapper.Verify, the issuance
// signature is the actual anchor. The wrapper remains as an optional W3C-shaped
// presentation envelope for interop; do not treat its presence as a trust check.
type Credential struct {
	Subject   types.DID                `json:"subject"`   // who this authorizes (the holder)
	Issuer    types.DID                `json:"issuer"`    // parent principal / org that issued it
	Macaroon  macaroon.Macaroon        `json:"macaroon"`  // attenuated authority
	StatusRef status.Reference         `json:"statusRef"` // position in the issuer's status list
	HolderKey *did.JWK                 `json:"holderKey"` // bound holder key (Ed25519 OKP or P-256 EC); proof-of-possession
	VCWrapper *vc.VerifiableCredential `json:"vcWrapper,omitempty"`
}

// Options are the inputs to New.
type Options struct {
	Subject  types.DID
	Issuer   types.DID
	Macaroon macaroon.Macaroon
	// HolderKey is the public half of the holder's key, either an
	// ed25519.PublicKey or a *ecdsa.PublicKey (P-256). It is stored as a
	// self-describing JWK so the credential records which algorithm proof-of-
	// possession must be verified under (the employee/device key is P-256, minted
	// in hardware; every other principal is Ed25519).
	HolderKey crypto.PublicKey
	StatusRef status.Reference
	VCWrapper *vc.VerifiableCredential
}

// New composes and validates a Credential. It does not mutate the macaroon; to
// commit the holder key into the macaroon chain, attenuate with BindHolder
// before composing.
func New(o Options) (*Credential, error) {
	if o.Subject == "" {
		return nil, errors.New("credential: empty subject")
	}
	if o.Issuer == "" {
		return nil, errors.New("credential: empty issuer")
	}
	jwk, err := holderJWK(o.HolderKey)
	if err != nil {
		return nil, err
	}
	if o.Macaroon.Identifier == "" || len(o.Macaroon.Signature) == 0 {
		return nil, errors.New("credential: macaroon is empty or unsigned")
	}
	return &Credential{
		Subject:   o.Subject,
		Issuer:    o.Issuer,
		Macaroon:  o.Macaroon,
		StatusRef: o.StatusRef,
		HolderKey: jwk,
		VCWrapper: o.VCWrapper,
	}, nil
}

// holderJWK validates that pub is a structurally valid, supported holder key and
// encodes it as a JWK. It is the CONSTRUCTION-TIME boundary check: a credential
// returned by New always carries a well-formed holder key, so a malformed one is
// refused here rather than travelling on to be rejected only at verify time
// (R3-01: the "validation moved from construction to deferred verify" regression
// this restores; see also R2-01, the same shape).
//
// It pre-validates the concrete type and curve so it can return an ERROR for bad
// input (the holder key may come from parsed/external material) instead of
// tripping PublicKeyToJWK's panic, and then round-trips through JWK.PublicKey as
// the total check: whatever survives here is guaranteed parseable and on-curve.
func holderJWK(pub crypto.PublicKey) (*did.JWK, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("credential: Ed25519 holder key is %d bytes, want %d", len(k), ed25519.PublicKeySize)
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("credential: ECDSA holder key must be on the P-256 curve")
		}
	case nil:
		return nil, errors.New("credential: holder key is required")
	default:
		return nil, fmt.Errorf("credential: unsupported holder key type %T (want Ed25519 or P-256)", pub)
	}
	jwk := did.PublicKeyToJWK(pub)
	// Total check: the encoded key must parse back to a valid public key. This
	// catches anything the type/curve switch above could not (e.g. an ECDSA key
	// whose point is off-curve), so New cannot mint a structurally invalid holder.
	if _, err := jwk.PublicKey(); err != nil {
		return nil, fmt.Errorf("credential: invalid holder key: %w", err)
	}
	return jwk, nil
}

// ---- holder binding in the macaroon --------------------------------------

// HolderValue encodes a holder public key for use as a caveat value. It is the
// canonical JWK JSON, base64url-encoded, so the value is algorithm-agnostic (an
// Ed25519 and a P-256 key produce distinct, self-describing values) and
// reproducible identically at issuance and at verification.
func HolderValue(holder crypto.PublicKey) (string, error) {
	jwk, err := holderJWK(holder)
	if err != nil {
		return "", err
	}
	return jwkValue(jwk), nil
}

// jwkValue is the deterministic caveat encoding of a JWK: compact JSON (stable
// field order, y omitted for Ed25519) base64url-encoded. Both BindHolder (from a
// key) and HolderContext (from the stored JWK) route through it, so they always
// agree.
func jwkValue(j *did.JWK) string {
	b, _ := json.Marshal(j) // a plain struct of strings never fails to marshal
	return base64.RawURLEncoding.EncodeToString(b)
}

// HolderCaveat is the caveat that binds a credential to a holder key.
func HolderCaveat(holder crypto.PublicKey) (macaroon.Caveat, error) {
	v, err := HolderValue(holder)
	if err != nil {
		return macaroon.Caveat{}, err
	}
	return macaroon.Caveat{Field: HolderField, Op: macaroon.OpEq, Value: v}, nil
}

// BindHolder returns a new macaroon attenuated with the holder-binding caveat.
// Because attenuation is append-only and HMAC-chained, the bound key is then
// tamper-evident.
func BindHolder(m macaroon.Macaroon, holder crypto.PublicKey) (macaroon.Macaroon, error) {
	cav, err := HolderCaveat(holder)
	if err != nil {
		return macaroon.Macaroon{}, err
	}
	return macaroon.Attenuate(m, cav)
}

// HolderContext returns the macaroon context fragment asserting this
// credential's holder key. Merge it into the action context so a macaroon
// carrying a holder caveat can be satisfied by the legitimately bound holder.
// It derives the value from the stored JWK directly, so it cannot disagree with
// the caveat BindHolder wrote at issuance.
func (c *Credential) HolderContext() macaroon.Context {
	if c.HolderKey == nil {
		return macaroon.Context{}
	}
	return macaroon.Context{HolderField: jwkValue(c.HolderKey)}
}

// ---- proof of possession --------------------------------------------------

// PoP is a holder's proof that it controls the private key bound in a credential.
type PoP struct {
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature"`
}

// Challenge returns a fresh 32-byte random nonce for a proof-of-possession
// challenge. Deterministic demos may substitute a fixed nonce instead.
func Challenge() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("credential: challenge: %w", err)
	}
	return nonce, nil
}

// popInput binds the proof to this specific credential (subject + macaroon id),
// the challenge nonce, the exact action being authorized, and the entry's chain
// position (Seq + PrevHash). Covering the action stops a captured PoP from being
// replayed onto a fabricated entry for a different action (F3); covering the
// position stops it from being lifted onto a sibling entry or replayed into a
// later append (F4), so a proof authorizes one action at one chain slot, not
// merely "this holder".
//
// PrevHash is here because Seq alone was not enough (R2-04). audit.VerifyEntries
// enforces Seq == index, which makes a Seq unique WITHIN one log, but a proxy
// restarted with a fresh in-memory log starts again at 0, so a proof minted for
// the first run's slot 5 replayed into the second run's slot 5. PrevHash is the
// preceding entry's hash and therefore commits transitively to everything logged
// before it, which distinguishes the two. See audit.ApprovalInput for the same
// reasoning and for the one case this does not cover (Seq 0, where both logs
// share GenesisHash).
func (c *Credential) popInput(nonce []byte, action types.Action, seq uint64, prevHash []byte) ([]byte, error) {
	body, err := json.Marshal(action)
	if err != nil {
		return nil, fmt.Errorf("credential: canonicalize action for PoP: %w", err)
	}
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	out := make([]byte, 0, len(popDomain)+len(c.Subject)+len(c.Macaroon.Identifier)+len(nonce)+len(body)+len(seqb)+len(prevHash)+6)
	out = append(out, popDomain...)
	out = append(out, 0x00)
	out = append(out, c.Subject...)
	out = append(out, 0x00)
	out = append(out, c.Macaroon.Identifier...)
	out = append(out, 0x00)
	out = append(out, nonce...)
	out = append(out, 0x00)
	out = append(out, body...)
	out = append(out, 0x00)
	out = append(out, seqb[:]...)
	out = append(out, 0x00)
	out = append(out, prevHash...)
	return out, nil
}

// ProvePossession signs the challenge nonce (bound to the action and the entry's
// position) with the holder's key, producing a PoP. The caller is expected to hold
// the private key bound in the credential; if not, the resulting PoP will simply
// fail VerifyPossession.
func (c *Credential) ProvePossession(holder signer.Signer, nonce []byte, action types.Action, seq uint64, prevHash []byte) (PoP, error) {
	input, err := c.popInput(nonce, action, seq, prevHash)
	if err != nil {
		return PoP{}, err
	}
	sig, err := holder.Sign(input)
	if err != nil {
		return PoP{}, fmt.Errorf("credential: prove possession: %w", err)
	}
	return PoP{Nonce: nonce, Signature: sig}, nil
}

// VerifyPossession checks a proof of possession against the bound holder key. The
// action and entry position come from the recorded entry itself, so a proof minted
// for a different action, a different slot, or a different log fails. The holder
// key may be Ed25519 or P-256; signer.Verify dispatches on it, so PoP is verified
// under whatever algorithm the credential was bound to.
func (c *Credential) VerifyPossession(pop PoP, action types.Action, seq uint64, prevHash []byte) error {
	if c.HolderKey == nil {
		return errors.New("credential: no bound holder key")
	}
	pub, err := c.HolderKey.PublicKey()
	if err != nil {
		return fmt.Errorf("credential: bound holder key: %w", err)
	}
	if len(pop.Nonce) == 0 {
		return errors.New("credential: proof of possession has empty nonce")
	}
	input, err := c.popInput(pop.Nonce, action, seq, prevHash)
	if err != nil {
		return err
	}
	if !signer.Verify(pub, input, pop.Signature) {
		return errors.New("credential: proof of possession failed (holder key not controlled)")
	}
	return nil
}

// ---- serialization --------------------------------------------------------

// Marshal serializes the credential to portable JSON.
func (c *Credential) Marshal() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// Parse reads a credential from JSON. It performs no verification.
func Parse(data []byte) (*Credential, error) {
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("credential: parse: %w", err)
	}
	return &c, nil
}
