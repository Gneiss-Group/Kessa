// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package signer defines the signing seam for Kessa. Everything that needs to
// produce a signature (issuers minting credentials, the proxy signing audit
// entries, holders answering proof-of-possession challenges) does so through
// the Signer interface, never by touching a private key directly.
//
// Two signature algorithms are supported, and the seam is deliberately
// algorithm-agile: a public key is a crypto.PublicKey, and Verify dispatches on
// its concrete type. This is what lets the employee/device key be a
// hardware-generated NIST P-256 key (Secure Enclave and most TPMs cannot
// generate Ed25519 at all) while every other principal, org, proxy, status
// issuer, stays software Ed25519. The verifier treats every key identically and
// accepts either algorithm for any of them; "scoped to the employee key" is a
// property of what enrollment GENERATES in hardware, not a rule the role-blind
// verification path enforces.
//
//   - Ed25519 signs the message directly (no pre-hash), the default for every
//     software-minted key.
//   - ECDSA/P-256 signs SHA-256(message) and emits an ASN.1 DER signature, which
//     is exactly the shape a Secure Enclave / TPM signing operation returns, so a
//     hardware backend drops in behind this seam with no format change.
//
// SoftwareSigner (Ed25519) and ECDSASigner (P-256) are the in-memory
// implementations; their private keys exist in process memory, which is the
// documented non-production path. The hardware side of the seam is no longer
// hypothetical: internal/signer/enclave holds a macOS Secure Enclave backend
// whose P-256 key is non-extractable, and it satisfies this interface returning
// the same DER-encoded signatures ECDSASigner does, which is why nothing above
// this package changed when it landed. TPM (Linux) and HSM backends do not exist;
// see UPCOMING.md. What each backend does and does not prove is stated in
// docs/signer.md.
package signer

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Signer produces signatures on behalf of a single DID-identified principal.
// Implementations must be safe to call concurrently.
type Signer interface {
	// Sign returns a signature over data. The algorithm is the implementation's
	// own (Ed25519 over the raw message, or ECDSA/P-256 over SHA-256(data)); a
	// caller never needs to know which, because Verify recovers it from the
	// public key.
	Sign(data []byte) (sig []byte, err error)
	// Public returns the public half of the signing key, for verification and
	// for publication in a DID document. Its concrete type (ed25519.PublicKey or
	// *ecdsa.PublicKey) is what Verify dispatches on.
	Public() crypto.PublicKey
	// DID returns the identifier this signer speaks for.
	DID() types.DID
}

// SoftwareSigner is an Ed25519 Signer whose private key lives in process
// memory. It is the default (and, for the POC, only) implementation.
type SoftwareSigner struct {
	did  types.DID
	priv ed25519.PrivateKey
}

// compile-time assertion that SoftwareSigner satisfies Signer.
var _ Signer = (*SoftwareSigner)(nil)

// NewSoftwareSigner generates a fresh random Ed25519 key for did.
func NewSoftwareSigner(did types.DID) (*SoftwareSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate key: %w", err)
	}
	return &SoftwareSigner{did: did, priv: priv}, nil
}

// NewSoftwareSignerFromSeed builds a deterministic signer from a 32-byte seed.
// This is how testdata fixtures and the demo obtain stable, reproducible keys:
// the same seed always yields the same key pair, which keeps `make demo`
// deterministic. Never use a fixed seed for anything real.
func NewSoftwareSignerFromSeed(did types.DID, seed []byte) (*SoftwareSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signer: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &SoftwareSigner{did: did, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func (s *SoftwareSigner) Sign(data []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("signer: no private key")
	}
	return ed25519.Sign(s.priv, data), nil
}

func (s *SoftwareSigner) Public() crypto.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

func (s *SoftwareSigner) DID() types.DID { return s.did }

// ECDSASigner is a NIST P-256 Signer whose private key lives in process memory.
// It exists so the whole scoped-P-256 verification path can be exercised
// deterministically in tests and demos without real hardware; a Secure Enclave /
// TPM backend produces the same DER-encoded P-256 signatures over the same
// SHA-256(message) input, so it substitutes behind this same interface.
//
// Note it is NOT deterministic across signings: crypto/ecdsa draws a fresh nonce
// per signature (the stdlib offers no RFC 6979 mode without hand-rolling it, which
// the no-dependency discipline rules out). Fixtures that need stability therefore
// VERIFY a P-256 signature rather than byte-comparing it; a real hardware key is
// non-deterministic for the same reason, so this matches production behavior.
type ECDSASigner struct {
	did  types.DID
	priv *ecdsa.PrivateKey
}

var _ Signer = (*ECDSASigner)(nil)

// NewECDSASigner generates a fresh random P-256 key for did.
func NewECDSASigner(did types.DID) (*ECDSASigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate P-256 key: %w", err)
	}
	return &ECDSASigner{did: did, priv: priv}, nil
}

// NewECDSASignerFromSeed builds a deterministic P-256 KEY (not deterministic
// signatures) from a 32-byte seed, so tests and demos obtain a reproducible key
// pair. Never use a fixed seed for anything real.
//
// It derives candidate scalars from a deterministic seed stream and imports the
// first valid one through crypto/ecdh, which both range-checks the scalar and
// computes the public point, so no deprecated elliptic method (ScalarBaseMult,
// IsOnCurve) or curve-order arithmetic is needed. The resulting scalar and point
// are then adapted into an *ecdsa.PrivateKey, because signing uses ecdsa.SignASN1
// (ecdh keys cannot sign). ecdsa.GenerateKey is deliberately NOT used here: it
// reads a hedge byte from its reader (randutil.MaybeReadByte), so it is
// non-deterministic even given a deterministic reader.
func NewECDSASignerFromSeed(did types.DID, seed []byte) (*ECDSASigner, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("signer: P-256 seed must be 32 bytes, got %d", len(seed))
	}
	r := &seededReader{seed: seed}
	// A random 32-byte value is a valid P-256 scalar with overwhelming probability
	// (order n is within ~2^-32 of 2^256), so this loop effectively never repeats;
	// the bound just guarantees termination.
	for attempt := 0; attempt < 128; attempt++ {
		var scalar [32]byte
		_, _ = r.Read(scalar[:]) // seededReader always fills fully, never errors
		ek, err := ecdh.P256().NewPrivateKey(scalar[:])
		if err != nil {
			continue // scalar out of [1, n-1]; take the next deterministic block
		}
		pub := ek.PublicKey().Bytes() // SEC1 uncompressed: 0x04 || X(32) || Y(32)
		priv := &ecdsa.PrivateKey{
			D: new(big.Int).SetBytes(scalar[:]),
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(pub[1 : 1+32]),
				Y:     new(big.Int).SetBytes(pub[1+32:]),
			},
		}
		return &ECDSASigner{did: did, priv: priv}, nil
	}
	return nil, errors.New("signer: could not derive a valid P-256 scalar from seed")
}

// seededReader is a deterministic byte stream: SHA-256(seed || counter) blocks.
// It exists solely to make NewECDSASignerFromSeed reproducible within a run; it
// is not a CSPRNG and must never be used to generate a real key.
type seededReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.counter)
			r.counter++
			block := sha256.Sum256(append(append([]byte{}, r.seed...), c[:]...))
			r.buf = block[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}
	return n, nil
}

func (s *ECDSASigner) Sign(data []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("signer: no private key")
	}
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
}

func (s *ECDSASigner) Public() crypto.PublicKey { return &s.priv.PublicKey }

func (s *ECDSASigner) DID() types.DID { return s.did }

// Verify checks a signature under pub, dispatching on the key's concrete type.
// It is the single verification primitive every path in Kessa routes through, so
// algorithm agility lives in exactly one place. Verification never needs a Signer
// (only the public key, which callers resolve from a DID document), so this is a
// free function.
//
//   - ed25519.PublicKey: Ed25519 over the raw message.
//   - *ecdsa.PublicKey (P-256): ECDSA over SHA-256(message), ASN.1 DER signature.
//
// An unknown key type, or a P-256 key on any other curve, returns false rather
// than panicking: a key we cannot verify is a failed verification, never a skip.
//
// PROPERTY NOTE (R3-03): the P-256 path does NOT enforce canonical low-S, so
// ECDSA signatures are malleable: given a valid (r, s), (r, n-s) also verifies.
// Ed25519 is non-malleable, so this property is specific to the P-256
// (employee/device) key path. This is safe TODAY because no Kessa mechanism
// treats a signature as an identity, a nonce, or a dedup key: PoP and approval
// are bound to (action, seq, prevHash), so a malleated signature authorizes the
// exact same thing at the exact same slot, and forging a new audit entry needs
// the enforcement point's key regardless. If a future mechanism ever makes a
// signature identity-bearing (e.g. dedup-by-signature, or a delivery receipt),
// enforce low-S here FIRST.
func Verify(pub crypto.PublicKey, data, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(k, data, sig)
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return false
		}
		digest := sha256.Sum256(data)
		return ecdsa.VerifyASN1(k, digest[:], sig)
	default:
		return false
	}
}

// KeysEqual reports whether two resolved public keys are the same key, across
// either supported algorithm. Both ed25519.PublicKey and *ecdsa.PublicKey
// implement Equal(crypto.PublicKey) bool, which also returns false for a
// type mismatch, so this is the one comparison the holder-key/subject-key binding
// check uses.
func KeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if a == nil || b == nil {
		return false
	}
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
