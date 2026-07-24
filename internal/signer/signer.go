// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package signer defines the signing seam for Kessa. Everything that needs to
// produce a signature (issuers minting credentials, the proxy signing audit
// entries, holders answering proof-of-possession challenges) does so through
// the Signer interface, never by touching a private key directly.
//
// The only implementation here is SoftwareSigner, an in-memory Ed25519 key.
// Hardware binding (TPM / Secure Enclave / HSM) is explicitly MOCKED for the
// POC: a future HardwareSigner satisfies this same interface, so nothing above
// this package needs to change when real hardware binding lands. That seam is
// the whole point of routing through an interface.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Signer produces Ed25519 signatures on behalf of a single DID-identified
// principal. Implementations must be safe to call concurrently.
type Signer interface {
	// Sign returns an Ed25519 signature over data.
	Sign(data []byte) (sig []byte, err error)
	// Public returns the public half of the signing key, for verification and
	// for publication in a DID document.
	Public() ed25519.PublicKey
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

func (s *SoftwareSigner) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

func (s *SoftwareSigner) DID() types.DID { return s.did }

// Verify is a convenience wrapper over ed25519.Verify. Verification never needs
// a Signer (only the public key, which callers resolve from a DID document)
// so this is a free function, not a method.
func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, data, sig)
}
