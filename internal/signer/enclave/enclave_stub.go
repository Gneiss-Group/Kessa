// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin || !cgo

// This is the no-secure-element build: everything that is not darwin+cgo. It
// exists so the package compiles and can be imported anywhere (Linux CI, the
// pure-Go verifier, a CGO_ENABLED=0 build) while the real implementation lives in
// enclave_darwin.go. Every constructor returns ErrUnsupported; a cross-platform
// caller checks Available first and falls back to a software signer.
package enclave

import (
	"crypto"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Available reports whether a secure-element backend exists in this build. Always
// false here.
func Available() bool { return false }

// Signer is the no-op stand-in; its methods never run because no constructor
// returns one on this build.
type Signer struct{}

// Generate is unsupported on this build.
func Generate(did types.DID, tag []byte, policy Policy) (*Signer, error) {
	return nil, ErrUnsupported
}

// GenerateEphemeral is unsupported on this build.
func GenerateEphemeral(did types.DID, policy Policy) (*Signer, error) {
	return nil, ErrUnsupported
}

// Load is unsupported on this build.
func Load(did types.DID, tag []byte) (*Signer, error) { return nil, ErrUnsupported }

// Delete is unsupported on this build.
func Delete(tag []byte) error { return ErrUnsupported }

// Sign is unreachable (no Signer is ever constructed on this build).
func (s *Signer) Sign(data []byte) ([]byte, error) { return nil, ErrUnsupported }

// Public is unreachable on this build.
func (s *Signer) Public() crypto.PublicKey { return nil }

// DID is unreachable on this build.
func (s *Signer) DID() types.DID { return "" }

// Close is unreachable on this build.
func (s *Signer) Close() error { return nil }
