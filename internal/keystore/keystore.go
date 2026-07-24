// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Package keystore is MOCK key management for the POC command-line tools.
//
// It maps a DID to a hex-encoded 32-byte Ed25519 seed and materializes a
// software signer on demand. This is deliberately NOT how a real deployment
// works: real principals hold their own private keys behind the signer.Signer
// hardware seam (TPM / Secure Enclave / HSM), the agent signs its own
// proof-of-possession, and the human signs their own approval, none of it lives
// in one file readable by the proxy. Seeds live here in the clear only so the POC
// and `make demo` are deterministic and reproducible. Do not copy this pattern
// into anything real.
package keystore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Keystore maps a principal DID to a hex Ed25519 seed.
type Keystore map[types.DID]string

// Load reads a keystore JSON file.
func Load(path string) (Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read %q: %w", path, err)
	}
	var ks Keystore
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("keystore: parse %q: %w", path, err)
	}
	return ks, nil
}

// Signer materializes a software signer for a principal.
func (ks Keystore) Signer(d types.DID) (signer.Signer, error) {
	h, ok := ks[d]
	if !ok {
		return nil, fmt.Errorf("keystore: no seed for %q", d)
	}
	seed, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("keystore: seed for %q is not hex: %w", d, err)
	}
	return signer.NewSoftwareSignerFromSeed(d, seed)
}
