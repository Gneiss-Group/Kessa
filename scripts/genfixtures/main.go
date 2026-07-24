// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Command genfixtures regenerates the did:web testdata fixtures from fixed
// seeds. It is deliberately stdlib-only and independent of internal/did so that
// the DID package's tests are checked against a second implementation.
//
// Usage: go run ./scripts/genfixtures <dids-root>
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

func doc(did string, pub ed25519.PublicKey) map[string]any {
	vm := did + "#key-1"
	return map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": did,
		"verificationMethod": []map[string]any{{
			"id":         vm,
			"type":       "JsonWebKey2020",
			"controller": did,
			"publicKeyJwk": map[string]string{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		"authentication":  []string{vm},
		"assertionMethod": []string{vm},
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genfixtures <dids-root>")
		os.Exit(2)
	}
	root := os.Args[1]
	// Seeds are fixed so every fixture (and the demo) is reproducible. The
	// principals below form the human -> org -> agent -> sub-agent chain used by
	// the delegation fixtures, plus a second org for the cross-org scenario and
	// the enforcement point that signs audit entries.
	fixtures := []struct {
		did  string
		seed byte
		path string
	}{
		{"did:web:localhost:orgs:acme", 0x11, "localhost/orgs/acme/did.json"},
		{"did:web:localhost:orgs:bravo", 0x22, "localhost/orgs/bravo/did.json"},
		{"did:web:localhost", 0x44, "localhost/.well-known/did.json"},
		{"did:web:localhost:people:alice", 0x31, "localhost/people/alice/did.json"},
		{"did:web:localhost:agents:worker", 0x33, "localhost/agents/worker/did.json"},
		{"did:web:localhost:agents:helper", 0x34, "localhost/agents/helper/did.json"},
		{"did:web:localhost:proxies:gatekeeper", 0x55, "localhost/proxies/gatekeeper/did.json"},
	}
	for _, f := range fixtures {
		pub := ed25519.NewKeyFromSeed(seed32(f.seed)).Public().(ed25519.PublicKey)
		full := filepath.Join(root, f.path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			panic(err)
		}
		b, err := json.MarshalIndent(doc(f.did, pub), "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(full, append(b, '\n'), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s (seed 0x%02x)\n", full, f.seed)
	}
}
