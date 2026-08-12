// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestPrincipalsSkipsNonDIDEntries is the regression for a defect that shipped
// unnoticed: `kessa-issuer daemon --keystore` could not load either keystore in
// this repository, because both carry a "_comment" entry documenting that the
// file is mock key management, and the daemon turned every map key into a signer.
// The proxy never tripped it, because the proxy asks for one DID by name.
func TestPrincipalsSkipsNonDIDEntries(t *testing.T) {
	ks := Keystore{
		"_comment":                             "MOCK key management. Do not copy this pattern.",
		"note":                                 "also not a principal",
		"did:web:localhost:orgs:acme":          "1111111111111111111111111111111111111111111111111111111111111111",
		"did:web:localhost:proxies:gatekeeper": "5555555555555555555555555555555555555555555555555555555555555555",
	}

	got := ks.Principals()
	want := []types.DID{
		"did:web:localhost:orgs:acme",
		"did:web:localhost:proxies:gatekeeper",
	}
	if len(got) != len(want) {
		t.Fatalf("Principals() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Principals() = %v, want %v (sorted)", got, want)
		}
	}

	// Every returned principal must actually yield a signer: the point of the
	// helper is that iterating its result cannot fail on documentation.
	for _, d := range got {
		if _, err := ks.Signer(d); err != nil {
			t.Errorf("Signer(%s): %v", d, err)
		}
	}
}

// TestPrincipalsKeepsMalformedDIDs draws the other edge of the line. Skipping
// non-DID keys must not turn into skipping keys that are unusable, or a principal
// with a corrupt seed would be silently dropped from a daemon's key set and the
// only symptom would be a key that mysteriously is not brokered.
func TestPrincipalsKeepsMalformedDIDs(t *testing.T) {
	ks := Keystore{
		"_comment":                    "documentation",
		"did:web:localhost:orgs:acme": "not-hex-at-all",
	}

	got := ks.Principals()
	if len(got) != 1 || got[0] != "did:web:localhost:orgs:acme" {
		t.Fatalf("Principals() = %v, want the malformed DID to be retained", got)
	}
	if _, err := ks.Signer(got[0]); err == nil {
		t.Fatal("a malformed seed must fail at Signer, loudly, rather than be dropped")
	}
}

// TestShippedKeystoresLoadAsPrincipals runs the helper against the actual files
// an operator is pointed at, which is where the original defect lived. A test
// over a hand-built map alone would have passed on the day the daemon was broken.
func TestShippedKeystoresLoadAsPrincipals(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "examples", "issuer", "keystore.json"),
		filepath.Join("..", "..", "scripts", "demo", "keystore.json"),
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := os.Stat(path); err != nil {
				t.Skipf("fixture not present: %v", err)
			}
			ks, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			principals := ks.Principals()
			if len(principals) == 0 {
				t.Fatal("no principals found")
			}
			if len(principals) == len(ks) {
				t.Fatal("this fixture no longer carries a non-DID entry, so it no longer covers the defect this test is for")
			}
			for _, d := range principals {
				if !strings.HasPrefix(string(d), "did:") {
					t.Errorf("Principals() returned %q, which is not a DID", d)
				}
				if _, err := ks.Signer(d); err != nil {
					t.Errorf("Signer(%s): %v", d, err)
				}
			}
		})
	}
}
