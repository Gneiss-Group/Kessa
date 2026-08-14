// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSpec writes a spec file into a temp dir and returns its path.
func writeSpec(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// validSpec is the smallest spec that passes validate(), so a test about
// PARSING is not accidentally satisfied by a validation error instead.
const validSpec = `{
  "rootKeyHex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "identifier": "test",
  "location": "https://example.invalid",
  "status": {"url": "https://example.invalid/status.json", "issuer": "did:web:example.invalid:orgs:acme", "bits": 131072},
  "hops": [{"issuer": "did:web:example.invalid:orgs:acme", "subject": "did:web:example.invalid:agents:worker"}]
}`

func TestSpecRejectsMisspelledOptionalField(t *testing.T) {
	// This is the reason loadJSON is strict at all.
	//
	// extraPrincipals is where the enforcement point's DID goes, and it is
	// OPTIONAL, so no required-field check can speak for it. Misspelled, the old
	// lenient parse succeeded, left the slice empty, and published a root with no
	// DID document for the enforcement point. Every signature that root was
	// supposed to let a verifier check would then be unverifiable, and nothing
	// anywhere reported a problem.
	body := strings.Replace(validSpec,
		`"hops":`,
		`"extraPrinciples": ["did:web:example.invalid:proxies:gatekeeper"], "hops":`, 1)

	if _, err := loadJSON[Spec](writeSpec(t, body)); err == nil {
		t.Fatal("a misspelled optional field parsed cleanly; the typo is silent again")
	} else if !strings.Contains(err.Error(), "extraPrinciples") {
		t.Errorf("error does not name the offending field, so it does not help anyone fix it: %v", err)
	}
}

func TestSpecRejectsUnknownFieldInNestedStruct(t *testing.T) {
	// Strictness has to reach the nested structs too. status and hops are where
	// the revocation wiring lives, and a typo there is as quiet as one at the top
	// level.
	for name, body := range map[string]string{
		"status": strings.Replace(validSpec, `"bits": 131072`, `"bits": 131072, "isuer": "did:web:x"`, 1),
		"hop":    strings.Replace(validSpec, `"subject": "did:web:example.invalid:agents:worker"`, `"subject": "did:web:example.invalid:agents:worker", "statusIndx": 42`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadJSON[Spec](writeSpec(t, body)); err == nil {
				t.Errorf("unknown field in %s parsed cleanly", name)
			}
		})
	}
}

func TestSpecAcceptsCommentKey(t *testing.T) {
	// The three spec files in this repository carry a "_comment" recording that
	// the committed rootKeyHex is a non-secret demo value. If strictness rejected
	// it, the pressure would be to delete that text, which is the wrong direction:
	// it is the only thing explaining why a key-shaped string is in the tree.
	body := strings.Replace(validSpec, `{`, `{"_comment": "NON-SECRET demo value",`, 1)

	spec, err := loadJSON[Spec](writeSpec(t, body))
	if err != nil {
		t.Fatalf("a spec carrying _comment was rejected: %v", err)
	}
	if err := spec.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSpecRejectsTrailingContent(t *testing.T) {
	// Two concatenated objects, where only the first would ever be read. The
	// second one is invisible rather than merged, so an operator editing "the
	// spec" could be editing text the tool never looks at.
	if _, err := loadJSON[Spec](writeSpec(t, validSpec+"\n"+validSpec)); err == nil {
		t.Fatal("trailing object accepted")
	}
}

func TestKeystoreStillAcceptsCommentEntry(t *testing.T) {
	// The counterpart assertion, and the one most likely to be wrong later.
	//
	// Keystore is a MAP, so DisallowUnknownFields does nothing to it: a map has
	// no unknown fields. "_comment" is a legitimate key and stays one, which is
	// why keystore.Principals has to skip non-DID keys rather than the decoder
	// rejecting them. Someone reading the strictness change could reasonably
	// assume it closed that hole. It did not, and this test says so out loud.
	p := filepath.Join(t.TempDir(), "keystore.json")
	body := `{"_comment": "MOCK key management", "did:web:example.invalid:orgs:acme": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ks, err := loadJSON[Keystore](p)
	if err != nil {
		t.Fatalf("keystore with a _comment entry was rejected: %v", err)
	}
	if _, ok := ks["_comment"]; !ok {
		t.Error("the _comment entry was dropped; Principals is what is supposed to skip it, not the decoder")
	}
	if got := ks.Principals(); len(got) != 1 {
		t.Errorf("Principals() = %v, want exactly the one DID", got)
	}
}
