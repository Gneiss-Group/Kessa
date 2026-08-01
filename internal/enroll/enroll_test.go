// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	orgDID     = types.DID("did:web:localhost:orgs:acme")
	statusURL  = "https://localhost/status/acme.json"
	fixedNowIS = "2026-08-01T12:00:00Z"
)

func fixedNow() time.Time {
	t, _ := time.Parse(time.RFC3339, fixedNowIS)
	return t
}

// orgFixture publishes the org DID document into root and returns the org signer,
// so the enroll preflight can resolve it and issuance can be checked.
func orgFixture(t *testing.T, root string) signer.Signer {
	t.Helper()
	seed := bytes.Repeat([]byte{0x01}, 32)
	s, err := signer.NewSoftwareSignerFromSeed(orgDID, seed)
	if err != nil {
		t.Fatalf("org signer: %v", err)
	}
	if _, err := did.WriteDocument(root, did.NewDocument(orgDID, s.Public())); err != nil {
		t.Fatalf("write org DID doc: %v", err)
	}
	return s
}

// baseConfig returns a valid, deterministic software-key enrollment config.
func baseConfig(t *testing.T, root string, deviceDID types.DID, statusIndex int, seedByte byte) Config {
	t.Helper()
	return Config{
		Identity:        "alice@acme.example",
		DeviceDID:       deviceDID,
		OrgDID:          orgDID,
		OrgSigner:       orgFixture(t, root),
		MacaroonRootKey: []byte("org-macaroon-secret"),
		Identifier:      "acme-" + string(deviceDID),
		StatusURL:       statusURL,
		StatusIndex:     statusIndex,
		Root:            root,
		MappingPath:     filepath.Join(root, "map.json"),
		CredentialOut:   filepath.Join(t.TempDir(), "cred.json"),
		Device:          DeviceKeyOptions{ForceSoftware: true, Seed: bytes.Repeat([]byte{seedByte}, 32)},
		Backend:         LocalTOFU{AssumeYes: true},
		now:             fixedNow,
	}
}

func TestEnroll_EndToEnd_ChainVerifies(t *testing.T) {
	root := t.TempDir()
	cfg := baseConfig(t, root, "did:web:localhost:employees:alice-laptop", 3, 0x33)

	res, err := Enroll(cfg)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Key.Backend != backendSoftware || res.Key.Algorithm != "P-256" {
		t.Fatalf("unexpected key: %+v", res.Key)
	}
	if !strings.HasPrefix(res.Key.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint not formatted: %q", res.Key.Fingerprint)
	}

	// The one-hop org->employee chain enroll produced must verify offline against
	// the DID documents in the publication root (org published + device written by
	// enroll). This is the whole point: enroll's output is verifier-identical to
	// any other chain link.
	if err := res.Chain.Verify(did.FileResolver{Root: root}); err != nil {
		t.Fatalf("minted chain must verify: %v", err)
	}
	if res.Chain.Root() != orgDID {
		t.Fatalf("chain root = %q, want %q", res.Chain.Root(), orgDID)
	}
	if res.Chain.Actor() != cfg.DeviceDID {
		t.Fatalf("chain actor = %q, want %q", res.Chain.Actor(), cfg.DeviceDID)
	}

	// The mapping must record exactly this device under the identity.
	m, err := LoadMapping(cfg.MappingPath)
	if err != nil {
		t.Fatalf("LoadMapping: %v", err)
	}
	e := m.Employees[cfg.Identity]
	if e == nil || len(e.Credentials) != 1 {
		t.Fatalf("mapping should hold 1 credential for %q, got %+v", cfg.Identity, e)
	}
	if got := e.Credentials[0]; got.DID != cfg.DeviceDID || got.StatusIndex != 3 || got.CredentialID != res.CredentialID {
		t.Fatalf("mapping credential mismatch: %+v", got)
	}
}

func TestEnroll_DeviceLoss_SecondDeviceAppends(t *testing.T) {
	root := t.TempDir()
	mapPath := filepath.Join(root, "map.json")

	// First device.
	c1 := baseConfig(t, root, "did:web:localhost:employees:alice-laptop", 3, 0x33)
	c1.MappingPath = mapPath
	if _, err := Enroll(c1); err != nil {
		t.Fatalf("first enroll: %v", err)
	}

	// Replacement device: same identity, NEW DID -> appended, no collision.
	c2 := baseConfig(t, root, "did:web:localhost:employees:alice-phone", 4, 0x44)
	c2.OrgSigner = c1.OrgSigner // org DID doc already published; reuse the signer
	c2.MappingPath = mapPath
	c2.Identity = c1.Identity
	if _, err := Enroll(c2); err != nil {
		t.Fatalf("second enroll: %v", err)
	}

	m, err := LoadMapping(mapPath)
	if err != nil {
		t.Fatalf("LoadMapping: %v", err)
	}
	e := m.Employees[c1.Identity]
	if e == nil || len(e.Credentials) != 2 {
		t.Fatalf("identity should own 2 device credentials after replacement, got %+v", e)
	}
	if e.Credentials[0].DID == e.Credentials[1].DID {
		t.Fatal("the two device credentials must have distinct DIDs")
	}
}

// TestEnroll_DuplicateDID_RejectedBeforeSideEffect is the R4-03 regression test.
// It asserts not merely that a duplicate-DID enroll ERRORS, but that the
// uniqueness gate fires BEFORE any side effect: the first device's published DID
// document is left untouched (its key not overwritten) and the second attempt's
// credential file is never written. A test that only checked "the second enroll
// returns an error" would pass even with the gate firing too late, which is
// exactly the failure shape (R2-01/R3-01/R4-03) this codebase keeps regressing to
// — so the assertion is specifically on the absence of the side effect.
func TestEnroll_DuplicateDID_RejectedBeforeSideEffect(t *testing.T) {
	root := t.TempDir()
	mapPath := filepath.Join(root, "map.json")
	deviceDID := types.DID("did:web:localhost:employees:alice-laptop")

	c1 := baseConfig(t, root, deviceDID, 3, 0x33)
	c1.MappingPath = mapPath
	if _, err := Enroll(c1); err != nil {
		t.Fatalf("first enroll: %v", err)
	}

	// Snapshot the published DID document the first enroll wrote.
	docPath, err := did.DocumentPath(root, deviceDID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read published DID doc: %v", err)
	}

	// Re-enroll the SAME device DID with a DIFFERENT key (seed 0x55) and a fresh
	// output path. This must be refused, and must not have touched anything.
	c2 := baseConfig(t, root, deviceDID, 5, 0x55)
	c2.OrgSigner = c1.OrgSigner
	c2.MappingPath = mapPath
	c2.CredentialOut = filepath.Join(t.TempDir(), "second.json")

	_, err = Enroll(c2)
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("duplicate DID must be rejected, got %v", err)
	}

	// The published DID document must be byte-identical: the collision did NOT
	// overwrite the existing device's key.
	after, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected duplicate-DID enroll overwrote the existing device's published DID document")
	}
	// The second attempt's credential file must not exist: nothing was minted.
	if _, err := os.Stat(c2.CredentialOut); !os.IsNotExist(err) {
		t.Fatalf("a rejected enroll wrote a credential file (want none): %v", err)
	}
	// The mapping still holds exactly the first device.
	m, err := LoadMapping(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	if e := m.Employees[c1.Identity]; e == nil || len(e.Credentials) != 1 {
		t.Fatalf("mapping should still hold exactly 1 credential, got %+v", e)
	}
}

func TestEnroll_UnresolvableOrgDID_FailsPreflight(t *testing.T) {
	root := t.TempDir() // org DID doc deliberately NOT published here
	seed := bytes.Repeat([]byte{0x01}, 32)
	orgSigner, _ := signer.NewSoftwareSignerFromSeed(orgDID, seed)

	cfg := Config{
		Identity:        "alice@acme.example",
		DeviceDID:       "did:web:localhost:employees:alice-laptop",
		OrgDID:          orgDID,
		OrgSigner:       orgSigner,
		MacaroonRootKey: []byte("k"),
		Identifier:      "id",
		StatusURL:       statusURL,
		StatusIndex:     0,
		Root:            root,
		MappingPath:     filepath.Join(root, "map.json"),
		CredentialOut:   filepath.Join(root, "cred.json"),
		Device:          DeviceKeyOptions{ForceSoftware: true, Seed: bytes.Repeat([]byte{0x33}, 32)},
		Backend:         LocalTOFU{AssumeYes: true},
		now:             fixedNow,
	}
	_, err := Enroll(cfg)
	if err == nil || !strings.Contains(err.Error(), "not resolvable") {
		t.Fatalf("unresolvable org DID must fail preflight, got %v", err)
	}
}

func TestEnroll_DeclinedConfirmation_WritesNothing(t *testing.T) {
	root := t.TempDir()
	cfg := baseConfig(t, root, "did:web:localhost:employees:alice-laptop", 3, 0x33)
	cfg.Backend = LocalTOFU{In: strings.NewReader("no\n")} // operator declines

	if _, err := Enroll(cfg); err == nil {
		t.Fatal("declined enrollment must return an error")
	}
	// Nothing should have been minted or mapped.
	if _, err := LoadMapping(cfg.MappingPath); err != nil {
		t.Fatalf("mapping load: %v", err)
	}
	m, _ := LoadMapping(cfg.MappingPath)
	if len(m.Employees) != 0 {
		t.Fatalf("declined enrollment left a mapping entry: %+v", m.Employees)
	}
}

func TestProvisionDeviceKey_SoftwareDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x33}, 32)
	s1, i1, err := ProvisionDeviceKey("did:x", DeviceKeyOptions{ForceSoftware: true, Seed: seed})
	if err != nil {
		t.Fatalf("provision 1: %v", err)
	}
	s2, i2, err := ProvisionDeviceKey("did:x", DeviceKeyOptions{ForceSoftware: true, Seed: seed})
	if err != nil {
		t.Fatalf("provision 2: %v", err)
	}
	if i1.Fingerprint != i2.Fingerprint {
		t.Fatalf("same seed must yield same fingerprint: %q vs %q", i1.Fingerprint, i2.Fingerprint)
	}
	if !signer.KeysEqual(s1.Public(), s2.Public()) {
		t.Fatal("same seed must yield the same public key")
	}
	if i1.Algorithm != "P-256" || i1.Backend != backendSoftware {
		t.Fatalf("unexpected key info: %+v", i1)
	}
}

func TestLocalTOFU_Confirm(t *testing.T) {
	cases := []struct {
		name    string
		b       LocalTOFU
		wantErr bool
	}{
		{"assume-yes", LocalTOFU{AssumeYes: true}, false},
		{"typed-yes", LocalTOFU{In: strings.NewReader("yes\n"), Out: &bytes.Buffer{}}, false},
		{"typed-no", LocalTOFU{In: strings.NewReader("no\n"), Out: &bytes.Buffer{}}, true},
		{"empty-eof", LocalTOFU{In: strings.NewReader(""), Out: &bytes.Buffer{}}, true},
		{"nil-reader", LocalTOFU{Out: &bytes.Buffer{}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.b.Confirm(ConfirmRequest{Identity: "a", DID: "did:x", Fingerprint: "SHA256:z", Algorithm: "P-256"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Confirm err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMapping_MissingFileIsEmpty(t *testing.T) {
	m, err := LoadMapping(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing mapping should be empty, got %v", err)
	}
	if len(m.Employees) != 0 {
		t.Fatalf("expected empty mapping, got %+v", m.Employees)
	}
}

func TestMapping_AddDuplicateDIDAcrossIdentities(t *testing.T) {
	m := NewMapping()
	if err := m.AddCredential("alice", Credential{DID: "did:x"}); err != nil {
		t.Fatalf("add alice: %v", err)
	}
	// Same DID under a DIFFERENT identity is still a collision.
	if err := m.AddCredential("bob", Credential{DID: "did:x"}); err == nil {
		t.Fatal("same DID under a different identity must be rejected")
	}
}

func TestChain_MintedByEnroll_IsSingleHop(t *testing.T) {
	root := t.TempDir()
	cfg := baseConfig(t, root, "did:web:localhost:employees:alice-laptop", 1, 0x33)
	res, err := Enroll(cfg)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// Re-read the on-disk credential to confirm it round-trips as a chain.
	data, err := os.ReadFile(cfg.CredentialOut)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	ch, err := chain.Parse(data)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if len(ch.Links) != 1 {
		t.Fatalf("enroll credential should be a single hop, got %d", len(ch.Links))
	}
	if ch.Links[0].Credential.Issuer != orgDID || ch.Links[0].Credential.Subject != res.DeviceDID {
		t.Fatalf("hop is not org->employee: %+v", ch.Links[0].Credential)
	}
}
