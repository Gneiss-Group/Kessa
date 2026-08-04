// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// mappingVersion is the on-disk schema version for the employee->credential map.
const mappingVersion = 1

// Mapping is the durable, org-side record connecting each employee identity to
// the device-bound credential instances currently (or formerly) authorized to
// act as that employee.
//
// It is the byproduct that makes revocation TARGETABLE. The enforcement side of
// revocation (flip a status-list bit, already built and adversarially tested) is
// useless without knowing WHICH bit belongs to WHICH device; this map is that
// index. It is deliberately not a separate bookkeeping chore: every enrollment
// appends exactly one credential record here, so the map is always a faithful
// mirror of what has been issued.
//
// The identity model is WebAuthn-shaped: one durable employee identity (the map
// key) owns N device credentials (one per registered device key), each with its
// own DID and its own independently-revocable status bit. Device loss/replacement
// is therefore symmetric with initial enrollment: enroll a new device (a new
// credential appended under the same identity) and revoke the old one, with no
// new mechanism. A DID identifies exactly one device key and is unique across the
// whole map (see AddCredential), so re-enrolling the same identity on a new
// device never collides, while a duplicate DID is refused as the real error it is.
type Mapping struct {
	Version   int                  `json:"version"`
	Employees map[string]*Employee `json:"employees"`
}

// Employee is one durable identity and its device credentials, newest last.
type Employee struct {
	Identity    string       `json:"identity"`
	Credentials []Credential `json:"credentials"`
}

// Credential is one device-bound credential instance issued to an employee. It
// records everything needed to revoke it later (StatusURL + StatusIndex) and to
// recognize the device key it binds (KeyFingerprint), without ever holding a
// private key.
type Credential struct {
	DID            types.DID `json:"did"`            // the device's employee DID
	CredentialID   string    `json:"credentialID"`   // export.CredentialID of the org->employee credential
	StatusURL      string    `json:"statusURL"`      // status list this credential's bit lives in
	StatusIndex    int       `json:"statusIndex"`    // which bit to flip to revoke this device
	KeyFingerprint string    `json:"keyFingerprint"` // SHA-256 of the device public key JWK
	KeyBackend     string    `json:"keyBackend"`     // "secure-enclave" or "software"
	KeyTag         string    `json:"keyTag,omitempty"`
	Algorithm      string    `json:"algorithm"`  // "P-256" or "Ed25519"
	EnrolledAt     time.Time `json:"enrolledAt"` // UTC
	Revoked        bool      `json:"revoked"`    // set when the operator revokes this device
}

// NewMapping returns an empty mapping.
func NewMapping() *Mapping {
	return &Mapping{Version: mappingVersion, Employees: map[string]*Employee{}}
}

// LoadMapping reads a mapping file. A missing file is not an error: enrollment
// bootstraps the map on first use, so LoadMapping returns a fresh empty mapping
// for a path that does not yet exist.
func LoadMapping(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewMapping(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("enroll: read mapping %q: %w", path, err)
	}
	var m Mapping
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("enroll: parse mapping %q: %w", path, err)
	}
	if m.Version != mappingVersion {
		return nil, fmt.Errorf("enroll: mapping %q is schema version %d, want %d", path, m.Version, mappingVersion)
	}
	if m.Employees == nil {
		m.Employees = map[string]*Employee{}
	}
	return &m, nil
}

// findByDID reports whether any employee already holds a credential for did.
func (m *Mapping) findByDID(did types.DID) (string, bool) {
	for id, e := range m.Employees {
		for _, c := range e.Credentials {
			if c.DID == did {
				return id, true
			}
		}
	}
	return "", false
}

// AddCredential appends cred under identity, creating the employee if new. It is
// append-only: an existing identity gains another device credential (the
// device-loss / multi-device case) rather than being overwritten.
//
// The one hard rule is DID uniqueness across the whole map. A DID names one
// device key; the same DID appearing twice would mean two device keys claim one
// identifier, which the chain's holder-key binding could not disambiguate. So a
// duplicate DID is refused: this is what lets re-enrolling an existing identity
// on a NEW device be a safe no-collision append, while catching an accidental
// re-use of a device DID as the genuine error it is.
func (m *Mapping) AddCredential(identity string, cred Credential) error {
	if identity == "" {
		return fmt.Errorf("enroll: mapping: empty identity")
	}
	if cred.DID == "" {
		return fmt.Errorf("enroll: mapping: credential has empty DID")
	}
	if owner, ok := m.findByDID(cred.DID); ok {
		return fmt.Errorf("enroll: mapping: DID %q is already registered to identity %q", cred.DID, owner)
	}
	e := m.Employees[identity]
	if e == nil {
		e = &Employee{Identity: identity}
		m.Employees[identity] = e
	}
	e.Credentials = append(e.Credentials, cred)
	return nil
}

// Save writes the mapping atomically (temp file + rename) with 0600 permissions,
// since it records which devices are authorized for which humans.
func (m *Mapping) Save(path string) error {
	if m.Version == 0 {
		m.Version = mappingVersion
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("enroll: marshal mapping: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("enroll: create mapping dir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".mapping-*")
	if err != nil {
		return fmt.Errorf("enroll: temp mapping: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("enroll: chmod mapping: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("enroll: write mapping: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("enroll: close mapping: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("enroll: install mapping %q: %w", path, err)
	}
	return nil
}

// Identities returns the employee identities in sorted order (stable output for
// callers that list the map).
func (m *Mapping) Identities() []string {
	out := make([]string, 0, len(m.Employees))
	for id := range m.Employees {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
