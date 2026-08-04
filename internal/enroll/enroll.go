// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Package enroll is the on-device enrollment ceremony for the employee/device
// key: generate a hardware-backed (or, for CI/dev, software) key, confirm it
// trust-on-first-use, publish its DID document, mint the org->employee credential
// that positions it in the delegation chain, and record it in the durable
// employee->credential mapping that makes revocation targetable.
//
// It sits at the generation/enrollment layer, which is exactly where the
// employee-key scoping lives: this is the ONLY place a hardware P-256 key is ever
// minted, while org/proxy/status keys stay software Ed25519 simply because that
// is what mints them. The verifier remains role-blind and algorithm-agile; enroll
// does not touch it.
//
// The chain shape it produces is org -> employee(device key) -> agent. Enroll
// builds the org -> employee hop (the employee's own credential instance); the
// employee -> agent hop is a later, separate act (the employee issuing to an
// agent from their own device). The grant caveats enroll writes onto the
// org -> employee credential deliberately do NOT constrain what kind of principal
// the employee may issue to next: a service/automation identity is a valid next
// hop under the identical credential format, so this output never needs reworking
// when that path is built. See AGENT-only forward-compat note on Config.Caveats.
//
// This package is AGPL-3.0: enrollment mints authority (it issues a credential),
// which is protective-tier per the open-core boundary. The hardware Signer it
// drives (internal/signer/enclave) stays Apache: the mechanism is open; issuing
// authority with it is not.
package enroll

import (
	"errors"
	"fmt"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Config is everything one enrollment needs. Org-side secrets (the org signer,
// the macaroon root key) are supplied by the caller; enroll never reads a
// keystore itself, so the same logic serves the mock-keystore CLI and any real
// key custody without change.
type Config struct {
	// Identity is the durable employee label the credential is grouped under in the
	// mapping (e.g. an email or username). Stable across device replacements.
	Identity string
	// DeviceDID is this specific device's employee DID (the credential subject).
	// Unique per device; a second device for the same Identity uses a new DeviceDID.
	DeviceDID types.DID

	// OrgDID is the issuing organization (the credential issuer / chain root).
	OrgDID types.DID
	// OrgSigner signs the issuance. Its DID must equal OrgDID. Software Ed25519 in
	// the mock; the org key is not the one enrollment mints in hardware.
	OrgSigner signer.Signer
	// MacaroonRootKey is the org's secret HMAC key for this credential's macaroon.
	MacaroonRootKey []byte
	// Identifier is the macaroon identifier (credential id) for this hop.
	Identifier string
	// Location is the macaroon location (informational).
	Location string

	// Caveats scope the authority granted to the employee. FORWARD-COMPAT RULE:
	// none of these may constrain the employee to issuing only to an "agent": the
	// next hop must be free to be a service/automation identity too. The macaroon
	// vocabulary has no next-hop-kind caveat, so this holds by construction; the
	// rule is stated so a future caveat addition does not quietly break it.
	Caveats []macaroon.Caveat

	// StatusURL / StatusIndex place this credential in the org's published status
	// list so it can later be revoked (the mapping remembers which bit).
	StatusURL   string
	StatusIndex int

	// Root is the publication root: where the device DID document is written, and,
	// unless Resolver is set, where the org DID document is resolved from for the
	// connectivity preflight.
	Root string
	// Resolver overrides how the org DID is resolved in the preflight. Defaults to
	// a FileResolver over Root. An HTTPResolver here checks a live did:web instead.
	Resolver did.Resolver

	// MappingPath is the employee->credential mapping file (created if absent).
	MappingPath string
	// CredentialOut is where the minted org->employee credential (a one-hop chain)
	// is written. It is not a public artifact; keep it out of Root.
	CredentialOut string

	// Device controls device-key generation (hardware vs software, tag, seed).
	Device DeviceKeyOptions
	// Backend authenticates the enrollment (defaults to interactive LocalTOFU).
	Backend Backend

	// now is injectable for deterministic tests; nil uses time.Now.
	now func() time.Time
}

// Result summarizes a completed enrollment.
type Result struct {
	Identity      string
	DeviceDID     types.DID
	CredentialID  string
	Key           KeyInfo
	DIDDocPath    string
	CredentialOut string
	MappingPath   string
	BackendName   string
	Chain         *chain.Chain // the one-hop org->employee chain, for callers that compose further
}

func (c *Config) validate() error {
	switch {
	case c.Identity == "":
		return errors.New("enroll: identity is required")
	case c.DeviceDID == "":
		return errors.New("enroll: device DID is required")
	case c.OrgDID == "":
		return errors.New("enroll: org DID is required")
	case c.OrgSigner == nil:
		return errors.New("enroll: org signer is required")
	case c.OrgSigner.DID() != c.OrgDID:
		return fmt.Errorf("enroll: org signer DID %q does not match org DID %q", c.OrgSigner.DID(), c.OrgDID)
	case c.DeviceDID == c.OrgDID:
		return errors.New("enroll: device DID must differ from org DID")
	case len(c.MacaroonRootKey) == 0:
		return errors.New("enroll: macaroon root key is required")
	case c.Identifier == "":
		return errors.New("enroll: macaroon identifier is required")
	case c.StatusURL == "":
		return errors.New("enroll: status URL is required")
	case c.StatusIndex < 0:
		return errors.New("enroll: status index must be >= 0")
	case c.Root == "":
		return errors.New("enroll: publication root is required")
	case c.MappingPath == "":
		return errors.New("enroll: mapping path is required")
	case c.CredentialOut == "":
		return errors.New("enroll: credential output path is required")
	}
	return nil
}

// Enroll runs the ceremony end to end. Ordering is deliberate and load-bearing:
// every check that can reject an enrollment: org-DID preflight, DID-uniqueness,
// and the trust-on-first-use confirmation: runs BEFORE any side effect, so a
// rejected enrollment leaves NO partial state: no generated key, no overwritten
// DID document, no credential, no mapping entry.
//
// The DID-uniqueness gate in particular runs up front, not at the mapping append
// at the end (R4-03). A device DID identifies one device key and its published DID
// document; discovering a collision only AFTER WriteDocument had already
// overwritten an existing device's published key would silently break that
// device's credential (its bound key would no longer match the published one).
// Checking first is what makes the no-partial-state guarantee true rather than
// aspirational. (This is the third instance of the codebase's recurring
// gate-after-side-effect shape (R2-01, R3-01, R4-03), so it is guarded here and
// asserted by a dedicated test.)
func Enroll(cfg Config) (result *Result, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	backend := cfg.Backend
	if backend == nil {
		return nil, errors.New("enroll: no enrollment backend configured")
	}

	// 1. Preflight: the issuer must be able to reach and parse the org's own
	// published DID document before it registers anyone against it. This is the
	// issuer-side sharp end of the root-of-trust question: an employee credential
	// whose issuer DID resolves to nothing is dead on arrival at the verifier, so
	// fail loudly here rather than mint it. (It does NOT cover org-root enrollment
	// or key rotation: those stay out of scope.)
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = did.FileResolver{Root: cfg.Root}
	}
	if _, err := did.ResolveKey(resolver, cfg.OrgDID); err != nil {
		return nil, fmt.Errorf("enroll: org DID %q is not resolvable (publish the org DID document first): %w", cfg.OrgDID, err)
	}

	// 2. DID-uniqueness gate, UP FRONT (R4-03): load the mapping and reject a
	// duplicate DID before generating a key or writing anything. AddCredential
	// re-checks at the end (harmless, and it closes the tiny window), but this early
	// check is what guarantees no side effect precedes the rejection.
	m, err := LoadMapping(cfg.MappingPath)
	if err != nil {
		return nil, err
	}
	if owner, dup := m.findByDID(cfg.DeviceDID); dup {
		return nil, fmt.Errorf("enroll: mapping: DID %q is already registered to identity %q", cfg.DeviceDID, owner)
	}

	// 3. Generate the device key (hardware if available, else software).
	deviceSigner, keyInfo, err := ProvisionDeviceKey(cfg.DeviceDID, cfg.Device)
	if err != nil {
		return nil, err
	}
	// From here a key EXISTS (a persistent Enclave key is already in the keychain).
	// If any subsequent step fails, tear it down so a rejected enrollment still
	// leaves no partial state. Cleared once the enrollment is committed.
	committed := false
	defer func() {
		if !committed {
			cleanupDeviceKey(deviceSigner, keyInfo)
		}
	}()

	// 4. Trust-on-first-use / backend authorization.
	if err := backend.Confirm(ConfirmRequest{
		Identity:    cfg.Identity,
		DID:         cfg.DeviceDID,
		Fingerprint: keyInfo.Fingerprint,
		Algorithm:   keyInfo.Algorithm,
	}); err != nil {
		return nil, err
	}

	// 5. Publish the device DID document (public key only).
	docPath, err := did.WriteDocument(cfg.Root, did.NewDocument(cfg.DeviceDID, deviceSigner.Public()))
	if err != nil {
		return nil, fmt.Errorf("enroll: write device DID document: %w", err)
	}

	// 6. Mint the org->employee credential.
	cred, link, err := cfg.mintCredential(deviceSigner.Public())
	if err != nil {
		return nil, err
	}
	credID, err := export.CredentialID(cred)
	if err != nil {
		return nil, fmt.Errorf("enroll: credential id: %w", err)
	}
	ch := &chain.Chain{Links: []chain.Link{*link}}
	if err := writeChain(cfg.CredentialOut, ch); err != nil {
		return nil, err
	}

	// 7. Record the mapping LAST (append-only; new DID never collides).
	tag := ""
	if len(keyInfo.Tag) > 0 {
		tag = string(keyInfo.Tag)
	}
	if err := m.AddCredential(cfg.Identity, Credential{
		DID:            cfg.DeviceDID,
		CredentialID:   credID,
		StatusURL:      cfg.StatusURL,
		StatusIndex:    cfg.StatusIndex,
		KeyFingerprint: keyInfo.Fingerprint,
		KeyBackend:     keyInfo.Backend,
		KeyTag:         tag,
		Algorithm:      keyInfo.Algorithm,
		EnrolledAt:     now().UTC(),
	}); err != nil {
		return nil, err
	}
	if err := m.Save(cfg.MappingPath); err != nil {
		return nil, err
	}
	committed = true // enrollment succeeded: keep the key, skip cleanup

	return &Result{
		Identity:      cfg.Identity,
		DeviceDID:     cfg.DeviceDID,
		CredentialID:  credID,
		Key:           keyInfo,
		DIDDocPath:    docPath,
		CredentialOut: cfg.CredentialOut,
		MappingPath:   cfg.MappingPath,
		BackendName:   backend.Name(),
		Chain:         ch,
	}, nil
}

// mintCredential builds and signs the org->employee credential binding holderPub
// as the device's holder key. Mirrors the per-hop logic in cmd/issuer publish so
// the output is verifier-identical to any other chain link.
func (cfg *Config) mintCredential(holderPub any) (*credential.Credential, *chain.Link, error) {
	m := macaroon.Mint(cfg.MacaroonRootKey, cfg.Identifier, cfg.Location)
	var err error
	for _, cav := range cfg.Caveats {
		m, err = macaroon.Attenuate(m, cav)
		if err != nil {
			return nil, nil, fmt.Errorf("enroll: attenuate caveat %q: %w", cav, err)
		}
	}
	cred, err := credential.New(credential.Options{
		Subject:   cfg.DeviceDID,
		Issuer:    cfg.OrgDID,
		Macaroon:  m,
		StatusRef: status.Reference{ListURL: cfg.StatusURL, Index: cfg.StatusIndex},
		HolderKey: holderPub,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: compose credential: %w", err)
	}
	proof, err := chain.SignIssuance(cfg.OrgSigner, cred)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: sign issuance: %w", err)
	}
	return cred, &chain.Link{Credential: *cred, IssuerProof: proof}, nil
}
