// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/config"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/keystore"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Keystore is internal/keystore's mock keystore, aliased rather than redeclared.
//
// This file used to carry its own copy of the same map type and its own copy of
// Signer, differing only in the wording of two error messages. Two copies of one
// type is two places a fix has to land, and the second one is the copy nobody
// remembers: the Principals helper that skips a keystore's non-DID "_comment"
// entry would have had to be written twice, which is how the daemon came to be
// unable to load a keystore the proxy reads fine.
//
// THIS IS MOCK KEY MANAGEMENT. Real deployments put private keys behind the
// signer.Signer seam (TPM / Secure Enclave / HSM) and never write them to disk.
// Seeds live here so the POC and `make demo` are deterministic and reproducible.
type Keystore = keystore.Keystore

// CaveatSpec is one restriction added at a delegation hop.
type CaveatSpec struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// HopSpec is one parent -> child delegation.
type HopSpec struct {
	Issuer  types.DID    `json:"issuer"`
	Subject types.DID    `json:"subject"`
	Caveats []CaveatSpec `json:"caveats,omitempty"`
	// StatusIndex, if set, gives this credential a position in the published
	// status list so it can later be revoked. Omit it for hops that publish no
	// revocation list (a bit index of 0 is a valid position, so presence is
	// signalled by the pointer, never by a zero value).
	StatusIndex *int `json:"statusIndex,omitempty"`
}

// StatusSpec describes the bitstring status list this issuer publishes.
type StatusSpec struct {
	URL    string    `json:"url"`    // where the signed list will be published
	Issuer types.DID `json:"issuer"` // who signs it
	Bits   int       `json:"bits"`   // raised to status.MinBits if smaller
}

// Spec is the issuer's declarative input: which chain to mint, and what to
// publish. The status URL's host is entirely the operator's choice, it can be an
// internal-only or air-gapped hostname that resolves nowhere.
type Spec struct {
	RootKeyHex      string      `json:"rootKeyHex"` // macaroon HMAC root key (issuer secret)
	Identifier      string      `json:"identifier"`
	Location        string      `json:"location"`
	Status          StatusSpec  `json:"status"`
	Hops            []HopSpec   `json:"hops"`
	ExtraPrincipals []types.DID `json:"extraPrincipals,omitempty"` // e.g. the enforcement point

	// Comment is never read. It exists so a spec file may carry a "_comment"
	// key, which is how this repository writes a comment into JSON, which has no
	// syntax for one.
	//
	// Declared rather than tolerated. Under strict decoding an undeclared
	// "_comment" is an error, and the three spec files in this repository all
	// carry one saying that the committed rootKeyHex is a NON-SECRET demo value
	// and pointing at SECURITY.md's "Committed demo material". Deleting that text
	// to satisfy a parser would remove the only explanation for why something
	// shaped like a key is in the tree, which is the first question a reviewer or
	// a secret-scanner triage asks.
	Comment string `json:"_comment,omitempty"`
}

// loadJSON reads a JSON file into T, rejecting unknown fields.
//
// Strictness is here for the OPTIONAL fields. A misspelled required field is
// already caught downstream, because Spec.validate refuses an empty
// RootKeyHex, Identifier, Status or Hops whatever the reason for it being empty.
// An optional one has no such backstop: "extraPrincipals" misspelled parses
// cleanly, yields an empty slice, and publishes a root with the enforcement point
// silently absent. That is a check whose absence is invisible precisely because
// the field it governs is allowed to be missing.
//
// This does NOTHING for loadJSON[Keystore]. Keystore is a map type and a map has
// no unknown fields; see config.DecodeStrict. The keystore's own "_comment" entry
// stays a legitimate key, handled where it has to be, in keystore.Principals.
func loadJSON[T any](path string) (T, error) {
	var v T
	data, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("read %q: %w", path, err)
	}
	if err := config.DecodeStrict(data, &v); err != nil {
		return v, fmt.Errorf("parse %q: %w", path, err)
	}
	return v, nil
}

func (s *Spec) validate() error {
	if s.RootKeyHex == "" {
		return fmt.Errorf("spec: rootKeyHex is required")
	}
	if s.Identifier == "" {
		return fmt.Errorf("spec: identifier is required")
	}
	if len(s.Hops) == 0 {
		return fmt.Errorf("spec: at least one hop is required")
	}
	// Depth cap enforced at issuance: refuse to mint a chain deeper than the
	// verifier will accept, so a spec that would only ever be rejected downstream
	// fails loudly here instead. The verifier re-enforces the same cap (see
	// chain.MaxDepth), so lowering it does not let an over-deep chain slip through.
	if len(s.Hops) > chain.MaxDepth {
		return fmt.Errorf("spec: %d hops exceeds max delegation depth %d", len(s.Hops), chain.MaxDepth)
	}
	if s.Status.URL == "" || s.Status.Issuer == "" {
		return fmt.Errorf("spec: status.url and status.issuer are required")
	}
	for i, h := range s.Hops {
		if h.Issuer == "" || h.Subject == "" {
			return fmt.Errorf("spec: hop %d needs both issuer and subject", i)
		}
		if h.Issuer == h.Subject {
			return fmt.Errorf("spec: hop %d delegates to itself", i)
		}
		// Continuity: each hop's issuer must be the previous hop's subject, or the
		// resulting chain would not resolve.
		if i > 0 && h.Issuer != s.Hops[i-1].Subject {
			return fmt.Errorf("spec: hop %d issuer %q is not hop %d's subject %q", i, h.Issuer, i-1, s.Hops[i-1].Subject)
		}
	}
	return nil
}

// principals lists every DID whose DID document must be published: both ends of
// every hop, the status-list issuer, plus any extras (typically the enforcement
// point, whose key a verifier needs to check audit entry signatures).
func (s *Spec) principals() []types.DID {
	seen := map[types.DID]bool{}
	var out []types.DID
	add := func(d types.DID) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, h := range s.Hops {
		add(h.Issuer)
		add(h.Subject)
	}
	add(s.Status.Issuer)
	for _, d := range s.ExtraPrincipals {
		add(d)
	}
	return out
}

// Result summarizes what publish() produced.
type Result struct {
	Root          string
	DIDDocs       []string
	StatusPath    string
	ChainPath     string
	Chain         *chain.Chain
	CredentialIDs []string
}

// publish mints the delegation chain and writes the static publication root.
//
// Self-hostable-first: `root` ends up containing nothing but plain JSON files at
// the exact paths did:web resolution and the status URL imply. Serve it from
// Cloudflare Pages, an internal nginx, a USB stick, or hand the directory
// straight to an offline verifier, the artifacts are identical and no Kessa
// service is involved at any point.
//
// Secrets never enter `root`. The minted credentials (and the macaroon root key
// in the spec) are not public artifacts, so the chain is written to chainOut,
// deliberately outside the publication root.
func publish(spec *Spec, ks Keystore, root, chainOut string) (*Result, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	res := &Result{Root: root}

	// 1. Publish a DID document for every principal.
	for _, d := range spec.principals() {
		s, err := ks.Signer(d)
		if err != nil {
			return nil, err
		}
		path, err := did.WriteDocument(root, did.NewDocument(d, s.Public()))
		if err != nil {
			return nil, err
		}
		res.DIDDocs = append(res.DIDDocs, path)
	}

	// 2. Mint the attenuated delegation chain.
	rootKey, err := hex.DecodeString(spec.RootKeyHex)
	if err != nil {
		return nil, fmt.Errorf("spec: rootKeyHex is not hex: %w", err)
	}
	m := macaroon.Mint(rootKey, spec.Identifier, spec.Location)

	links := make([]chain.Link, 0, len(spec.Hops))
	for i, hop := range spec.Hops {
		// Each hop appends its caveats to the running macaroon, so every child
		// strictly extends its parent. Attenuate rejects any caveat that would
		// broaden authority, the issuer *cannot* mint a widening delegation.
		for _, cv := range hop.Caveats {
			m, err = macaroon.Attenuate(m, macaroon.Caveat{Field: cv.Field, Op: macaroon.Op(cv.Op), Value: cv.Value})
			if err != nil {
				return nil, fmt.Errorf("hop %d (%s -> %s): %w", i, hop.Issuer, hop.Subject, err)
			}
		}

		holder, err := ks.Signer(hop.Subject)
		if err != nil {
			return nil, err
		}
		var ref status.Reference
		if hop.StatusIndex != nil {
			ref = status.Reference{ListURL: spec.Status.URL, Index: *hop.StatusIndex}
			// One spec publishes ONE list for the whole chain, so a hop issued by an
			// agent can legitimately point at its org's list. Where that happens, the
			// credential must SAY so, because verification will only accept a list
			// signed by the authority the credential names (R6-01), and the default
			// when it names none is the hop's own issuer.
			//
			// Written only when it actually differs. Stamping it unconditionally
			// would put a redundant field inside signed, content-addressed material
			// on every credential, and the omitted form already means exactly this
			// value. Omission narrows rather than widens, so leaving it off where it
			// agrees costs nothing.
			if spec.Status.Issuer != hop.Issuer {
				ref.Issuer = spec.Status.Issuer
			}
		}
		cred, err := credential.New(credential.Options{
			Subject:   hop.Subject,
			Issuer:    hop.Issuer,
			Macaroon:  m,
			StatusRef: ref,
			HolderKey: holder.Public(),
		})
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i, err)
		}
		issuerSigner, err := ks.Signer(hop.Issuer)
		if err != nil {
			return nil, err
		}
		proof, err := chain.SignIssuance(issuerSigner, cred)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i, err)
		}
		id, err := export.CredentialID(cred)
		if err != nil {
			return nil, err
		}
		res.CredentialIDs = append(res.CredentialIDs, id)
		links = append(links, chain.Link{Credential: *cred, IssuerProof: proof})
	}
	res.Chain = &chain.Chain{Links: links}

	// 3. Publish the signed, all-clear status list.
	list := status.New(spec.Status.Bits)
	statusSigner, err := ks.Signer(spec.Status.Issuer)
	if err != nil {
		return nil, err
	}
	if err := list.Sign(statusSigner); err != nil {
		return nil, err
	}
	if res.StatusPath, err = status.Publish(list, root, spec.Status.URL); err != nil {
		return nil, err
	}

	// 4. Write the credentials OUTSIDE the public root.
	data, err := res.Chain.Marshal()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(chainOut), 0o755); err != nil {
		return nil, fmt.Errorf("create %q: %w", filepath.Dir(chainOut), err)
	}
	if err := os.WriteFile(chainOut, append(data, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("write %q: %w", chainOut, err)
	}
	res.ChainPath = chainOut
	return res, nil
}

// revoke flips a credential's bit in the published status list and re-signs it.
// Publication is just rewriting the static file; propagation to verifiers is
// whatever your static host's cache policy is. Nothing calls home.
func revoke(spec *Spec, ks Keystore, root string, index int, clear bool) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	path, err := status.PublishPath(root, spec.Status.URL)
	if err != nil {
		return "", err
	}
	list, err := status.Load(path)
	if err != nil {
		return "", fmt.Errorf("load published status list (run `publish` first): %w", err)
	}
	if err := list.Set(index, !clear); err != nil {
		return "", err
	}
	statusSigner, err := ks.Signer(spec.Status.Issuer)
	if err != nil {
		return "", err
	}
	if err := list.Sign(statusSigner); err != nil { // re-sign: the bits changed
		return "", err
	}
	return status.Publish(list, root, spec.Status.URL)
}
