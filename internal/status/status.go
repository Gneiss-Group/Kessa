// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package status implements a W3C-style Bitstring Status List: a large,
// issuer-signed bitfield in which each credential occupies one bit, flipped
// when the credential is revoked (or suspended). A verifier consults the bit at
// a credential's index to decide whether it is still live.
//
// Two properties drive the design:
//
//   - Herd privacy. The list is at least 131072 bits (16 KiB). Because so many
//     credentials share one published list, fetching it does not reveal which
//     credential the checker cares about, and revoking one credential does not
//     single it out. New() enforces the floor; Verify() rejects an undersized
//     list.
//   - Tamper evidence in transit. The published list is Ed25519-signed by the
//     issuer over its exact bits, so a proxy or verifier that fetches it can
//     detect any modification (including a flipped revocation bit) without
//     trusting the transport.
//
// Self-hostable first (spec §10): the portable Marshal/Parse format plus the
// Save/Load file helpers are the DEFAULT publication mechanism, with no
// dependency on any hosted service. A hosted publisher would be an optional
// alternative, not a requirement.
//
// Like internal/macaroon, verification here needs only a public key, resolved
// by the caller from the issuer's DID document, so Verify takes an
// ed25519.PublicKey and this package imposes no did dependency on the verifier.
package status

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// MinBits is the herd-privacy floor: a status list must hold at least this many
// bits (131072 bits = 16 KiB), per the W3C Bitstring Status List guidance.
const MinBits = 131072

// signingDomain namespaces the signature so a status-list signature can never be
// mistaken for a signature over some other Kessa artifact.
const signingDomain = "kessa/status-list/v1"

// Purpose distinguishes why a bit is set. Revocation is permanent; suspension is
// reversible. The POC uses revocation; suspension is here for completeness.
type Purpose string

const (
	PurposeRevocation Purpose = "revocation"
	PurposeSuspension Purpose = "suspension"
)

// Reference is a credential's pointer into a published status list.
type Reference struct {
	ListURL string `json:"listURL"` // where the signed bitstring is published
	Index   int    `json:"index"`   // this credential's bit position
}

// StatusList is an issuer-signed bitstring.
type StatusList struct {
	Issuer    types.DID
	Purpose   Purpose
	Bits      []byte // MSB-first within each byte; index 0 is bit 0x80 of Bits[0]
	Signature []byte // Ed25519 over signingInput(); set by Sign
}

// New allocates a zeroed status list holding at least minBits bits (rounded up
// to a byte and never below MinBits). All credentials start un-revoked.
func New(minBits int) *StatusList {
	if minBits < MinBits {
		minBits = MinBits
	}
	nbytes := (minBits + 7) / 8
	return &StatusList{
		Purpose: PurposeRevocation,
		Bits:    make([]byte, nbytes),
	}
}

// Len returns the number of addressable bits.
func (l *StatusList) Len() int { return len(l.Bits) * 8 }

// Set marks the credential at index revoked (true) or clears it (false).
func (l *StatusList) Set(index int, revoked bool) error {
	if err := l.checkIndex(index); err != nil {
		return err
	}
	mask := byte(1) << uint(7-index%8)
	if revoked {
		l.Bits[index/8] |= mask
	} else {
		l.Bits[index/8] &^= mask
	}
	return nil
}

// Lookup reports whether the credential at index is revoked.
func (l *StatusList) Lookup(index int) (bool, error) {
	if err := l.checkIndex(index); err != nil {
		return false, err
	}
	mask := byte(1) << uint(7-index%8)
	return l.Bits[index/8]&mask != 0, nil
}

func (l *StatusList) checkIndex(index int) error {
	if index < 0 || index >= l.Len() {
		return fmt.Errorf("status: index %d out of range [0,%d)", index, l.Len())
	}
	return nil
}

// Sign stamps the list with the issuer's DID and an Ed25519 signature over its
// current contents. Any later change to Issuer, Purpose, or Bits invalidates it.
func (l *StatusList) Sign(s signer.Signer) error {
	l.Issuer = s.DID()
	sig, err := s.Sign(l.signingInput())
	if err != nil {
		return fmt.Errorf("status: sign: %w", err)
	}
	l.Signature = sig
	return nil
}

// Verify confirms the list meets the herd-privacy floor and that its signature
// is valid under pub (which the caller resolves from l.Issuer's DID document).
func (l *StatusList) Verify(pub crypto.PublicKey) error {
	if l.Len() < MinBits {
		return fmt.Errorf("status: list has %d bits, below herd-privacy minimum %d", l.Len(), MinBits)
	}
	if len(l.Signature) == 0 {
		return errors.New("status: list is unsigned")
	}
	if !signer.Verify(pub, l.signingInput(), l.Signature) {
		return errors.New("status: signature verification failed (tampered or wrong issuer key)")
	}
	return nil
}

// signingInput is the exact, domain-separated byte string that is signed and
// verified. Bits go last because they are variable-length binary; the fixed,
// newline-free domain/issuer/purpose prefix keeps the framing unambiguous.
func (l *StatusList) signingInput() []byte {
	buf := make([]byte, 0, len(signingDomain)+len(l.Issuer)+len(l.Purpose)+len(l.Bits)+3)
	buf = append(buf, signingDomain...)
	buf = append(buf, 0x00)
	buf = append(buf, l.Issuer...)
	buf = append(buf, 0x00)
	buf = append(buf, l.Purpose...)
	buf = append(buf, 0x00)
	buf = append(buf, l.Bits...)
	return buf
}

// ---- portable publication format -----------------------------------------

// published is the frozen on-the-wire / on-disk JSON shape of a signed status
// list. Bits are raw (uncompressed) base64url, deterministic and trivially
// auditable; gzip is a possible later optimization, not needed for the POC.
type published struct {
	Issuer    types.DID `json:"issuer"`
	Purpose   Purpose   `json:"purpose"`
	Encoding  string    `json:"encoding"` // always "base64url" for now
	Bitstring string    `json:"bitstring"`
	Signature string    `json:"signature"`
}

// Marshal serializes the signed list into its portable JSON form.
func (l *StatusList) Marshal() ([]byte, error) {
	if len(l.Signature) == 0 {
		return nil, errors.New("status: refusing to marshal an unsigned list")
	}
	return json.MarshalIndent(published{
		Issuer:    l.Issuer,
		Purpose:   l.Purpose,
		Encoding:  "base64url",
		Bitstring: base64.RawURLEncoding.EncodeToString(l.Bits),
		Signature: base64.RawURLEncoding.EncodeToString(l.Signature),
	}, "", "  ")
}

// Parse reads a status list back from its portable JSON form. It does not verify
// the signature, call Verify with the issuer's resolved key for that.
func Parse(data []byte) (*StatusList, error) {
	var p published
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("status: parse: %w", err)
	}
	if p.Encoding != "base64url" {
		return nil, fmt.Errorf("status: unsupported encoding %q", p.Encoding)
	}
	bits, err := base64.RawURLEncoding.DecodeString(p.Bitstring)
	if err != nil {
		return nil, fmt.Errorf("status: decode bitstring: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil {
		return nil, fmt.Errorf("status: decode signature: %w", err)
	}
	return &StatusList{
		Issuer:    p.Issuer,
		Purpose:   p.Purpose,
		Bits:      bits,
		Signature: sig,
	}, nil
}

// Save publishes the signed list to a local file, the default, self-hostable
// publication path.
func Save(l *StatusList, path string) error {
	data, err := l.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// PublishPath maps a published status-list URL to its file location beneath
// root, mirroring the URL's host and path exactly, the same discipline as
// did.DocumentPath. Serving root with any static web server (or handing the
// directory to an air-gapped verifier) satisfies the URL without a Kessa service.
func PublishPath(root, listURL string) (string, error) {
	u, err := url.Parse(listURL)
	if err != nil {
		return "", fmt.Errorf("status: parse list URL %q: %w", listURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("status: list URL %q must be http(s)", listURL)
	}
	if u.Host == "" {
		return "", fmt.Errorf("status: list URL %q has no host", listURL)
	}
	// The host becomes a path segment beneath root, so reject a traversal there
	// too, not just in the path (F5). Mirrors did.parseDIDWeb's host check.
	if u.Host == "." || u.Host == ".." || strings.ContainsAny(u.Host, `/\`) {
		return "", fmt.Errorf("status: list URL %q has an unsafe host %q", listURL, u.Host)
	}
	clean := strings.Trim(u.Path, "/")
	if clean == "" {
		return "", fmt.Errorf("status: list URL %q must include a path", listURL)
	}
	parts := []string{root, u.Host}
	for _, seg := range strings.Split(clean, "/") {
		// We write to this path; reject traversal at the boundary.
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("status: list URL %q has an unsafe path segment %q", listURL, seg)
		}
		parts = append(parts, seg)
	}
	return filepath.Join(parts...), nil
}

// Publish writes the signed list into the static publication root at the
// location implied by listURL, creating directories as needed.
func Publish(l *StatusList, root, listURL string) (string, error) {
	path, err := PublishPath(root, listURL)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("status: create %q: %w", filepath.Dir(path), err)
	}
	if err := Save(l, path); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads a published list from a local file.
func Load(path string) (*StatusList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("status: load %q: %w", path, err)
	}
	return Parse(data)
}
