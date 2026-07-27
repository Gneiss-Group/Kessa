// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package did implements the slice of did:web that Kessa needs: turning a
// did:web identifier into a fetch location, parsing the resulting DID document,
// and pulling the Ed25519 public key out of it.
//
// Design constraints that shape this package:
//
//   - Self-hostable first. Resolution is an interface with a LOCAL-FILE
//     implementation as the default; HTTPS is an optional alternative. Nothing
//     here requires a hosted Kessa service, the whole point is that a verifier
//     trusts nothing of ours beyond public DID documents.
//   - did:web only for the POC. No blockchain-anchored methods.
//   - Keys are published as publicKeyJwk, which keeps encoding to stdlib
//     base64url and avoids a base58/multibase dependency. Two key types are
//     supported: OKP/Ed25519 (the default for org, proxy, and status-issuer
//     keys) and EC/P-256 (the employee/device key, which a Secure Enclave or TPM
//     generates in hardware; those devices cannot produce Ed25519). Resolution
//     is algorithm-agile: a resolved key is a crypto.PublicKey and callers verify
//     through signer.Verify, which dispatches on its concrete type.
package did

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Document is a minimal W3C DID document, only the fields Kessa reads.
type Document struct {
	Context            []string             `json:"@context"`
	ID                 types.DID            `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
}

// VerificationMethod carries one public key. Kessa only issues/consumes
// JsonWebKey2020 methods with an OKP/Ed25519 JWK.
type VerificationMethod struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Controller   types.DID `json:"controller"`
	PublicKeyJwk *JWK      `json:"publicKeyJwk,omitempty"`
}

// JWK is a JSON Web Key. Two key types are supported:
//
//   - OKP / Ed25519: x is the base64url-encoded 32-byte public key. Y is empty.
//   - EC / P-256:    x and y are the base64url-encoded 32-byte affine
//     coordinates of the curve point.
//
// This is the single canonical JSON encoding for a public key everywhere in
// Kessa, both in DID documents and as a credential's bound holder key, so one
// parser covers both and a key is always self-describing about its algorithm.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"` // EC only; the point's y-coordinate
}

// p256CoordSize is the byte length of a P-256 affine coordinate (256 bits).
const p256CoordSize = 32

// PublicKeyToJWK encodes a supported public key as a JWK. It panics on an
// unsupported key type OR an unsupported EC curve, which is a programming error
// (the caller controls what it generates) and is never attacker-reachable: the
// verifier only ever PARSES JWKs (JWK.PublicKey), it never encodes. Panicking
// rather than returning an error is deliberate here — the alternative that this
// function must never do is what it used to: silently stamp a non-P-256 key as
// crv:"P-256" and emit a JWK that lies about what it carries (R3-02). A loud
// refusal to encode an unrepresentable key is strictly safer than a false label.
func PublicKeyToJWK(pub crypto.PublicKey) *JWK {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return &JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k),
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			// Do not mislabel: the only EC curve this JWK form represents is P-256.
			panic("did: cannot encode ECDSA public key on a non-P-256 curve")
		}
		return &JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(leftPad(k.X.Bytes(), p256CoordSize)),
			Y:   base64.RawURLEncoding.EncodeToString(leftPad(k.Y.Bytes(), p256CoordSize)),
		}
	default:
		panic(fmt.Sprintf("did: cannot encode unsupported public key type %T", pub))
	}
}

// PublicKey decodes the JWK back into a crypto.PublicKey (ed25519.PublicKey or
// *ecdsa.PublicKey). Callers verify signatures through signer.Verify, which
// dispatches on this concrete type.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	if j == nil {
		return nil, fmt.Errorf("did: nil JWK")
	}
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		b, err := decodeBase64URL(j.X)
		if err != nil {
			return nil, fmt.Errorf("did: decode JWK x: %w", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("did: JWK x is %d bytes, want %d", len(b), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(b), nil
	case j.Kty == "EC" && j.Crv == "P-256":
		xb, err := decodeBase64URL(j.X)
		if err != nil {
			return nil, fmt.Errorf("did: decode JWK x: %w", err)
		}
		yb, err := decodeBase64URL(j.Y)
		if err != nil {
			return nil, fmt.Errorf("did: decode JWK y: %w", err)
		}
		if len(xb) != p256CoordSize || len(yb) != p256CoordSize {
			return nil, fmt.Errorf("did: P-256 JWK coordinates are %d/%d bytes, want %d each", len(xb), len(yb), p256CoordSize)
		}
		// Validate the point is a legitimate P-256 public key (on the curve, not the
		// identity) via crypto/ecdh, the current replacement for the deprecated
		// elliptic.IsOnCurve. The SEC1 uncompressed encoding is 0x04 || X || Y.
		sec1 := make([]byte, 1+2*p256CoordSize)
		sec1[0] = 0x04
		copy(sec1[1:1+p256CoordSize], xb)
		copy(sec1[1+p256CoordSize:], yb)
		if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
			return nil, fmt.Errorf("did: invalid P-256 public key: %w", err)
		}
		// Return an *ecdsa.PublicKey because verification uses ecdsa.VerifyASN1;
		// ecdh keys cannot verify signatures. elliptic.P256() here is just the curve
		// identity, not a deprecated operation.
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}, nil
	default:
		return nil, fmt.Errorf("did: unsupported JWK kty=%q crv=%q (want OKP/Ed25519 or EC/P-256)", j.Kty, j.Crv)
	}
}

// leftPad returns b left-padded with zero bytes to exactly size bytes. A P-256
// coordinate can be shorter than 32 bytes when its high bytes are zero;
// big.Int.Bytes() drops them, but the JWK encoding is fixed-width.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// decodeBase64URL accepts both padded and unpadded base64url, since we cannot
// control how every producer of a DID document encodes the key.
func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// NewDocument builds a DID document for did that publishes a single
// verification method (#key-1) usable for both authentication and assertion. The
// key may be Ed25519 or P-256; PublicKeyToJWK records which.
func NewDocument(did types.DID, pub crypto.PublicKey) *Document {
	vmID := string(did) + "#key-1"
	return &Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{{
			ID:           vmID,
			Type:         "JsonWebKey2020",
			Controller:   did,
			PublicKeyJwk: PublicKeyToJWK(pub),
		}},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}
}

// FirstKey returns the public key of the first verification method. Most Kessa
// DID documents publish exactly one key, so this is the common accessor.
func (d *Document) FirstKey() (crypto.PublicKey, error) {
	if d == nil || len(d.VerificationMethod) == 0 {
		return nil, fmt.Errorf("did: document %q has no verification methods", d.id())
	}
	return d.VerificationMethod[0].PublicKeyJwk.PublicKey()
}

// Key returns the public key for a specific verification method id. The id may
// be given fully (did#frag) or as just the fragment (#frag or frag).
func (d *Document) Key(vmID string) (crypto.PublicKey, error) {
	if d == nil {
		return nil, fmt.Errorf("did: nil document")
	}
	want := vmID
	if !strings.Contains(vmID, "#") {
		want = string(d.ID) + "#" + strings.TrimPrefix(vmID, "#")
	} else if strings.HasPrefix(vmID, "#") {
		want = string(d.ID) + vmID
	}
	for i := range d.VerificationMethod {
		if d.VerificationMethod[i].ID == want {
			return d.VerificationMethod[i].PublicKeyJwk.PublicKey()
		}
	}
	return nil, fmt.Errorf("did: verification method %q not found in %q", want, d.ID)
}

func (d *Document) id() types.DID {
	if d == nil {
		return ""
	}
	return d.ID
}

// Resolver turns a DID into its DID document.
type Resolver interface {
	Resolve(did types.DID) (*Document, error)
}

// ResolveKey is a convenience: resolve did and return its first public key
// (ed25519.PublicKey or *ecdsa.PublicKey; the caller verifies through
// signer.Verify, which dispatches on the concrete type).
func ResolveKey(r Resolver, did types.DID) (crypto.PublicKey, error) {
	doc, err := r.Resolve(did)
	if err != nil {
		return nil, err
	}
	return doc.FirstKey()
}

// FileResolver resolves did:web documents from a local directory tree rooted at
// Root, mirroring the HTTPS path layout. This is the default, self-hostable /
// air-gapped resolver.
//
//	did:web:example.com            -> <Root>/example.com/.well-known/did.json
//	did:web:example.com:orgs:acme  -> <Root>/example.com/orgs/acme/did.json
type FileResolver struct {
	Root string
}

var _ Resolver = FileResolver{}

func (r FileResolver) Resolve(did types.DID) (*Document, error) {
	path, err := DocumentPath(r.Root, did)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("did: read %q: %w", path, err)
	}
	return parseDocument(did, data)
}

// DocumentPath maps a did:web identifier to its file location beneath root,
// mirroring the HTTPS layout exactly. It is the single source of truth for that
// mapping: FileResolver reads through it and WriteDocument writes through it, so
// a published directory is, by construction, resolvable both as a local
// directory and as a static website.
func DocumentPath(root string, did types.DID) (string, error) {
	host, segs, err := parseDIDWeb(did)
	if err != nil {
		return "", err
	}
	parts := []string{root, host}
	if len(segs) == 0 {
		parts = append(parts, ".well-known", "did.json")
	} else {
		parts = append(parts, segs...)
		parts = append(parts, "did.json")
	}
	return filepath.Join(parts...), nil
}

// WriteDocument publishes doc beneath root at its did:web path, creating
// directories as needed, and returns the file written. The result is a plain
// static file: serve root with any web server (or none at all) and did:web
// resolution works. Nothing about it depends on a Kessa service.
func WriteDocument(root string, doc *Document) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("did: nil document")
	}
	path, err := DocumentPath(root, doc.ID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("did: create %q: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("did: marshal document %q: %w", doc.ID, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("did: write %q: %w", path, err)
	}
	return path, nil
}

// HTTPResolver resolves did:web documents over HTTPS. Fetching public DID
// documents is the ONLY network access allowed anywhere in the verification
// path, and it is fetching public documents, never querying our infrastructure.
type HTTPResolver struct {
	Client *http.Client
	// Scheme defaults to "https". Overridable to "http" only for tests against
	// httptest servers; production did:web is HTTPS by definition.
	Scheme string
}

var _ Resolver = HTTPResolver{}

func (r HTTPResolver) Resolve(did types.DID) (*Document, error) {
	u, err := didWebToURL(did, r.Scheme)
	if err != nil {
		return nil, err
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("did: fetch %q: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did: fetch %q: status %d", u, resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("did: decode %q: %w", u, err)
	}
	if doc.ID != did {
		return nil, fmt.Errorf("did: document id %q does not match requested %q", doc.ID, did)
	}
	return &doc, nil
}

// didWebToURL converts a did:web identifier to its HTTPS document URL per the
// did:web method spec.
func didWebToURL(did types.DID, scheme string) (string, error) {
	host, segs, err := parseDIDWeb(did)
	if err != nil {
		return "", err
	}
	if scheme == "" {
		scheme = "https"
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if len(segs) == 0 {
		b.WriteString("/.well-known/did.json")
	} else {
		for _, s := range segs {
			b.WriteByte('/')
			b.WriteString(s)
		}
		b.WriteString("/did.json")
	}
	return b.String(), nil
}

// parseDIDWeb splits a did:web identifier into its host (with any percent-encoded
// port decoded) and its path segments (percent-decoded).
func parseDIDWeb(did types.DID) (host string, segs []string, err error) {
	s := string(did)
	const prefix = "did:web:"
	if !strings.HasPrefix(s, prefix) {
		return "", nil, fmt.Errorf("did: %q is not a did:web identifier", did)
	}
	rest := strings.TrimPrefix(s, prefix)
	if rest == "" {
		return "", nil, fmt.Errorf("did: %q has empty did:web-specific id", did)
	}
	fields := strings.Split(rest, ":")
	// The first field is the host (which may percent-encode a :port as %3A);
	// remaining fields are path segments.
	host, err = url.PathUnescape(fields[0])
	if err != nil {
		return "", nil, fmt.Errorf("did: decode host in %q: %w", did, err)
	}
	if host == "" {
		return "", nil, fmt.Errorf("did: %q has empty host", did)
	}
	if host == "." || host == ".." || strings.ContainsAny(host, `/\`) {
		return "", nil, fmt.Errorf("did: %q has an unsafe host", did)
	}
	for _, f := range fields[1:] {
		if f == "" {
			return "", nil, fmt.Errorf("did: %q has an empty path segment", did)
		}
		seg, err := url.PathUnescape(f)
		if err != nil {
			return "", nil, fmt.Errorf("did: decode segment %q in %q: %w", f, did, err)
		}
		// DocumentPath joins these segments into a filesystem path and
		// WriteDocument writes there, so a "." or ".." segment would be a path
		// traversal primitive. Reject them at the parse boundary.
		if seg == "." || seg == ".." || strings.ContainsAny(seg, `/\`) {
			return "", nil, fmt.Errorf("did: %q has an unsafe path segment %q", did, seg)
		}
		segs = append(segs, seg)
	}
	return host, segs, nil
}

// parseDocument unmarshals a DID document and confirms its id matches the DID we
// asked for, a resolver must never hand back a document for a different DID.
func parseDocument(did types.DID, data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("did: parse document for %q: %w", did, err)
	}
	if doc.ID != did {
		return nil, fmt.Errorf("did: document id %q does not match requested %q", doc.ID, did)
	}
	return &doc, nil
}
