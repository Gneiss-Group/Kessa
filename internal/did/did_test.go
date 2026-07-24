// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// testdata fixtures are generated (see scripts/genfixtures or the Makefile
// `fixtures` target) from these fixed seeds. Keeping the seeds here lets the
// test derive the expected key independently of the fixture file.
func seed32(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

func keyForSeed(t *testing.T, b byte) ed25519.PublicKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(seed32(b)).Public().(ed25519.PublicKey)
}

const didsRoot = "../../testdata/dids"

func TestFileResolver_ResolvesFixtureToKey(t *testing.T) {
	cases := []struct {
		name string
		did  types.DID
		seed byte
	}{
		{"path segments", "did:web:localhost:orgs:acme", 0x11},
		{"other org", "did:web:localhost:orgs:bravo", 0x22},
		{"well-known (bare host)", "did:web:localhost", 0x44},
	}
	r := FileResolver{Root: didsRoot}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := r.Resolve(tc.did)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.did, err)
			}
			if doc.ID != tc.did {
				t.Fatalf("resolved id = %q, want %q", doc.ID, tc.did)
			}
			got, err := doc.FirstKey()
			if err != nil {
				t.Fatalf("FirstKey: %v", err)
			}
			if want := keyForSeed(t, tc.seed); !got.Equal(want) {
				t.Fatalf("resolved key does not match the seed-derived key")
			}
			// Key() by fragment must find the same key.
			byFrag, err := doc.Key("#key-1")
			if err != nil {
				t.Fatalf("Key(#key-1): %v", err)
			}
			if !byFrag.Equal(got) {
				t.Fatal("Key(#key-1) disagrees with FirstKey()")
			}
		})
	}
}

func TestFileResolver_Errors(t *testing.T) {
	r := FileResolver{Root: didsRoot}
	if _, err := r.Resolve("did:web:localhost:orgs:nonexistent"); err == nil {
		t.Fatal("expected error resolving a missing DID, got nil")
	}
	if _, err := r.Resolve("did:key:z6Mk"); err == nil {
		t.Fatal("expected error for non-did:web identifier, got nil")
	}
}

func TestHTTPResolver_ResolvesOverNetwork(t *testing.T) {
	// The did:web host carries the httptest host:port, so the document's id must
	// match that host, serve a document minted for whatever address httptest
	// hands us, at the path the resolver will request.
	pub := keyForSeed(t, 0x11)
	var did types.DID // set once the server address is known; read at request time

	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/acme/did.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(NewDocument(did, pub))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := srv.Listener.Addr().String() // 127.0.0.1:PORT
	did = types.DID("did:web:" + encodeHost(host) + ":orgs:acme")

	r := HTTPResolver{Scheme: "http"}
	doc, err := r.Resolve(did)
	if err != nil {
		t.Fatalf("Resolve over http: %v", err)
	}
	got, err := doc.FirstKey()
	if err != nil {
		t.Fatalf("FirstKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("http-resolved key does not match the served document")
	}

	// A mismatched-id document must be rejected: ask for a DID the server does
	// not serve under that path's id.
	if _, err := r.Resolve(types.DID("did:web:" + encodeHost(host) + ":orgs:other")); err == nil {
		t.Fatal("expected error resolving an unserved DID")
	}
}

// encodeHost percent-encodes the ':' before a port, as did:web requires.
func encodeHost(hostPort string) string {
	out := ""
	for _, c := range hostPort {
		if c == ':' {
			out += "%3A"
		} else {
			out += string(c)
		}
	}
	return out
}

func TestDIDWebToURL(t *testing.T) {
	cases := []struct {
		did  types.DID
		want string
	}{
		{"did:web:example.com", "https://example.com/.well-known/did.json"},
		{"did:web:example.com:orgs:acme", "https://example.com/orgs/acme/did.json"},
		{"did:web:localhost%3A8080:orgs:acme", "https://localhost:8080/orgs/acme/did.json"},
	}
	for _, tc := range cases {
		got, err := didWebToURL(tc.did, "https")
		if err != nil {
			t.Fatalf("didWebToURL(%q): %v", tc.did, err)
		}
		if got != tc.want {
			t.Fatalf("didWebToURL(%q) = %q, want %q", tc.did, got, tc.want)
		}
	}
}

func TestFileResolver_PathMapping(t *testing.T) {
	cases := []struct {
		did  types.DID
		want string
	}{
		{"did:web:localhost", filepath.Join(didsRoot, "localhost/.well-known/did.json")},
		{"did:web:localhost:orgs:acme", filepath.Join(didsRoot, "localhost/orgs/acme/did.json")},
	}
	for _, tc := range cases {
		host, segs, err := parseDIDWeb(tc.did)
		if err != nil {
			t.Fatalf("parseDIDWeb(%q): %v", tc.did, err)
		}
		parts := []string{didsRoot, host}
		if len(segs) == 0 {
			parts = append(parts, ".well-known", "did.json")
		} else {
			parts = append(parts, segs...)
			parts = append(parts, "did.json")
		}
		if got := filepath.Join(parts...); got != tc.want {
			t.Fatalf("file path for %q = %q, want %q", tc.did, got, tc.want)
		}
	}
}

func TestJWKRoundTrip(t *testing.T) {
	pub := keyForSeed(t, 0x11)
	jwk := PublicKeyToJWK(pub)
	back, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("JWK.PublicKey: %v", err)
	}
	if !pub.Equal(back) {
		t.Fatal("JWK round trip changed the key")
	}

	// A non-Ed25519 JWK must be rejected.
	if _, err := (&JWK{Kty: "EC", Crv: "P-256", X: jwk.X}).PublicKey(); err == nil {
		t.Fatal("expected error for non-OKP JWK")
	}
}

func TestNewDocument_RoundTripsThroughFirstKey(t *testing.T) {
	pub := keyForSeed(t, 0x33)
	did := types.DID("did:web:localhost:agents:worker")
	doc := NewDocument(did, pub)
	got, err := doc.FirstKey()
	if err != nil {
		t.Fatalf("FirstKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("NewDocument did not preserve the key")
	}
	if doc.VerificationMethod[0].ID != string(did)+"#key-1" {
		t.Fatalf("unexpected vm id %q", doc.VerificationMethod[0].ID)
	}
}
