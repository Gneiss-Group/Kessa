// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/signer"
)

// A P-256 public key must survive the JWK encode/parse round trip and still
// verify a signature its private key produced. This is the DID-document side of
// the employee/device key: enrollment publishes the hardware P-256 key here.
func TestJWK_P256RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	jwk := PublicKeyToJWK(&priv.PublicKey)
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" {
		t.Fatalf("unexpected P-256 JWK: %+v", jwk)
	}

	back, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("parse P-256 JWK: %v", err)
	}
	if !signer.KeysEqual(back, &priv.PublicKey) {
		t.Fatal("round-tripped P-256 key differs from the original")
	}

	// The parsed key verifies a genuine signature, so the round trip preserved
	// the actual curve point, not just the bytes. signer.Verify hashes with
	// SHA-256, so the test signs the same digest the dispatcher checks.
	msg := []byte("did-published P-256 key")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !signer.Verify(back, msg, sig) {
		t.Fatal("parsed P-256 key must verify a signature from its private half")
	}
}

// A JWK claiming to be P-256 but carrying a point that is not on the curve must
// be rejected at parse time, not silently accepted.
func TestJWK_P256OffCurveRejected(t *testing.T) {
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, p256CoordSize))
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: zero, Y: zero}
	if _, err := jwk.PublicKey(); err == nil {
		t.Fatal("an off-curve P-256 point must be rejected")
	}
}

// A P-256 coordinate whose high byte is zero encodes to fewer than 32 raw bytes
// from big.Int; the JWK must still be fixed 32-byte width and parse back equal.
func TestJWK_P256ShortCoordinatePadded(t *testing.T) {
	// Try several keys; at least one will have a short coordinate in practice, but
	// the invariant we assert holds for every key: the encoded coordinate decodes
	// to exactly p256CoordSize bytes.
	for i := 0; i < 8; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		jwk := PublicKeyToJWK(&priv.PublicKey)
		xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			t.Fatalf("decode x: %v", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			t.Fatalf("decode y: %v", err)
		}
		if len(xb) != p256CoordSize || len(yb) != p256CoordSize {
			t.Fatalf("coordinates are %d/%d bytes, want %d", len(xb), len(yb), p256CoordSize)
		}
		back, err := jwk.PublicKey()
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !signer.KeysEqual(back, &priv.PublicKey) {
			t.Fatal("padded coordinate did not round-trip")
		}
	}
}
