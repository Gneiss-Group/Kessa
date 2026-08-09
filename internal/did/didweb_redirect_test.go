// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// serveDoc starts a test server that answers every path with a DID document for
// whatever DID the caller nominates. The DID is read at request time because it
// cannot be known until httptest has picked a port.
func serveDoc(t *testing.T, did *types.DID) *httptest.Server {
	t.Helper()
	pub := keyForSeed(t, 0x11)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NewDocument(*did, pub))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestResolve_RefusesCrossHostRedirect is the guard for the trust-anchor move. A
// did:web identifier IS a host plus a path, so a document served by a different
// host than the DID names has a different TLS certificate behind it, which is a
// different trust anchor.
//
// The document check in Resolve cannot catch this: the redirect target here
// serves a document whose id MATCHES the requested DID, so content validation is
// satisfied and only the refusal below stands between the resolver and trusting
// a server the DID never mentioned. That is exactly why this test serves a
// matching document rather than a mismatched one.
func TestResolve_RefusesCrossHostRedirect(t *testing.T) {
	var did types.DID
	target := serveDoc(t, &did)

	// The redirector sends the resolver off to the other host.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	redirHost := mustHost(t, redirector.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(redirHost, ":", "%3A"))

	// The DID's own host is permitted; the redirect TARGET is not the point here.
	// The allowlist passes, and the cross-host refusal is what must still fire,
	// which is how this stays a test of the redirect rule rather than of the list.
	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{redirHost}}
	_, err := r.Resolve(did)
	if err == nil {
		t.Fatal("Resolve followed a redirect to a host the DID does not name")
	}
	for _, want := range []string{"redirected to", "must come from the host the DID names"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestResolve_AllowsSameHostRedirect keeps the refusal from being a blanket ban.
// Trailing-slash and path canonicalisation are ordinary web-server behaviour and
// move no trust anchor, so they must still work. Without this, the cross-host
// test above would also pass against an implementation that simply refused every
// redirect, and the pair is what pins the behaviour to the actual rule.
func TestResolve_AllowsSameHostRedirect(t *testing.T) {
	var did types.DID
	pub := keyForSeed(t, 0x11)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/canonical/") {
			http.Redirect(w, r, "/canonical"+r.URL.Path, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NewDocument(did, pub))
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))
	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{host}}
	if _, err := r.Resolve(did); err != nil {
		t.Fatalf("a same-host redirect should still resolve: %v", err)
	}
}

// TestResolve_CapsRedirectChain stops a server from holding the resolver in a
// loop. Same-host redirects are allowed, so without a cap "allowed" would mean
// "forever".
func TestResolve_CapsRedirectChain(t *testing.T) {
	var did types.DID
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/again", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))
	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{host}}
	_, err := r.Resolve(did)
	if err == nil {
		t.Fatal("an endless same-host redirect chain should be refused")
	}
	if !strings.Contains(err.Error(), "redirected more than") {
		t.Errorf("error %q should name the redirect cap", err)
	}
}

// TestSameHost covers the normalisation directly, since a server that
// canonicalises to an explicit :443 must not read as a different host.
func TestSameHost(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/x", "https://example.com/y", true},
		{"https://example.com/x", "https://EXAMPLE.com/y", true},
		{"https://example.com/x", "https://example.com:443/y", true},
		{"http://example.com/x", "http://example.com:80/y", true},
		{"https://example.com/x", "https://example.com:8443/y", false},
		{"https://example.com/x", "https://evil.com/y", false},
		{"https://example.com/x", "https://sub.example.com/y", false},
		{"https://example.com:8443/x", "https://example.com:8443/y", true},
	}
	for _, tc := range cases {
		a, b := mustParse(t, tc.a), mustParse(t, tc.b)
		if got := sameHost(a, b); got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	return mustParse(t, raw).Host
}
