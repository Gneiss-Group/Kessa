// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestDIDDeterminesTheURL is the regression test for the defect CodeQL surfaced
// as go/request-forgery: a did:web identifier whose host carried URL structure,
// so the DID did not determine the URL fetched from it.
//
// The assertion is deliberately on parseDIDWeb, the PARSE boundary, and not on
// didWebToURL. Building the URL with net/url would also neutralise most of these
// inputs by escaping them, but escaping turns a hostile identifier into a
// confusing 404 instead of a refusal, and it would leave DocumentPath, which
// shares this parser and writes to the filesystem, depending on a fix made in the
// URL layer. Rejecting here is what makes both callers safe.
func TestDIDDeterminesTheURL(t *testing.T) {
	// Percent-encoded, because that is how a host smuggles these past the ":"
	// field split in a did:web identifier. Decoded forms in the comments.
	cases := []struct {
		name string
		did  string
	}{
		{"userinfo redirects the request", "did:web:evil.com%40169.254.169.254"}, // evil.com@169.254.169.254
		{"query swallows the path", "did:web:evil.com%3Fa=b"},                    // evil.com?a=b
		{"fragment truncates the path", "did:web:evil.com%23frag"},               // evil.com#frag
		{"slash in host", "did:web:evil.com%2Fpath"},                             // evil.com/path
		{"space in host", "did:web:evil.com%20host"},                             // evil.com host
		{"crlf header injection", "did:web:evil.com%0D%0AHost%3A+x"},
		{"port zero", "did:web:example.com%3A0"},
		{"port out of range", "did:web:example.com%3A99999"},
		{"non-numeric port", "did:web:example.com%3Aabc"},
		{"empty port", "did:web:example.com%3A"},
		{"empty label", "did:web:example..com"},
		{"leading dash", "did:web:-evil.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseDIDWeb(types.DID(tc.did)); err == nil {
				t.Errorf("parseDIDWeb(%q) accepted a host that carries URL structure", tc.did)
			}
			// Both callers of parseDIDWeb must refuse it, not just the URL one.
			if u, err := didWebToURL(types.DID(tc.did), "https"); err == nil {
				t.Errorf("didWebToURL(%q) built %q from a host it should have refused", tc.did, u)
			}
			if p, err := DocumentPath("/tmp/root", types.DID(tc.did)); err == nil {
				t.Errorf("DocumentPath(%q) built %q from a host it should have refused", tc.did, p)
			}
		})
	}
}

// TestDIDWebURLsAreUnchangedForValidInput is the other half, and the one that
// actually carries risk. Tightening the host grammar and swapping string
// concatenation for net/url are both behaviour-preserving ONLY for valid input,
// and "only for valid input" is a claim that needs a test rather than an
// assurance. These expectations were captured from the concatenating
// implementation before it was replaced.
func TestDIDWebURLsAreUnchangedForValidInput(t *testing.T) {
	cases := []struct{ did, want string }{
		{"did:web:example.com", "https://example.com/.well-known/did.json"},
		{"did:web:example.com%3A8443", "https://example.com:8443/.well-known/did.json"},
		{"did:web:localhost%3A8080", "https://localhost:8080/.well-known/did.json"},
		{"did:web:sub.example.co.uk", "https://sub.example.co.uk/.well-known/did.json"},
		{"did:web:192.0.2.1", "https://192.0.2.1/.well-known/did.json"},
		{"did:web:example.com:orgs:acme", "https://example.com/orgs/acme/did.json"},
		{"did:web:localhost%3A8080:agents:worker", "https://localhost:8080/agents/worker/did.json"},
		{"did:web:example.com:a:b:c", "https://example.com/a/b/c/did.json"},
	}
	for _, tc := range cases {
		t.Run(tc.did, func(t *testing.T) {
			got, err := didWebToURL(types.DID(tc.did), "https")
			if err != nil {
				t.Fatalf("didWebToURL(%q) rejected a valid DID: %v", tc.did, err)
			}
			if got != tc.want {
				t.Errorf("didWebToURL(%q) changed shape:\n got: %s\nwant: %s", tc.did, got, tc.want)
			}
		})
	}
}

// TestHTTPSchemeOverrideStillWorks keeps the test-only escape hatch honest: the
// Scheme field exists so the package's own tests can run against httptest, and a
// URL-construction change is exactly the sort of thing that would break it
// silently.
func TestHTTPSchemeOverrideStillWorks(t *testing.T) {
	got, err := didWebToURL(types.DID("did:web:127.0.0.1%3A8080:x"), "http")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "http://127.0.0.1:8080/x/did.json"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestHostileHostErrorNamesTheHost checks the diagnostic, not the verdict. These
// values arrive inside a credential someone else minted, so an operator reading
// the failure needs to see which identifier was responsible.
func TestHostileHostErrorNamesTheHost(t *testing.T) {
	_, _, err := parseDIDWeb(types.DID("did:web:evil.com%40169.254.169.254"))
	if err == nil {
		t.Fatal("expected a rejection")
	}
	for _, want := range []string{"unsafe host", "evil.com@169.254.169.254", "'@'"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
