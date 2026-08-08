// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// A did:web identifier is attacker-supplied in both directions that matter: it
// decides a URL the verifier FETCHES (didWebToURL) and a filesystem path the
// issuer WRITES (DocumentPath). The hand-written cases in didweb_host_test.go
// pin the specific inputs that once got through; these targets keep searching
// for the next one as the parser changes, which is the part a fixed table cannot
// do.
//
// Both properties below were established by review rather than invented here:
// the DID determines the URL it resolves (the allowlist grammar in
// internal/webhost), and a path segment can never escape the publication root.

// didSeeds are the identifiers both targets start from: the shapes a real
// deployment uses, plus every host-confusion input the parser has previously
// been fixed for. Seeding with the historical bypasses is deliberate, it puts
// the mutator next to the neighbourhood the bugs actually lived in.
func didSeeds(f *testing.F) {
	f.Helper()
	for _, s := range []string{
		"did:web:example.com",
		"did:web:example.com%3A8443",
		"did:web:localhost%3A8080:agents:worker",
		"did:web:example.com:orgs:acme",
		"did:web:sub.example.co.uk",
		"did:web:192.0.2.1",
		"did:web:[2001:db8::1]",
		// Host confusion: each of these once produced a URL the DID did not name.
		"did:web:evil.com%40169.254.169.254",
		"did:web:evil.com%3Fa=b",
		"did:web:evil.com%23frag",
		"did:web:evil.com%2Fpath",
		"did:web:evil.com%0D%0AHost%3A+x",
		// Traversal through a path segment.
		"did:web:example.com:..:..:etc",
		"did:web:example.com:%2E%2E:x",
		"did:web:example.com::x",
		// Not a did:web at all, and the degenerate forms around the prefix.
		"did:web:",
		"did:key:z6Mk",
		"",
	} {
		f.Add(s)
	}
}

// fuzzRoot is a fixed absolute root. Neither target touches the filesystem: the
// property under test is what the mapping COMPUTES, and doing real I/O would
// make the target slow, non-hermetic, and dependent on what happens to exist on
// the machine running it.
const fuzzRoot = "/kessa-fuzz-root"

func FuzzDocumentPath(f *testing.F) {
	didSeeds(f)

	f.Fuzz(func(t *testing.T, s string) {
		path, err := DocumentPath(fuzzRoot, types.DID(s))
		if err != nil {
			if path != "" {
				t.Fatalf("DocumentPath returned path %q alongside error %v", path, err)
			}
			return
		}

		// 1. Containment. WriteDocument calls MkdirAll and WriteFile on this
		//    result, so a path outside the root is a write outside the root: the
		//    published directory is the blast radius, and the DID is supplied by
		//    whoever asks to be enrolled.
		if !strings.HasPrefix(path, fuzzRoot+string(filepath.Separator)) {
			t.Fatalf("DocumentPath(%q) escaped the root: %q", s, path)
		}

		// 2. No traversal element survives into the result. filepath.Join cleans
		//    its output, so a ".." that got past the parser would already have
		//    been resolved away by the time we see the string, and the prefix
		//    check above would still pass while the write landed somewhere else.
		//    Checking the pre-clean form is what makes the check mean something.
		if path != filepath.Clean(path) {
			t.Fatalf("DocumentPath(%q) returned an uncleaned path: %q", s, path)
		}
		for _, seg := range strings.Split(path, string(filepath.Separator)) {
			if seg == ".." {
				t.Fatalf("DocumentPath(%q) contains a traversal segment: %q", s, path)
			}
		}

		// 3. The mapping always lands on a document, never on a directory or on
		//    some other file in the tree.
		if filepath.Base(path) != "did.json" {
			t.Fatalf("DocumentPath(%q) does not name a did.json: %q", s, path)
		}
	})
}

func FuzzDIDWebToURL(f *testing.F) {
	didSeeds(f)

	f.Fuzz(func(t *testing.T, s string) {
		d := types.DID(s)
		raw, err := didWebToURL(d, "https")
		if err != nil {
			if raw != "" {
				t.Fatalf("didWebToURL returned %q alongside error %v", raw, err)
			}
			return
		}

		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("didWebToURL(%q) produced an unparseable URL %q: %v", s, raw, err)
		}

		// 1. THE property: the identifier determines the host contacted. Every
		//    host-confusion bypass this parser has had was a case where the host
		//    in the URL was not the host in the DID, so it is checked against
		//    what the parser itself extracted rather than against a re-derivation
		//    that could share the same mistake.
		host, _, err := parseDIDWeb(d)
		if err != nil {
			t.Fatalf("didWebToURL accepted %q that parseDIDWeb rejects: %v", s, err)
		}
		if u.Host != host {
			t.Fatalf("didWebToURL(%q) fetches host %q, but the DID names %q", s, u.Host, host)
		}

		// 2. No smuggled URL structure. Userinfo redirects the request while the
		//    URL still reads as the named host; a query or a fragment swallows
		//    the document path so the fetch lands on "/". All three were live
		//    bypasses, so none may reappear as a normalisation.
		if u.User != nil {
			t.Fatalf("didWebToURL(%q) produced userinfo: %q", s, raw)
		}
		if u.RawQuery != "" || u.ForceQuery {
			t.Fatalf("didWebToURL(%q) produced a query string: %q", s, raw)
		}
		if u.Fragment != "" {
			t.Fatalf("didWebToURL(%q) produced a fragment: %q", s, raw)
		}

		// 3. The request is always for a DID document over the scheme asked for,
		//    never for some other resource on that host.
		if u.Scheme != "https" {
			t.Fatalf("didWebToURL(%q) produced scheme %q: %q", s, u.Scheme, raw)
		}
		if !strings.HasSuffix(u.Path, "/did.json") {
			t.Fatalf("didWebToURL(%q) does not request a did.json: %q", s, raw)
		}
	})
}
