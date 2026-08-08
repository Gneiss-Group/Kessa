// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package status

import (
	"path/filepath"
	"strings"
	"testing"
)

// PublishPath is the write-side twin of did.DocumentPath: it maps a status-list
// URL, which arrives inside a credential and is therefore supplied by whoever
// issued that credential, onto a filesystem path that Publish then creates
// directories for and writes a file to. It shares its host grammar with
// did.parseDIDWeb because the two once carried separate copies of the same
// denylist and were wrong in both places at once.
//
// The property is containment, and it is checked before the clean rather than
// after: filepath.Join resolves a ".." away, so a traversal that got past the
// segment loop would leave a plausible-looking path that lands outside the root,
// and a prefix check alone would still pass.

const fuzzPublishRoot = "/kessa-fuzz-publish"

func FuzzPublishPath(f *testing.F) {
	for _, s := range []string{
		"https://localhost/orgs/acme/status.json",
		"https://example.com:8443/s.json",
		"http://192.0.2.1/a/b/c.json",
		// Userinfo, query and fragment: each makes the URL mean something other
		// than it appears to, and each is refused rather than normalised away.
		"https://acme.example@169.254.169.254/s.json",
		"https://example.com/s.json?a=b",
		"https://example.com/s.json#frag",
		// Traversal through the path, and the degenerate paths around it.
		"https://example.com/../../etc/passwd",
		"https://example.com/a/../../b.json",
		"https://example.com/",
		"https://example.com",
		// Wrong scheme, no scheme, no host.
		"file:///etc/passwd",
		"//example.com/s.json",
		"https:///s.json",
		"",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, listURL string) {
		path, err := PublishPath(fuzzPublishRoot, listURL)
		if err != nil {
			if path != "" {
				t.Fatalf("PublishPath returned path %q alongside error %v", path, err)
			}
			return
		}

		// 1. Containment. Publish calls MkdirAll and writes at this path, so an
		//    escape is a write outside the publication root driven by a URL that
		//    came out of a credential.
		if !strings.HasPrefix(path, fuzzPublishRoot+string(filepath.Separator)) {
			t.Fatalf("PublishPath(%q) escaped the root: %q", listURL, path)
		}

		// 2. Nothing needed cleaning. A result that differs from its own cleaned
		//    form means a traversal element reached filepath.Join and was
		//    silently resolved, which is the case the prefix check above cannot
		//    see on its own.
		if path != filepath.Clean(path) {
			t.Fatalf("PublishPath(%q) returned an uncleaned path: %q", listURL, path)
		}
		for _, seg := range strings.Split(path, string(filepath.Separator)) {
			if seg == ".." {
				t.Fatalf("PublishPath(%q) contains a traversal segment: %q", listURL, path)
			}
		}
	})
}
