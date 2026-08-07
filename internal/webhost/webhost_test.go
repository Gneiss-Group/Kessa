// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package webhost

import (
	"strings"
	"testing"
)

// TestValidateRejectsURLStructure is the regression test for the defect this
// package was created for: a host that carries URL structure, so the identifier
// does not determine the URL fetched from it.
//
// Each case asserts on WHICH rule fired, not merely that an error came back.
// Several of these inputs are rejectable for more than one reason, and a test
// that passes because the wrong check tripped is a test that will keep passing
// after the right check is deleted.
func TestValidateRejectsURLStructure(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string // substring of the expected error
	}{
		// The three that were accepted before this package existed. These are the
		// ones with a demonstrated exploit path, so they are named individually
		// rather than folded into a generic "bad character" case.
		{"userinfo makes the host a lie", "evil.com@169.254.169.254", "'@'"},
		{"query swallows the document path", "evil.com?a=b", "'?'"},
		{"fragment truncates the path", "evil.com#frag", "'#'"},

		// Rejected before too, kept so a rewrite cannot quietly lose them.
		{"forward slash", "evil.com/path", "'/'"},
		{"backslash", `evil.com\path`, `'\\'`},
		{"single dot", ".", "empty label"},
		{"double dot", "..", "empty label"},

		{"space", "evil.com host", "' '"},
		{"tab", "evil.com\thost", "not allowed in a hostname"},
		{"null byte", "evil.com\x00", "not allowed in a hostname"},
		{"newline", "evil.com\nHost: x", "not allowed in a hostname"},
		{"colon in userinfo form", "user:pass@example.com", "port"},

		{"empty", "", "empty host"},
		{"empty label", "example..com", "empty label"},
		{"leading dash", "-bad.example.com", "starting or ending with '-'"},
		{"trailing dash", "bad-.example.com", "starting or ending with '-'"},
		{"trailing dot", "example.com.", "empty label"},
		{"label over 63", strings.Repeat("a", 64) + ".com", "longer than 63"},
		{"host over 253", strings.Repeat("a.", 130) + "com", "over the 253 limit"},

		{"port zero", "example.com:0", "out of range"},
		{"port too high", "example.com:99999", "out of range"},
		{"port negative", "example.com:-1", "out of range"},
		{"port not a number", "example.com:abc", "not a number"},
		{"port empty", "example.com:", "not a number"},
		{"unbracketed ipv6", "::1", "must be bracketed"},
		{"unclosed bracket", "[::1", "closing bracket"},
		{"junk after bracket", "[::1]junk", "after the IPv6 literal"},
		{"empty ipv6", "[]", "empty IPv6"},
		{"ipv6 with structure", "[::1@evil]", "contains '@'"},
		{"ipv6 zone id", "[fe80::1%eth0]", "contains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.host)
			if err == nil {
				t.Fatalf("Validate(%q) accepted a host that carries structure or is malformed", tc.host)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate(%q) failed for the wrong reason:\n got: %v\nwant substring: %q",
					tc.host, err, tc.want)
			}
		})
	}
}

// TestValidateAcceptsRealHosts guards the other direction. Tightening a check is
// only safe if the legitimate inputs still pass, and the ones below are shapes
// this project actually uses: the demo's localhost-with-port, an org's public
// name, and a bare IP.
//
// Note 169.254.169.254 is ACCEPTED here on purpose. Whether a destination is
// permitted is a policy question that has to be answered against the resolved
// address at dial time, not against the name. This function is grammar only, and
// conflating the two would put a network policy decision somewhere it cannot be
// enforced correctly.
func TestValidateAcceptsRealHosts(t *testing.T) {
	for _, host := range []string{
		"example.com",
		"sub.example.co.uk",
		"localhost",
		"localhost:8080",
		"example.com:8443",
		"example.com:65535",
		"example.com:1",
		"192.0.2.1",
		"169.254.169.254",
		"[::1]",
		"[2001:db8::1]",
		"[2001:db8::1]:8443",
		"[::ffff:192.0.2.1]",
		"xn--bcher-kva.example",
		"a",
		strings.Repeat("a", 63) + ".com",
		"under_score.example.com",
	} {
		t.Run(host, func(t *testing.T) {
			if err := Validate(host); err != nil {
				t.Errorf("Validate(%q) rejected a legitimate host: %v", host, err)
			}
		})
	}
}
