// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package webhost

import (
	"net/url"
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
		{"port overflows an int", "example.com:" + strings.Repeat("9", 25), "out of range"},
		{"port not a number", "example.com:abc", "not a number"},
		{"port empty", "example.com:", "not a number"},

		// A signed port is a GRAMMAR violation, not a range violation, which is
		// why these say "not a number" rather than "out of range". strconv.Atoi
		// accepts a leading sign, so "+1" parsed as 1 and passed the range check
		// while net/url refuses ":+1" outright: did:web:0%3A+1 validated here and
		// produced a URL the caller could not parse. Found by internal/did's
		// FuzzDIDWebToURL.
		{"port with plus sign", "example.com:+1", "not a number"},
		{"port negative", "example.com:-1", "not a number"},
		{"port with underscore", "example.com:1_0", "not a number"},
		{"port with leading space", "example.com: 1", "not a number"},
		{"unbracketed ipv6", "::1", "must be bracketed"},
		{"unclosed bracket", "[::1", "closing bracket"},
		{"junk after bracket", "[::1]junk", "after the IPv6 literal"},
		{"empty ipv6", "[]", "empty IPv6"},
		{"ipv6 with structure", "[::1@evil]", "not an IP address"},
		{"ipv6 zone id", "[fe80::1%eth0]", "zone id"},

		// Bracketed values that are made only of the characters an IPv6 literal
		// may contain, but are not IPv6 addresses. The check was previously a
		// character class, so every one of these passed here and then failed
		// later inside net/url, which put the refusal in the wrong place and
		// described it in terms of a URL the caller never wrote. Found by
		// internal/did's FuzzDIDWebToURL.
		{"ipv6 single digit", "[0]", "not an IP address"},
		{"ipv6 bare hex group", "[ffff]", "not an IP address"},
		{"ipv6 two double colons", "[::1::2]", "not an IP address"},
		{"ipv6 dot only", "[.]", "not an IP address"},
		{"ipv6 colon only", "[:]", "not an IP address"},
		// An IPv4 address is a valid IP but is not an IPv6 literal, and net/url
		// refuses it in brackets. Rejecting it here keeps the two agreeing.
		{"ipv4 in brackets", "[1.2.3.4]", "IPv4 address"},
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
	for _, host := range acceptedHosts() {
		t.Run(host, func(t *testing.T) {
			if err := Validate(host); err != nil {
				t.Errorf("Validate(%q) rejected a legitimate host: %v", host, err)
			}
		})
	}
}

// acceptedHosts is the shared list of hosts that must pass. It is a function
// rather than a literal inside one test because two tests assert different
// things about the same set: that each is accepted, and that each accepted value
// can then be built into a URL.
func acceptedHosts() []string {
	return []string{
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
	}
}

// TestAcceptedHostAlwaysBuildsAParseableURL states the invariant the two
// instance fixes above were each half of, so the next one is caught as a class.
//
// A host that clears Validate is built straight into a URL and fetched; nothing
// asks again. So Validate must accept NO MORE than net/url does, and both
// defects found here were that rule broken in different places: a character
// class admitting "[0]" as an IPv6 literal, and strconv.Atoi admitting "+1" as a
// port. Each was fixed on its own terms, and neither fix would have caught the
// other. This asserts the shared property directly.
//
// It runs over the accepted table above, so a host added there gets checked
// against net/url for free, which is the point: the guard has to sit on the list
// people extend.
func TestAcceptedHostAlwaysBuildsAParseableURL(t *testing.T) {
	hosts := acceptedHosts()
	if len(hosts) == 0 {
		t.Fatal("no accepted hosts to check; this test would pass vacuously")
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			if err := Validate(host); err != nil {
				t.Fatalf("Validate(%q) rejected a host the accepted table names: %v", host, err)
			}
			raw := "https://" + host + "/.well-known/did.json"
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("Validate accepted %q but net/url cannot parse %q: %v\n\n"+
					"Validate must accept no more than net/url does: an accepted host is "+
					"built into a URL and fetched without being asked again, so a value "+
					"that only fails later fails in the wrong place.", host, raw, err)
			}
			// The host must also survive the round trip unchanged. A URL that
			// parses but reports a different host would be the host-confusion
			// class this package exists to close.
			if u.Host != host {
				t.Fatalf("Validate accepted %q but net/url reads the host as %q", host, u.Host)
			}
		})
	}
}
