// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package webhost validates the host component of a did:web identifier or a
// published status-list URL.
//
// It exists because two callers derive a real-world effect from an
// attacker-supplied host, and they were each carrying their own partial version
// of the same check:
//
//   - did.parseDIDWeb feeds the host into a URL the verifier FETCHES.
//   - status.PublishPath feeds the host into a filesystem path it WRITES.
//
// Both previously rejected "/", "\", "." and ".." and accepted everything else.
// That is a denylist, and it had the gap denylists have: "@", "?" and "#" all
// passed, so a host could carry URL structure. The concrete result was that
// did:web:evil.com%40169.254.169.254 built the URL
// https://evil.com@169.254.169.254/.well-known/did.json, which requests the
// metadata address while reading as evil.com, and did:web:evil.com%3Fa=b pushed
// the /.well-known/did.json path into a query string so the fetch hit "/".
//
// So this is an ALLOWLIST GRAMMAR rather than a longer list of bad characters.
// The distinction is the point: a denylist has to be extended every time someone
// finds the next delimiter, and the bug above IS that pattern having already
// failed once. An allowlist that admits only hostnames and IP literals cannot
// admit a delimiter nobody thought of.
//
// What this package deliberately does NOT do is decide whether a host is a
// desirable destination. Whether 127.0.0.1 or 169.254.169.254 may be contacted is
// a policy question that depends on the caller and, for a network fetch, has to be
// answered against the resolved address at dial time rather than the name. Keeping
// that out of here means this function is a pure grammar check with no network
// behaviour and no configuration.
package webhost

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxHostLen is the maximum length of a hostname, per RFC 1035 presentation
// form. Applied to the name only, never counting a ":port" suffix.
const MaxHostLen = 253

// Validate reports whether host is a syntactically acceptable did:web or
// status-list host: a DNS hostname, an IPv4 literal, or a bracketed IPv6
// literal, each optionally followed by ":port".
//
// The returned error names what was wrong, because these values come from a
// credential someone else minted and "invalid host" in an audit trail is a
// worse answer than saying which rule it broke.
func Validate(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}

	name, port, hasPort, err := splitPort(host)
	if err != nil {
		return err
	}

	// Name first, port second. Order matters for the error, not the verdict: a
	// host like "evil.com\nHost: x" contains a colon, so a port-first check
	// rejects it with "port not a number" and buries the header injection it was
	// actually attempting. The rule that fired is what gets written to an audit
	// trail, so it should be the rule that describes the input.
	if strings.HasPrefix(name, "[") {
		if err := validateIPv6Literal(name); err != nil {
			return err
		}
	} else if err := validateHostname(name); err != nil {
		return err
	}

	if hasPort {
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("port %q is not a number", port)
		}
		// Port 0 means "any free port" to a listener and is never a destination.
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range 1 to 65535", p)
		}
	}
	return nil
}

// splitPort separates an optional ":port" suffix. A bracketed IPv6 literal keeps
// its colons, so the split looks for the LAST colon and only outside brackets.
//
// hasPort distinguishes "no colon at all" from "a colon with nothing after it".
// Without that distinction "example.com:" reads as portless and is accepted, then
// builds the URL "https://example.com:/...". Returning the empty port as absent
// is a check that passes by not running.
func splitPort(host string) (name, port string, hasPort bool, err error) {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		if end < 0 {
			return "", "", false, fmt.Errorf("IPv6 literal %q is missing its closing bracket", host)
		}
		rest := host[end+1:]
		switch {
		case rest == "":
			return host, "", false, nil
		case strings.HasPrefix(rest, ":"):
			return host[:end+1], rest[1:], true, nil
		default:
			return "", "", false, fmt.Errorf("unexpected %q after the IPv6 literal in %q", rest, host)
		}
	}
	i := strings.LastIndex(host, ":")
	if i < 0 {
		return host, "", false, nil
	}
	// A second colon outside brackets is an unbracketed IPv6 literal, which is
	// ambiguous with a port and is not valid in a URL host.
	if strings.Contains(host[:i], ":") {
		return "", "", false, fmt.Errorf("host %q has multiple colons; an IPv6 literal must be bracketed", host)
	}
	return host[:i], host[i+1:], true, nil
}

// validateHostname accepts a DNS name or an IPv4 literal. The two share a
// grammar here: an IPv4 literal is a valid hostname shape, and rejecting or
// specially casing it would only matter if this function decided policy, which
// it does not.
func validateHostname(name string) error {
	if name == "" {
		return fmt.Errorf("empty host")
	}
	if len(name) > MaxHostLen {
		return fmt.Errorf("host is %d bytes, over the %d limit", len(name), MaxHostLen)
	}
	// A trailing dot is legal in DNS but would create an empty final label here
	// and an empty directory component in the filesystem mapping, so it is not
	// accepted. did:web has no use for the distinction.
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("host %q has an empty label", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("host %q has a label longer than 63 bytes", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("host %q has a label starting or ending with '-'", name)
		}
		for i := 0; i < len(label); i++ {
			if !isHostByte(label[i]) {
				return fmt.Errorf("host %q contains %q, which is not allowed in a hostname", name, label[i])
			}
		}
	}
	return nil
}

// validateIPv6Literal accepts "[" hexdigits-and-colons "]". The contents are not
// parsed into an address: the caller hands this to net/url and the network stack,
// both of which reject a malformed address, and the job here is to guarantee the
// value cannot carry URL or path structure.
func validateIPv6Literal(name string) error {
	if !strings.HasSuffix(name, "]") {
		return fmt.Errorf("IPv6 literal %q is missing its closing bracket", name)
	}
	inner := name[1 : len(name)-1]
	if inner == "" {
		return fmt.Errorf("empty IPv6 literal")
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		// '.' allows the IPv4-mapped form. A zone id ("%eth0") is deliberately
		// NOT allowed: a zone only has meaning for a link-local address on one
		// specific interface of one specific machine, which can never be a
		// published did:web location, and allowing '%' would admit an arbitrary
		// interface-name string into a value that becomes both a URL and a
		// filesystem path.
		if !isHex && c != ':' && c != '.' {
			return fmt.Errorf("IPv6 literal %q contains %q", name, c)
		}
	}
	return nil
}

func isHostByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}
