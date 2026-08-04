// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"mime"
	"net"
	"net/http"
	"net/url"
)

// Ingress guards shared by both listeners.
//
// Both the generic HTTP listener and the MCP-native one default to a loopback
// bind, and a loopback bind is not an authentication boundary: any process on
// the host reaches it, and so does any WEB PAGE the operator happens to visit,
// which is the case these guards exist for.
//
// Two distinct attacks, which is why there are two guards:
//
//   - Cross-origin request forgery. A page can issue a "simple" cross-origin
//     POST (Content-Type text/plain, no custom headers) with no CORS preflight
//     at all. Before requireJSONContentType, such a body reached Proxy.Handle:
//     a foreign page could drive the chokepoint. The browser cannot READ the
//     reply, but the request still executed.
//   - DNS rebinding. Here CORS does not help: the attacker's name resolves to
//     127.0.0.1, so the browser treats the page as same-origin, permits custom
//     headers, and lets it read every reply. The Origin header still names the
//     attacker's site, which is exactly why checking it is the defense, and why
//     the MCP transport spec makes it a MUST.
//
// Neither guard protects a secret: a request still needs a verifiable delegation
// chain and a valid proof of possession before it can become an ALLOW. They stop
// unauthenticated traffic from reaching the enforcement path and the audit log at
// all, which is a separate property from "cannot forge a decision".

// checkIngress applies both guards. It reports whether the request may proceed
// and has already written the refusal when it may not. bodyExpected is false for
// methods with no body (GET), where the content type carries no meaning.
func checkIngress(w http.ResponseWriter, r *http.Request, bodyExpected bool) bool {
	if !originAllowed(r) {
		http.Error(w, "forbidden: cross-origin request to a local enforcement endpoint", http.StatusForbidden)
		return false
	}
	if bodyExpected && !hasJSONContentType(r) {
		http.Error(w, "unsupported media type: this endpoint accepts application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// originAllowed implements the Origin rule: a request with no Origin is allowed
// (non-browser clients do not send one), and a request whose Origin names
// anything other than a loopback host is refused.
//
// WHY ABSENCE IS TRUSTED HERE, HAVING JUST BEEN REJECTED TWICE ELSEWHERE.
// This is deliberately the "check only when present" shape that R5-02 and R5-04
// were filed for, so the difference has to be stated rather than assumed.
//
// The difference is who writes the header. Mcp-Method and clientCapabilities are
// written by the CALLER, so their absence is attacker-controlled and carries no
// information: omitting one is free, and a check that only runs when the field
// is there is a check the caller can decline. Origin is written by the BROWSER,
// and a page cannot suppress it on a cross-origin request. Within this guard's
// threat model (a web page the operator visits), absence is therefore positive
// evidence that the caller is not a cross-origin browser request, which is the
// entire population being excluded.
//
// The corollary is the limit: this is sound only because the threat model stops
// at the browser. Any non-browser client (curl, a local process, a scripted HTTP
// call) can set or omit Origin at will, so this guard is worth nothing against
// one: deliberately, since an attacker with local code execution has better
// targets than the chokepoint's front door. If the model ever widens to "any
// network client", Origin stops being evidence and the answer is authentication,
// not a stricter rule here. It is a browser-scoped defence and only that.
//
// Deliberately a fixed policy rather than a configurable allowlist. A
// cross-origin browser caller is not a use case this transport has: the
// documented deployments are a local sidecar and an in-process host, so an
// allowlist would be a knob whose only settings are "as now" and "less safe".
// A deployment that genuinely needs one should terminate TLS and CORS in front
// of the chokepoint rather than widening it here.
func originAllowed(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	switch len(origins) {
	case 0:
		return true
	case 1:
	default:
		// Two Origin headers is never a real client. Refuse rather than pick one:
		// picking is how a validator and a router end up reading different values.
		return false
	}

	u, err := url.Parse(origins[0])
	if err != nil || u.Host == "" {
		// Includes the literal "null" Origin a sandboxed iframe sends.
		return false
	}
	return isLoopbackHost(u.Hostname())
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hasJSONContentType requires an explicit application/json body. This is what
// makes the cross-origin-forgery defense DELIBERATE: application/json is not one
// of the three types a browser may send without a preflight, so requiring it
// means a forged simple request is refused on its own merits rather than
// incidentally, by whichever custom headers a given endpoint happens to need.
func hasJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}

// singleHeader reads a mirrored header that must appear at most once. It reports
// the value, whether it was present, and whether it was duplicated.
//
// This is the header-mirroring bypass reached by REPETITION rather than absence.
// http.Header.Get returns the first value; an intermediary routing on the last
// would act on a value this server never validated, which is precisely the
// split-brain the header rules exist to prevent.
func singleHeader(r *http.Request, name string) (value string, present, duplicated bool) {
	v := r.Header.Values(name)
	switch len(v) {
	case 0:
		return "", false, false
	case 1:
		return v[0], true, false
	default:
		return "", true, true
	}
}
