// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// Ingress regression suite (R5).
//
// Every test here is an adversarial proof-of-concept, inverted: the PoC asserted
// that the break reproduced against the pre-fix code, and this asserts that it no
// longer does. They are kept as tests rather than deleted because a fix without a
// test is a fix with an expiry date.
//
// The class under test is "a check that does not fire". R5 was scoped to the
// ingress surface after the MCP listener was rewritten for revision 2026-07-28,
// on the theory that the header-mirroring rule, which the rewrite had
// implemented as validate-only-when-present, would not be the only instance.
// It was not. Two of the findings below are checks that fired only under some
// inputs (a repeated header, a null-valued required field), and two are checks
// that were absent entirely (Origin, request Content-Type).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func rawPost(t *testing.T, url string, hdr map[string][]string, msg map[string]any) *http.Response {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// R5-01. A loopback bind is not an authentication boundary against a browser:
// under DNS rebinding the attacker's name resolves to 127.0.0.1, the page is
// treated as same-origin, and it may send custom headers AND read replies. The
// Origin header still names the attacker, which is why checking it is the
// defense and why the transport spec makes it a MUST.
func TestIngressForeignOriginRefused(t *testing.T) {
	px := newHarness(t).proxy(t)
	mcpURL := mcpServerURL(t, px)
	httpSrv := httptest.NewServer(Handler(px))
	t.Cleanup(httpSrv.Close)

	foreign := []string{"https://evil.example", "http://127.0.0.1.evil.example", "null"}

	for _, origin := range foreign {
		t.Run("mcp/"+origin, func(t *testing.T) {
			h := map[string][]string{"Origin": {origin}}
			for k, v := range stdHeaders("tools/list", "") {
				h[k] = []string{v}
			}
			if got := rawPost(t, mcpURL, h, rpcBody(1, "tools/list", nil)).StatusCode; got != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", got)
			}
		})

		// /export is the one that matters most: it is the entire signed audit
		// history, and a rebound page can read the response.
		t.Run("http-export/"+origin, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, httpSrv.URL+"/export", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Origin", origin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
}

// A request with no Origin is a non-browser client and must still work, and a
// loopback Origin is the legitimate same-origin browser case. The guard must not
// be so blunt that it breaks either.
func TestIngressLoopbackAndAbsentOriginAllowed(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	for _, origin := range []string{"", "http://localhost:8182", "http://127.0.0.1:8182", "http://[::1]:8182"} {
		t.Run("origin="+origin, func(t *testing.T) {
			h := map[string][]string{}
			for k, v := range stdHeaders("tools/list", "") {
				h[k] = []string{v}
			}
			if origin != "" {
				h["Origin"] = []string{origin}
			}
			if got := rawPost(t, url, h, rpcBody(1, "tools/list", nil)).StatusCode; got != http.StatusOK {
				t.Fatalf("status = %d, want 200", got)
			}
		})
	}
}

// R5-02. The header-mirroring bypass reached by REPETITION rather than absence.
// http.Header.Get returns the first value, so a second, contradictory value was
// simply unread, and an intermediary routing on the last would act on a value
// this server never validated. That is the same split-brain between router and
// enforcer the header rules exist to prevent.
func TestIngressDuplicateMirroredHeaderRefused(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	cases := []struct {
		name string
		hdr  map[string][]string
		body map[string]any
	}{
		{
			"two Mcp-Method values",
			map[string][]string{
				hdrMCPProtocolVersion: {mcpProtocolVersion},
				hdrMCPMethod:          {"tools/list", "tools/call"},
			},
			rpcBody(1, "tools/list", nil),
		},
		{
			"two MCP-Protocol-Version values",
			map[string][]string{
				hdrMCPProtocolVersion: {mcpProtocolVersion, "2025-11-25"},
				hdrMCPMethod:          {"tools/list"},
			},
			rpcBody(2, "tools/list", nil),
		},
		{
			"two Mcp-Name values",
			map[string][]string{
				hdrMCPProtocolVersion: {mcpProtocolVersion},
				hdrMCPMethod:          {"tools/call"},
				hdrMCPName:            {toolTip, toolEnforce},
			},
			rpcBody(3, "tools/call", map[string]any{"name": toolTip}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawPost(t, url, tc.hdr, tc.body).StatusCode; got != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", got)
			}
		})
	}
}

// Two Origin headers is never a real client. Refusing beats picking one: picking
// is how a validator and a router end up reading different values.
func TestIngressDuplicateOriginRefused(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	h := map[string][]string{"Origin": {"http://127.0.0.1:8182", "https://evil.example"}}
	for k, v := range stdHeaders("tools/list", "") {
		h[k] = []string{v}
	}
	if got := rawPost(t, url, h, rpcBody(1, "tools/list", nil)).StatusCode; got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
}

// R5-03. A null id is neither a request nor a notification. Testing only for an
// ABSENT id let null through as a request: a third state the dispatcher does
// not model.
func TestIngressNullIDRefused(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	body := map[string]any{"jsonrpc": "2.0", "id": nil, "method": "tools/list",
		"params": map[string]any{"_meta": stdMeta()}}

	h := map[string][]string{}
	for k, v := range stdHeaders("tools/list", "") {
		h[k] = []string{v}
	}
	if got := rawPost(t, url, h, body).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// R5-04. clientCapabilities was checked for PRESENCE only, so a JSON null
// satisfied a required field while supplying nothing: the same shape as a check
// that fires only when a field happens to be there.
func TestIngressNullClientCapabilitiesRefused(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	for _, bad := range []any{nil, "not-an-object", 42, []any{}} {
		t.Run("clientCapabilities", func(t *testing.T) {
			body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list",
				"params": map[string]any{"_meta": map[string]any{
					metaProtocolVersion:    mcpProtocolVersion,
					metaClientCapabilities: bad,
				}}}
			h := map[string][]string{}
			for k, v := range stdHeaders("tools/list", "") {
				h[k] = []string{v}
			}
			if got := rawPost(t, url, h, body).StatusCode; got != http.StatusBadRequest {
				t.Fatalf("clientCapabilities=%v: status = %d, want 400", bad, got)
			}
		})
	}
}

// R5-05. A browser may issue a cross-origin POST with no preflight only when the
// Content-Type is one of three "simple" values: none of which is
// application/json. Requiring application/json is what makes the forgery defense
// deliberate instead of a side effect of whichever custom headers an endpoint
// happens to need.
func TestIngressNonJSONContentTypeRefused(t *testing.T) {
	px := newHarness(t).proxy(t)
	mcpURL := mcpServerURL(t, px)
	httpSrv := httptest.NewServer(Handler(px))
	t.Cleanup(httpSrv.Close)

	simple := []string{"text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data", ""}

	for _, ct := range simple {
		t.Run("mcp/"+ct, func(t *testing.T) {
			body, _ := json.Marshal(rpcBody(1, "tools/list", nil))
			req, _ := http.NewRequest(http.MethodPost, mcpURL, bytes.NewReader(body))
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			for k, v := range stdHeaders("tools/list", "") {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}
		})
	}

	// The HTTP listener was the worse case: /enforce needs no custom header, so a
	// simple cross-origin POST reached Proxy.Handle with no rebinding required.
	t.Run("http-enforce", func(t *testing.T) {
		h := newHarness(t)
		p := h.proxy(t)
		srv := httptest.NewServer(Handler(p))
		t.Cleanup(srv.Close)

		a := action("10")
		body, err := json.Marshal(Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "csrf")})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/enforce", bytes.NewReader(body))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", resp.StatusCode)
		}

		// And nothing reached the log.
		exp, err := p.Export()
		if err != nil {
			t.Fatal(err)
		}
		if len(exp.Entries) != 0 {
			t.Fatalf("a refused request must not be logged; got %d entries", len(exp.Entries))
		}
	})
}
