// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/chain"
)

// The MCP-native listener is a thin adapter over the same Proxy.Handle the HTTP
// listener uses. These tests drive it with genuinely-verifiable requests (via the
// shared harness in enforce_test.go), so an allow here is the same allow the
// independent verifier accepts: proving the adapter adds a transport, not a
// second, weaker enforcement path.

// mcpResp is the decoded JSON-RPC reply the client reads back.
type mcpResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// mcpToolReply is the tools/call result envelope.
type mcpToolReply struct {
	Content           []toolContent   `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

// stdMeta is the per-request protocol metadata every 2026-07-28 request must
// carry. It replaced the initialize handshake, so it rides in params._meta on
// each call rather than being negotiated once.
func stdMeta() map[string]any {
	return map[string]any{
		metaProtocolVersion:    mcpProtocolVersion,
		metaClientCapabilities: map[string]any{},
	}
}

// rpcBody builds a conformant request body: params with _meta merged in.
func rpcBody(id int, method string, params map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = stdMeta()
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}

// stdHeaders is the required header set. name is omitted when empty (only
// requests that name a tool carry Mcp-Name).
func stdHeaders(method, name string) map[string]string {
	h := map[string]string{
		hdrMCPProtocolVersion: mcpProtocolVersion,
		hdrMCPMethod:          method,
	}
	if name != "" {
		h[hdrMCPName] = name
	}
	return h
}

// postOK sends a fully conformant request: required headers, required _meta.
func postOK(t *testing.T, url string, id int, method string, params map[string]any) (*http.Response, *mcpResp) {
	t.Helper()
	return post(t, url, stdHeaders(method, ""), rpcBody(id, method, params))
}

// post sends one JSON-RPC message and returns the raw HTTP response plus the
// decoded body (nil body when the server sends none, e.g. a 202 to a
// notification). headers and body are applied verbatim, so a test can send a
// deliberately non-conformant request.
func post(t *testing.T, url string, headers map[string]string, msg map[string]any) (*http.Response, *mcpResp) {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := buf.Bytes()
	// Envelope faults now carry a JSON-RPC error body alongside their HTTP status,
	// so almost everything decodes. The exceptions are bodiless replies (202 to a
	// notification) and the pre-JSON faults (413, 405) that http.Error writes as
	// plain text.
	if len(bytes.TrimSpace(raw)) == 0 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return resp, nil
	}
	var out mcpResp
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode reply %q: %v", raw, err)
	}
	return resp, &out
}

func mcpServerURL(t *testing.T, px *Proxy) string {
	t.Helper()
	srv := httptest.NewServer(MCPHandler(px))
	t.Cleanup(srv.Close)
	return srv.URL
}

// callTool sends a tools/call and returns the decoded tool reply. It sets the
// matching routing headers so the happy path exercises them.
func callTool(t *testing.T, url, name string, args any) (*http.Response, *mcpToolReply, *mcpResp) {
	t.Helper()
	params := map[string]any{"name": name}
	if args != nil {
		params["arguments"] = args
	}
	resp, reply := post(t, url, stdHeaders("tools/call", name), rpcBody(1, "tools/call", params))
	if reply == nil || reply.Error != nil {
		return resp, nil, reply
	}
	var tr mcpToolReply
	if err := json.Unmarshal(reply.Result, &tr); err != nil {
		t.Fatalf("decode tool reply: %v", err)
	}
	return resp, &tr, reply
}

func TestMCPToolsList(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	resp, reply := postOK(t, url, 1, "tools/list", nil)
	if resp.StatusCode != http.StatusOK || reply.Error != nil {
		t.Fatalf("tools/list failed: status %d, reply %+v", resp.StatusCode, reply)
	}
	var tl toolsListResult
	if err := json.Unmarshal(reply.Result, &tl); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range tl.Tools {
		got[tool.Name] = true
	}
	if !got[toolTip] || !got[toolEnforce] {
		t.Fatalf("tools/list must advertise %s and %s, got %+v", toolTip, toolEnforce, tl.Tools)
	}
}

// TestMCPEnforceEnvelope is the faithfulness test: a consequential action driven
// entirely through the MCP listener produces an allow AND the independent
// verifier accepts the resulting export. The MCP path is a transport, not a
// shortcut around enforcement.
func TestMCPEnforceEnvelope(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	url := mcpServerURL(t, px)

	// Read the tip through kessa/tip, exactly as an external client must before it
	// can bind a PoP.
	_, tipReply, _ := callTool(t, url, toolTip, nil)
	var tip Tip
	if err := json.Unmarshal(tipReply.StructuredContent, &tip); err != nil {
		t.Fatal(err)
	}
	if tip.Seq != 0 {
		t.Fatalf("fresh log tip seq = %d, want 0", tip.Seq)
	}

	a := action("100") // at the $100 threshold -> consequential, needs approval
	reqBody := Request{
		Chain: h.chain, Action: a, PoP: h.pop(t, tip, a, "mcp1"),
		Approver: didAlice, Approval: h.approval(t, tip, didAlice, a),
	}
	_, reply, _ := callTool(t, url, toolEnforce, reqBody)
	if reply.IsError {
		t.Fatalf("consequential allow surfaced as tool error: %s", reply.Content[0].Text)
	}
	var res Result
	if err := json.Unmarshal(reply.StructuredContent, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential {
		t.Fatalf("expected consequential allow through MCP, got %+v", res.Decision)
	}
	// The whole point: the independent verifier accepts what the MCP path produced.
	if v := h.verify(t, px); !v.Pass() {
		t.Fatalf("verifier disagreed with MCP-produced entry: %s", v.Entries[0].Reason)
	}
}

// TestMCPDenyIsNotToolError confirms a real DENY comes back as a decision
// (isError:false), not a tool failure: only unattributable requests are errors.
func TestMCPDenyIsNotToolError(t *testing.T) {
	h := newHarness(t)
	url := mcpServerURL(t, h.proxy(t))
	a := action("100") // consequential, but sent with no approval -> denied
	_, reply, _ := callTool(t, url, toolEnforce, Request{Chain: h.chain, Action: a, PoP: h.pop(t, tip0, a, "mcp2")})
	if reply.IsError {
		t.Fatal("a deny is a valid decision and must not be reported as a tool error")
	}
	var res Result
	if err := json.Unmarshal(reply.StructuredContent, &res); err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("consequential action without approval must be denied")
	}
}

// TestMCPUnattributableIsToolError confirms a request too malformed to log (an
// unverifiable chain) surfaces as a tool-level error, mirroring the HTTP 422.
func TestMCPUnattributableIsToolError(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	url := mcpServerURL(t, px)

	// Corrupt an issuance proof so the chain no longer verifies (as in
	// TestUnverifiableChainRejectedNotLogged).
	bad := *h.chain
	bad.Links = append([]chain.Link(nil), h.chain.Links...)
	bad.Links[1].IssuerProof = append([]byte(nil), bad.Links[1].IssuerProof...)
	bad.Links[1].IssuerProof[0] ^= 0xff

	a := action("10")
	_, reply, _ := callTool(t, url, toolEnforce, Request{Chain: &bad, Action: a, PoP: h.pop(t, tip0, a, "mcp3")})
	if !reply.IsError {
		t.Fatal("an unverifiable chain must surface as a tool error")
	}
	// And nothing was logged.
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Entries) != 0 {
		t.Fatalf("a rejected request must not be logged; got %d entries", len(exp.Entries))
	}
}

// TestMCPHeaderBodyDisagreement is the security-relevant case: an intermediary
// may route on the mirrored header while this server enforces on the body, so a
// header that contradicts the body must be refused, not ignored. Every rejection
// is HTTP 400 AND JSON-RPC -32020, because an intermediary may act on the status
// without parsing the body.
func TestMCPHeaderBodyDisagreement(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	cases := []struct {
		name    string
		headers map[string]string
		body    map[string]any
	}{
		{
			"Mcp-Method contradicts body method",
			map[string]string{hdrMCPProtocolVersion: mcpProtocolVersion, hdrMCPMethod: "tools/list"},
			rpcBody(1, "tools/call", map[string]any{"name": toolTip}),
		},
		{
			"Mcp-Name contradicts the tool named in the body",
			stdHeaders("tools/call", toolEnforce),
			rpcBody(2, "tools/call", map[string]any{"name": toolTip}),
		},
		{
			"MCP-Protocol-Version contradicts body _meta",
			map[string]string{hdrMCPProtocolVersion: "2025-11-25", hdrMCPMethod: "tools/list"},
			rpcBody(3, "tools/list", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, reply := post(t, url, tc.headers, tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if reply == nil || reply.Error == nil || reply.Error.Code != rpcHeaderMismatch {
				t.Fatalf("want JSON-RPC %d (HeaderMismatch), got %+v", rpcHeaderMismatch, reply)
			}
		})
	}
}

// TestMCPRequiredHeadersAreRequired: the mirrored headers are REQUIRED, not
// validated-only-when-present. A missing one is a header mismatch, which is the
// behavior a gateway relies on when it routes without parsing bodies.
func TestMCPRequiredHeadersAreRequired(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	cases := []struct {
		name    string
		headers map[string]string
		body    map[string]any
	}{
		{"no MCP-Protocol-Version", map[string]string{hdrMCPMethod: "tools/list"}, rpcBody(1, "tools/list", nil)},
		{"no Mcp-Method", map[string]string{hdrMCPProtocolVersion: mcpProtocolVersion}, rpcBody(2, "tools/list", nil)},
		{"no Mcp-Name on tools/call", stdHeaders("tools/call", ""), rpcBody(3, "tools/call", map[string]any{"name": toolTip})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, reply := post(t, url, tc.headers, tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if reply == nil || reply.Error == nil || reply.Error.Code != rpcHeaderMismatch {
				t.Fatalf("want JSON-RPC %d (HeaderMismatch), got %+v", rpcHeaderMismatch, reply)
			}
		})
	}
}

// TestMCPRequiredMetaFields: protocolVersion and clientCapabilities ride every
// request. A body missing one is malformed (-32602), which is deliberately NOT a
// header mismatch: the headers may be perfectly consistent with an incomplete
// body, and saying "header mismatch" would send a client looking in the wrong
// place.
func TestMCPRequiredMetaFields(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	for _, drop := range []string{metaProtocolVersion, metaClientCapabilities} {
		t.Run("missing "+drop, func(t *testing.T) {
			meta := stdMeta()
			delete(meta, drop)
			body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list",
				"params": map[string]any{"_meta": meta}}
			resp, reply := post(t, url, stdHeaders("tools/list", ""), body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if reply == nil || reply.Error == nil || reply.Error.Code != rpcInvalidParams {
				t.Fatalf("want JSON-RPC %d (invalid params), got %+v", rpcInvalidParams, reply)
			}
		})
	}
}

// TestMCPUnsupportedProtocolVersion: a client on a revision this adapter does not
// speak is told so explicitly, and told what IS supported, so it can retry
// without guessing.
func TestMCPUnsupportedProtocolVersion(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list",
		"params": map[string]any{"_meta": map[string]any{
			metaProtocolVersion:    "2025-11-25",
			metaClientCapabilities: map[string]any{},
		}}}
	resp, reply := post(t, url, map[string]string{
		hdrMCPProtocolVersion: "2025-11-25", hdrMCPMethod: "tools/list",
	}, body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if reply == nil || reply.Error == nil || reply.Error.Code != rpcUnsupportedProtocolVersion {
		t.Fatalf("want JSON-RPC %d, got %+v", rpcUnsupportedProtocolVersion, reply)
	}
	var data struct {
		Supported []string `json:"supported"`
	}
	if err := json.Unmarshal(reply.Error.Data, &data); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if len(data.Supported) != 1 || data.Supported[0] != mcpProtocolVersion {
		t.Fatalf("supported = %v, want [%s]", data.Supported, mcpProtocolVersion)
	}
}

// TestMCPSessionHeaderIgnored: 2026-07-28 removed protocol-level sessions. A
// stale Mcp-Session-Id from an older client must be ignored rather than rejected,
// and the server must not mint or echo one.
func TestMCPSessionHeaderIgnored(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	h := stdHeaders("tools/list", "")
	h["Mcp-Session-Id"] = "deadbeefdeadbeefdeadbeefdeadbeef"
	resp, reply := post(t, url, h, rpcBody(1, "tools/list", nil))

	if resp.StatusCode != http.StatusOK || reply == nil || reply.Error != nil {
		t.Fatalf("a session header must be ignored, got status %d reply %+v", resp.StatusCode, reply)
	}
	if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("server must not mint or echo a session id, got %q", got)
	}
}

// TestMCPInitializeIsNotFound: there is no handshake in this revision, so the
// legacy initialize call is simply an unimplemented method, and answering 404
// with a recognized JSON-RPC error is exactly how a dual-era client detects that
// this server is modern and should not fall back.
func TestMCPInitializeIsNotFound(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, reply := postOK(t, url, 1, "initialize", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("initialize should be 404, got %d", resp.StatusCode)
	}
	if reply == nil || reply.Error == nil || reply.Error.Code != rpcMethodNotFound {
		t.Fatalf("want JSON-RPC %d, got %+v", rpcMethodNotFound, reply)
	}
}

func TestMCPMethodNotFound(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, reply := postOK(t, url, 1, "does/not/exist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown method should be HTTP 404, got %d", resp.StatusCode)
	}
	if reply.Error == nil || reply.Error.Code != rpcMethodNotFound {
		t.Fatalf("unknown method should be JSON-RPC %d, got %+v", rpcMethodNotFound, reply.Error)
	}
}

// TestMCPBase64NameDecoded: a tool name that cannot ride as plain ASCII arrives
// Base64-encoded, and the server must decode before comparing. Comparing the
// encoded form would reject a conforming client.
func TestMCPBase64NameDecoded(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	encoded := b64Prefix + base64.StdEncoding.EncodeToString([]byte(toolTip)) + b64Suffix
	h := stdHeaders("tools/call", "")
	h[hdrMCPName] = encoded
	resp, reply := post(t, url, h, rpcBody(1, "tools/call", map[string]any{"name": toolTip}))

	if resp.StatusCode != http.StatusOK || reply == nil || reply.Error != nil {
		t.Fatalf("encoded Mcp-Name must be decoded and accepted, got status %d reply %+v", resp.StatusCode, reply)
	}
}

// TestMCPResultCarriesProtocolFields: with no handshake, a result is where a
// client learns the server's identity, and resultType is required on every
// result.
func TestMCPResultCarriesProtocolFields(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	_, reply := postOK(t, url, 1, "tools/list", nil)

	var got struct {
		ResultType string `json:"resultType"`
		Meta       struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"io.modelcontextprotocol/serverInfo"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(reply.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.ResultType != "complete" {
		t.Fatalf(`resultType = %q, want "complete"`, got.ResultType)
	}
	if got.Meta.ServerInfo.Name == "" || got.Meta.ServerInfo.Version == "" {
		t.Fatalf("result _meta must carry serverInfo, got %+v", got.Meta.ServerInfo)
	}
}

func TestMCPNotificationGetsNoBody(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	// A notification carries no id. This revision defines no client-to-server
	// notifications over Streamable HTTP and states no header rules for one, so it
	// is acknowledged rather than refused.
	resp, reply := post(t, url, nil, map[string]any{"jsonrpc": "2.0", "method": "notifications/progress"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification should be 202, got %d", resp.StatusCode)
	}
	if reply != nil {
		t.Fatalf("a notification must get no response body, got %+v", reply)
	}
}

func TestMCPBodyLimit(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	huge := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"junk":"` +
		strings.Repeat("A", (1<<20)+1024) + `"}}`
	resp, err := http.Post(url, "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body should be 413, got %d", resp.StatusCode)
	}
}

// TestMCPGetAndDeleteRejected: 2026-07-28 removed the GET stream endpoint and
// the DELETE that terminated a session, so the endpoint is POST-only. 405 on
// both is also how an older client discovers it is talking to a newer server.
func TestMCPGetAndDeleteRejected(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", method, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s should be 405, got %d", method, resp.StatusCode)
			}
		})
	}
}
