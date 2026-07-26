// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
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
// independent verifier accepts — proving the adapter adds a transport, not a
// second, weaker enforcement path.

// mcpResp is the decoded JSON-RPC reply the client reads back.
type mcpResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// mcpToolReply is the tools/call result envelope.
type mcpToolReply struct {
	Content           []toolContent   `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

// post sends one JSON-RPC message and returns the raw HTTP response plus the
// decoded body (nil body when the server sends none, e.g. a 202 to a
// notification). headers are applied verbatim so a test can exercise the routing
// headers.
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
	// A transport-level fault (bad routing header, unknown session) comes back as a
	// plain-text HTTP error, not a JSON-RPC body; those tests assert on status only.
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
	resp, reply := post(t, url, map[string]string{
		hdrMCPMethod: "tools/call",
		hdrMCPName:   name,
	}, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params,
	})
	if reply == nil || reply.Error != nil {
		return resp, nil, reply
	}
	var tr mcpToolReply
	if err := json.Unmarshal(reply.Result, &tr); err != nil {
		t.Fatalf("decode tool reply: %v", err)
	}
	return resp, &tr, reply
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	resp, reply := post(t, url, nil, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": mcpProtocolVersion, "capabilities": map[string]any{}},
	})
	if resp.StatusCode != http.StatusOK || reply.Error != nil {
		t.Fatalf("initialize failed: status %d, reply %+v", resp.StatusCode, reply)
	}
	if sid := resp.Header.Get(hdrMCPSessionID); sid == "" {
		t.Fatal("initialize must issue an Mcp-Session-Id")
	}
	var init initializeResult
	if err := json.Unmarshal(reply.Result, &init); err != nil {
		t.Fatal(err)
	}
	if init.ProtocolVersion != mcpProtocolVersion {
		t.Fatalf("protocol version = %q, want %q", init.ProtocolVersion, mcpProtocolVersion)
	}

	_, reply = post(t, url, nil, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	if reply.Error != nil {
		t.Fatalf("tools/list error: %+v", reply.Error)
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
// (isError:false), not a tool failure — only unattributable requests are errors.
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

func TestMCPRoutingHeaderMismatch(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))

	// Mcp-Method contradicts the body method.
	resp, _ := post(t, url, map[string]string{hdrMCPMethod: "tools/list"},
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": toolTip}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Mcp-Method mismatch should be 400, got %d", resp.StatusCode)
	}

	// Mcp-Name contradicts the tool named in the body.
	resp, _ = post(t, url, map[string]string{hdrMCPMethod: "tools/call", hdrMCPName: toolEnforce},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]any{"name": toolTip}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Mcp-Name mismatch should be 400, got %d", resp.StatusCode)
	}
}

func TestMCPUnknownSessionRejected(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, _ := post(t, url, map[string]string{hdrMCPSessionID: "deadbeefdeadbeefdeadbeefdeadbeef"},
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown session should be 404, got %d", resp.StatusCode)
	}
}

// TestMCPSessionRoundTrip confirms a session id issued by initialize is accepted
// on a later request.
func TestMCPSessionRoundTrip(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, _ := post(t, url, nil, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": mcpProtocolVersion}})
	sid := resp.Header.Get(hdrMCPSessionID)
	if sid == "" {
		t.Fatal("no session issued")
	}
	resp, reply := post(t, url, map[string]string{hdrMCPSessionID: sid},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	if resp.StatusCode != http.StatusOK || reply.Error != nil {
		t.Fatalf("issued session should be accepted, got status %d reply %+v", resp.StatusCode, reply)
	}
}

func TestMCPMethodNotFound(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	_, reply := post(t, url, nil, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "does/not/exist"})
	if reply.Error == nil || reply.Error.Code != rpcMethodNotFound {
		t.Fatalf("unknown method should be JSON-RPC %d, got %+v", rpcMethodNotFound, reply.Error)
	}
}

func TestMCPNotificationGetsNoBody(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, reply := post(t, url, nil, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
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

func TestMCPGetHasNoStream(t *testing.T) {
	url := mcpServerURL(t, newHarness(t).proxy(t))
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET with no server stream should be 405, got %d", resp.StatusCode)
	}
}
