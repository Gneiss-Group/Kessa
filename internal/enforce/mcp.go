// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/version"
)

// The MCP-native listener. It lets an MCP host point its server address straight
// at Kessa with no gateway in between, speaking MCP's own JSON-RPC 2.0 wire
// format over the Streamable HTTP transport.
//
// It is deliberately a THIN, ISOLATED ADAPTER, not a second enforcement engine.
// Every request it accepts is translated into the exact same Proxy.Handle /
// Proxy.Tip calls the HTTP listener (http.go) already makes, and every reply is
// the same enforce.Result / Tip translated back out. There is one enforcement
// path in this package and this file is not it; the guarantees live in Handle.
//
// Why the isolation matters operationally: the MCP spec is under fast revision
// (new routing headers, reworked session semantics), so the real risk here is
// spec-drift, not dependency risk (there is no dependency — stdlib only). Keeping
// the whole MCP surface in one file behind a stable internal call means "update
// fast when MCP changes" is a bounded edit to this file, never a change to core
// enforcement.
//
// MAPPING (envelope model): rather than presenting the guarded tools by name,
// Kessa exposes two reserved MCP tools that carry the existing wire protocol:
//
//	kessa/tip      no arguments; returns the Tip a caller binds its PoP/approval
//	               to (the MCP equivalent of GET /tip). A caller CANNOT build a
//	               valid enforce.Request without reading this first.
//	kessa/enforce  arguments ARE an enforce.Request; returns the enforce.Result.
//	               (the MCP equivalent of POST /enforce).
//
// SPEC TARGET: MCP revision 2026-07-28 (final). That revision made the protocol
// explicitly stateless and this adapter implements it that way:
//
//   - No sessions. Protocol-level sessions were removed; this server neither
//     mints nor echoes Mcp-Session-Id, and ignores one if a client sends it.
//   - No initialize handshake. Every request carries its own protocol version
//     and client capabilities in _meta, so there is no connection state to
//     establish and none is inferred from a previous request.
//   - Request-metadata headers are REQUIRED, not advisory. MCP-Protocol-Version
//     and Mcp-Method ride every request, Mcp-Name every request that names a
//     tool. A missing one, or one that disagrees with the body, is refused with
//     HTTP 400 and JSON-RPC -32020 (HeaderMismatch).
//
// The header rule is the security-relevant one and the reason it is enforced
// rather than tolerated: an intermediary may route on the header while this
// server enforces on the body. Allowing them to disagree would let a gateway
// send one thing to a rate limiter and another to the chokepoint.

const (
	// mcpProtocolVersion is the MCP revision this adapter speaks. MCP versions are
	// date-stamped; this is the only revision the listener accepts.
	mcpProtocolVersion = "2026-07-28"

	toolTip     = "kessa/tip"
	toolEnforce = "kessa/enforce"

	// Request-metadata headers. All are REQUIRED on a request POST; Mcp-Name only
	// on a request that names a tool. They mirror body fields so intermediaries
	// can route without parsing the body — which is exactly why a header that
	// disagrees with the body is refused rather than ignored.
	hdrMCPProtocolVersion = "MCP-Protocol-Version"
	hdrMCPMethod          = "Mcp-Method"
	hdrMCPName            = "Mcp-Name"

	// Per-request protocol fields carried in params._meta. protocolVersion and
	// clientCapabilities are required on every request; the server echoes its own
	// identity back under serverInfo.
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"

	// A header value that cannot be represented as plain ASCII is carried
	// Base64-encoded between these markers, and MUST be decoded before it is
	// compared to the body value.
	b64Prefix = "=?base64?"
	b64Suffix = "?="
)

// JSON-RPC 2.0 error codes (the reserved range from the spec).
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

// MCP-defined error codes. The -32020..-32099 sub-range is reserved for the MCP
// specification, and an implementation must not emit a code from it that the
// spec does not define, so only the two this adapter can actually raise appear
// here.
const (
	rpcHeaderMismatch             = -32020
	rpcUnsupportedProtocolVersion = -32022
)

// rpcRequest is one inbound JSON-RPC 2.0 message. A message with no id is a
// notification: it is processed but gets no response body.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (r rpcRequest) isNotification() bool { return len(r.ID) == 0 }

// rpcResponse is one outbound JSON-RPC 2.0 message. Exactly one of Result or
// Error is set.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ---- MCP payload shapes ----------------------------------------------------

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// paramsEnvelope is the slice of any request's params this adapter validates
// before dispatch. Only _meta is read here: it carries the per-request protocol
// fields that replaced the initialize handshake.
type paramsEnvelope struct {
	Meta map[string]json.RawMessage `json:"_meta"`
}

type toolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []toolSpec `json:"tools"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// toolContent / toolResult are MCP's tool-call reply shape. StructuredContent
// carries the machine-readable value (a Tip or an enforce.Result); Content
// carries the same value as a text block for hosts that only read text.
type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content           []toolContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError,omitempty"`
}

// mcpServer holds no state of its own. The protocol is stateless by
// specification — nothing may be inferred from a previous request — and the
// enforcement state lives entirely in px, so there is nothing here to guard.
type mcpServer struct {
	px *Proxy
}

// MCPHandler returns an http.Handler serving the MCP-native listener over the
// Streamable HTTP transport. It funnels into the same px this package's HTTP
// Handler uses; run both against one Proxy and they share one audit log and one
// set of invariants (Proxy guards its own concurrency, so two listeners are safe).
func MCPHandler(px *Proxy) http.Handler {
	return &mcpServer{px: px}
}

func (s *mcpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Origin is checked before the method is even dispatched: the transport spec
	// requires validating it on ALL incoming connections, and a rebound page must
	// not learn which methods exist by probing.
	if !originAllowed(r) {
		http.Error(w, "forbidden: cross-origin request to a local enforcement endpoint", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet, http.MethodDelete:
		// 2026-07-28 removed both the GET stream endpoint and the DELETE that
		// terminated a session. A server on this revision answers either with 405,
		// which is also how an older client discovers it is talking to a newer
		// server.
		http.Error(w, "MCP 2026-07-28: the endpoint accepts POST only (no GET stream, no sessions)", http.StatusMethodNotAllowed)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *mcpServer) handlePost(w http.ResponseWriter, r *http.Request) {
	// A JSON-RPC body must arrive as application/json. Requiring it refuses a
	// forged cross-origin "simple request" on its own merits rather than relying
	// on the required custom headers to do it incidentally.
	if !hasJSONContentType(r) {
		http.Error(w, "unsupported media type: this endpoint accepts application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Cap the body exactly as the HTTP listener does (F6): a crafted body must not
	// stream unbounded into the JSON decoder on the evaluator's machine.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// JSON-RPC batches (a top-level array) are not supported: 2026-07-28 requires
	// the body of a POST to be a single request or notification, and the envelope
	// surface has no use for batching. Reject explicitly rather than half-handle it.
	body := bytes.TrimSpace(raw)
	if len(body) > 0 && body[0] == '[' {
		writeRPCError(w, nil, rpcInvalidRequest, "JSON-RPC batches are not supported")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, rpcParseError, "parse error: "+err.Error())
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPCError(w, req.ID, rpcInvalidRequest, `"jsonrpc" must be "2.0"`)
		return
	}

	// An explicit null id is neither a request nor a notification. The spec says
	// the id MUST NOT be null, and testing only for an ABSENT id would let null
	// through as a request — a third state the rest of this file does not model.
	if bytes.Equal(bytes.TrimSpace(req.ID), []byte("null")) {
		writeRPCErrorStatus(w, nil, http.StatusBadRequest, rpcInvalidRequest, `"id" must not be null`)
		return
	}

	// A notification carries no id and gets no response body. This revision
	// defines no client-to-server notifications over Streamable HTTP and does not
	// define header requirements for a notification POST, so one is acknowledged
	// without the request-metadata validation below rather than refused on a rule
	// the spec does not state.
	if req.isNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !s.validateRequestMetadata(w, r, req) {
		return
	}

	s.dispatch(w, r, req)
}

// validateRequestMetadata enforces the per-request protocol contract that
// replaced the initialize handshake. It reports whether dispatch may proceed and
// has already written the error response when it may not.
//
// Order matters: the headers are checked against the body before the version is
// checked for support, so a client that disagrees with itself is told that
// rather than being told its version is unsupported.
func (s *mcpServer) validateRequestMetadata(w http.ResponseWriter, r *http.Request, req rpcRequest) bool {
	hdrVersion, ok := requireSingleHeader(w, r, req.ID, hdrMCPProtocolVersion)
	if !ok {
		return false
	}

	hdrMethod, ok := requireSingleHeader(w, r, req.ID, hdrMCPMethod)
	if !ok {
		return false
	}
	if hdrMethod != req.Method {
		writeHeaderMismatch(w, req.ID, fmt.Sprintf("%s %q does not match body method %q", hdrMCPMethod, hdrMethod, req.Method))
		return false
	}

	var pe paramsEnvelope
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &pe); err != nil {
			writeRPCErrorStatus(w, req.ID, http.StatusBadRequest, rpcInvalidParams, "invalid params: "+err.Error())
			return false
		}
	}

	// protocolVersion and clientCapabilities are required on every request; a
	// request missing either is malformed, which is -32602 with a 400, NOT a
	// header mismatch — the headers may be perfectly consistent with a body that
	// is simply incomplete.
	bodyVersion, ok := metaString(pe.Meta, metaProtocolVersion)
	if !ok {
		writeRPCErrorStatus(w, req.ID, http.StatusBadRequest, rpcInvalidParams,
			"params._meta must carry "+metaProtocolVersion)
		return false
	}
	// clientCapabilities must be an OBJECT, not merely present. Checking presence
	// alone accepts a JSON null, which satisfies the letter of "required field"
	// while supplying nothing — the same shape as a check that fires only when a
	// field happens to be there.
	if !metaIsObject(pe.Meta, metaClientCapabilities) {
		writeRPCErrorStatus(w, req.ID, http.StatusBadRequest, rpcInvalidParams,
			"params._meta must carry "+metaClientCapabilities+" as an object")
		return false
	}

	if hdrVersion != bodyVersion {
		writeHeaderMismatch(w, req.ID, fmt.Sprintf("%s %q does not match body %s %q",
			hdrMCPProtocolVersion, hdrVersion, metaProtocolVersion, bodyVersion))
		return false
	}

	if bodyVersion != mcpProtocolVersion {
		writeRPCErrorData(w, req.ID, http.StatusBadRequest, rpcUnsupportedProtocolVersion,
			"unsupported protocol version "+bodyVersion,
			map[string]any{"supported": []string{mcpProtocolVersion}})
		return false
	}

	return true
}

// requireSingleHeader reads a mirrored header that must be present exactly once,
// writing the HeaderMismatch refusal itself when it is missing or repeated.
func requireSingleHeader(w http.ResponseWriter, r *http.Request, id json.RawMessage, name string) (string, bool) {
	v, present, duplicated := singleHeader(r, name)
	switch {
	case duplicated:
		writeHeaderMismatch(w, id, "header "+name+" appears more than once")
		return "", false
	case !present:
		writeHeaderMismatch(w, id, "missing required "+name+" header")
		return "", false
	}
	return v, true
}

// metaIsObject reports whether a _meta field is present AND a JSON object.
func metaIsObject(meta map[string]json.RawMessage, key string) bool {
	raw, ok := meta[key]
	if !ok {
		return false
	}
	var obj map[string]json.RawMessage
	return json.Unmarshal(raw, &obj) == nil && obj != nil
}

// metaString reads a string-valued _meta field. A field present but not a JSON
// string is treated as absent: the caller's "required field missing" error is
// the honest description either way.
func metaString(meta map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := meta[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", false
	}
	return s, true
}

// decodeHeaderValue resolves the Base64 sentinel a client uses for a header
// value that cannot be plain ASCII. A value outside the sentinel form is
// returned unchanged.
func decodeHeaderValue(v string) (string, error) {
	if !strings.HasPrefix(v, b64Prefix) || !strings.HasSuffix(v, b64Suffix) {
		return v, nil
	}
	enc := v[len(b64Prefix) : len(v)-len(b64Suffix)]
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *mcpServer) dispatch(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	switch req.Method {
	case "ping":
		writeRPCResult(w, req.ID, map[string]any{})
	case "tools/list":
		writeRPCResult(w, req.ID, s.toolsList())
	case "tools/call":
		s.handleToolsCall(w, r, req)
	default:
		// An unimplemented method is 404 with -32601, not a 200 carrying an error.
		// The status is load-bearing: it is how a client distinguishes a modern
		// server that does not implement a method from a legacy server that does
		// not host this endpoint at all. "initialize" lands here by design — this
		// revision has no handshake.
		writeRPCErrorStatus(w, req.ID, http.StatusNotFound, rpcMethodNotFound, "unknown method: "+req.Method)
	}
}

func (s *mcpServer) handleToolsCall(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPCError(w, req.ID, rpcInvalidParams, "invalid tools/call params: "+err.Error())
		return
	}

	// Mcp-Name is required on a request that names a tool, and must name the tool
	// the body's params do. It may arrive Base64-encoded, and MUST be decoded
	// before the comparison — comparing the encoded form would reject a
	// conforming client.
	h, ok := requireSingleHeader(w, r, req.ID, hdrMCPName)
	if !ok {
		return
	}
	name, err := decodeHeaderValue(h)
	if err != nil {
		writeHeaderMismatch(w, req.ID, hdrMCPName+" is not valid base64: "+err.Error())
		return
	}
	if name != p.Name {
		writeHeaderMismatch(w, req.ID, fmt.Sprintf("%s %q does not match tool %q", hdrMCPName, name, p.Name))
		return
	}

	switch p.Name {
	case toolTip:
		// The MCP equivalent of GET /tip. Advisory by design: another request can
		// take the slot first, and Handle re-checks the bound evidence against the
		// position the entry actually lands in (see Tip's doc).
		writeToolResult(w, req.ID, s.px.Tip(), false)

	case toolEnforce:
		var er Request
		if err := json.Unmarshal(p.Arguments, &er); err != nil {
			writeRPCError(w, req.ID, rpcInvalidParams, "invalid enforce.Request arguments: "+err.Error())
			return
		}
		res, err := s.px.Handle(er)
		if err != nil {
			// An unattributable request never became an audit entry (Handle's
			// contract). It is not a decision, so it is surfaced as a tool-level
			// error the MCP host sees in-band — the same meaning the HTTP listener
			// conveys with 422, without importing HTTP status onto this surface.
			// A plain DENY is NOT this: a deny is a real decision and comes back
			// below with isError:false.
			writeToolError(w, req.ID, "proxy rejected request: "+err.Error())
			return
		}
		writeToolResult(w, req.ID, res, false)

	default:
		writeRPCError(w, req.ID, rpcInvalidParams, "unknown tool: "+p.Name)
	}
}

func (s *mcpServer) toolsList() toolsListResult {
	return toolsListResult{Tools: []toolSpec{
		{
			Name:        toolTip,
			Description: "Return the next audit-log slot {seq, prevHash} to bind proof-of-possession and approval to before calling kessa/enforce.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		{
			Name: toolEnforce,
			Description: "Adjudicate one action attempt. Arguments are a complete enforce.Request " +
				"(delegation chain, action, proof-of-possession, and human approval for consequential actions). " +
				"Returns the enforce.Result: the allow/deny decision and the signed audit entry.",
			InputSchema: json.RawMessage(`{"type":"object","required":["chain","action","pop"],` +
				`"properties":{"chain":{"type":"object"},"action":{"type":"object"},"pop":{"type":"object"},` +
				`"approver":{"type":"string"},"approval":{"type":"string"}}}`),
		},
	}}
}

// ---- JSON-RPC / tool reply writers -----------------------------------------

// writeToolResult wraps a machine-readable value as an MCP tool reply: the value
// as structuredContent, and its JSON as a text block for text-only hosts.
func writeToolResult(w http.ResponseWriter, id json.RawMessage, payload any, isError bool) {
	text, err := json.Marshal(payload)
	if err != nil {
		writeRPCError(w, id, rpcInternalError, "marshal tool result: "+err.Error())
		return
	}
	writeRPCResult(w, id, toolResult{
		Content:           []toolContent{{Type: "text", Text: string(text)}},
		StructuredContent: payload,
		IsError:           isError,
	})
}

// writeToolError reports a tool-level failure (isError) with a human-readable
// message and no structured payload.
func writeToolError(w http.ResponseWriter, id json.RawMessage, msg string) {
	writeRPCResult(w, id, toolResult{
		Content: []toolContent{{Type: "text", Text: msg}},
		IsError: true,
	})
}

// writeRPCResult writes a successful reply. Every result carries a resultType
// ("complete" — this adapter never needs a client round-trip, so it has no
// "input_required" case) and the server's identity in _meta, which is how a
// stateless client learns who answered without an initialize handshake.
func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	obj, err := resultObject(result)
	if err != nil {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: idOrNull(id),
			Error: &rpcError{Code: rpcInternalError, Message: "marshal result: " + err.Error()}})
		return
	}
	obj["resultType"] = "complete"
	obj["_meta"] = map[string]any{
		metaServerInfo: serverInfo{Name: "kessa-proxy", Version: version.Version},
	}
	writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Result: obj})
}

// resultObject renders a result value as a JSON object so the protocol fields
// can be added to it. Every result this adapter produces is an object; a
// non-object would be a programming error, and is reported as one.
func resultObject(result any) (map[string]any, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("result is not a JSON object: %w", err)
	}
	return obj, nil
}

// writeRPCError writes a JSON-RPC error on a 200. This is for errors that are
// about the CALL rather than the protocol envelope — an unknown tool, or
// arguments that will not parse. Envelope faults use writeRPCErrorStatus, since
// the spec makes their HTTP status part of the contract.
func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeRPCErrorStatus(w, id, http.StatusOK, code, msg)
}

// writeRPCErrorStatus writes a JSON-RPC error with an explicit HTTP status.
func writeRPCErrorStatus(w http.ResponseWriter, id json.RawMessage, status, code int, msg string) {
	writeRPCErrorData(w, id, status, code, msg, nil)
}

// writeRPCErrorData is writeRPCErrorStatus with a data member, which some MCP
// errors require (UnsupportedProtocolVersion carries the versions the server
// does support, so a client can retry without guessing).
func writeRPCErrorData(w http.ResponseWriter, id json.RawMessage, status, code int, msg string, data any) {
	writeRPC(w, status, rpcResponse{JSONRPC: "2.0", ID: idOrNull(id),
		Error: &rpcError{Code: code, Message: msg, Data: data}})
}

// writeHeaderMismatch refuses a request whose mirrored headers are missing or
// disagree with the body: HTTP 400 with -32020. Both halves matter — an
// intermediary may act on the status without parsing the body.
func writeHeaderMismatch(w http.ResponseWriter, id json.RawMessage, msg string) {
	writeRPCErrorStatus(w, id, http.StatusBadRequest, rpcHeaderMismatch, "header mismatch: "+msg)
}

func writeRPC(w http.ResponseWriter, status int, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// idOrNull satisfies JSON-RPC's rule that every response echo an id: a response
// to a request whose id could not be read (parse error, malformed body) carries
// a null id rather than omitting it.
func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
