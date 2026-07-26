// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

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
// SPEC TARGET: the 2026-07-28 release candidate. The routing-header and
// session-id handling below follows that RC as described in the deployment
// design note (§4); the precise absence/statelessness semantics of the final RC
// text should be reconciled against this one file when it lands. Everything
// mismatch-related (reject when a routing header contradicts the body) is
// implemented as specified.

const (
	// mcpProtocolVersion is the MCP revision this adapter speaks. MCP versions are
	// date-stamped; this is the 2026-07-28 RC the listener targets.
	mcpProtocolVersion = "2026-07-28"

	toolTip     = "kessa/tip"
	toolEnforce = "kessa/enforce"

	// The 2026-07-28 RC routing headers (§4). When present they must agree with
	// the JSON-RPC body; a contradiction is rejected before dispatch so a proxy or
	// gateway in front cannot route a body one way while labelling it another.
	hdrMCPMethod    = "Mcp-Method"
	hdrMCPName      = "Mcp-Name"
	hdrMCPSessionID = "Mcp-Session-Id"
)

// JSON-RPC 2.0 error codes (the reserved range from the spec).
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
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
}

// ---- MCP payload shapes ----------------------------------------------------

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      serverInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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

// mcpServer holds the adapter's only state: the sessions it has issued. The
// enforcement state lives entirely in px; this struct owns nothing about
// decisions.
type mcpServer struct {
	px       *Proxy
	mu       sync.Mutex
	sessions map[string]struct{}
}

// MCPHandler returns an http.Handler serving the MCP-native listener over the
// Streamable HTTP transport. It funnels into the same px this package's HTTP
// Handler uses; run both against one Proxy and they share one audit log and one
// set of invariants (Proxy guards its own concurrency, so two listeners are safe).
func MCPHandler(px *Proxy) http.Handler {
	return &mcpServer{px: px, sessions: make(map[string]struct{})}
}

func (s *mcpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet:
		// Streamable HTTP lets a server expose a GET SSE stream for messages it
		// initiates. The envelope model initiates none — every reply is the direct
		// response to a client POST — so per the spec a server without a stream
		// answers GET with 405.
		http.Error(w, "kessa MCP listener has no server-initiated event stream", http.StatusMethodNotAllowed)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *mcpServer) handlePost(w http.ResponseWriter, r *http.Request) {
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

	// JSON-RPC batches (a top-level array) are not supported: the 2026-07-28 RC's
	// batching story is not something to guess at, and the envelope surface has no
	// use for it. Reject explicitly rather than half-handle it.
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

	// Routing header (§4): if Mcp-Method is present it must name the same method
	// the body does. A mismatch is a transport-level routing fault, so it is
	// refused at the HTTP layer before any dispatch.
	if h := r.Header.Get(hdrMCPMethod); h != "" && h != req.Method {
		http.Error(w, fmt.Sprintf("%s %q does not match body method %q", hdrMCPMethod, h, req.Method), http.StatusBadRequest)
		return
	}

	// Session (§4): a client that carries an Mcp-Session-Id must present one this
	// server issued; an unrecognized id means the session is gone and the client
	// must re-initialize (404). Carrying none is allowed (stateless use).
	if sid := r.Header.Get(hdrMCPSessionID); sid != "" && !s.knownSession(sid) {
		http.Error(w, "unknown MCP session; re-initialize", http.StatusNotFound)
		return
	}

	s.dispatch(w, r, req)
}

func (s *mcpServer) dispatch(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "notifications/initialized":
		// A notification: acknowledge with no body.
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		writeRPCResult(w, req.ID, map[string]any{})
	case "tools/list":
		writeRPCResult(w, req.ID, s.toolsList())
	case "tools/call":
		s.handleToolsCall(w, r, req)
	default:
		if req.isNotification() {
			// Unknown notifications are ignored, not errored: a future MCP revision
			// may emit ones this adapter predates.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeRPCError(w, req.ID, rpcMethodNotFound, "unknown method: "+req.Method)
	}
}

func (s *mcpServer) handleInitialize(w http.ResponseWriter, req rpcRequest) {
	// Issue a session and hand it back in the response header; a well-behaved
	// client echoes it on subsequent requests. We answer with the protocol version
	// we speak rather than negotiating down: the envelope surface is stable across
	// the revisions this adapter targets, so there is nothing to negotiate.
	sid := s.newSession()
	w.Header().Set(hdrMCPSessionID, sid)
	writeRPCResult(w, req.ID, initializeResult{
		ProtocolVersion: mcpProtocolVersion,
		Capabilities:    map[string]any{"tools": map[string]any{}},
		ServerInfo:      serverInfo{Name: "kessa-proxy", Version: version.Version},
		Instructions: "Call kessa/tip to read the next audit slot, bind your proof-of-possession " +
			"(and human approval, if the action is consequential) to it, then call kessa/enforce " +
			"with a complete enforce.Request as the tool arguments.",
	})
}

func (s *mcpServer) handleToolsCall(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPCError(w, req.ID, rpcInvalidParams, "invalid tools/call params: "+err.Error())
		return
	}

	// Routing header (§4): if Mcp-Name is present it must name the same tool the
	// body's params do. Same reasoning as Mcp-Method — a labelled-vs-actual
	// mismatch is refused at the transport layer.
	if h := r.Header.Get(hdrMCPName); h != "" && h != p.Name {
		http.Error(w, fmt.Sprintf("%s %q does not match tool %q", hdrMCPName, h, p.Name), http.StatusBadRequest)
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

// ---- session handling ------------------------------------------------------

func (s *mcpServer) newSession() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	sid := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.sessions[sid] = struct{}{}
	s.mu.Unlock()
	return sid
}

func (s *mcpServer) knownSession(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[sid]
	return ok
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

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Result: result})
}

// writeRPCError writes a JSON-RPC error object. Per JSON-RPC over HTTP, this is a
// well-formed response and rides a 200; transport-level faults (bad routing
// header, unknown session, oversized body) are the ones that use HTTP status.
func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Error: &rpcError{Code: code, Message: msg}})
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
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
