// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
)

// The MCP listener is the network-reachable attacker surface: an MCP host points
// its server address straight at it, and everything before Proxy.Handle is
// parsing and guard code running on bytes nobody has authenticated yet. R5-02
// (Origin), R5-03 (a null "id") and R5-04 (clientCapabilities present but not an
// object) all lived in exactly this stretch, and all three were found by hand.
//
// The invariant this target searches against is the one those findings share:
// A SUCCESSFUL RESPONSE IS REACHABLE ONLY THROUGH THE COMPLETE GUARD SET. Each
// of those bugs was a guard that could be skipped, satisfied vacuously, or
// answered with a third state the code did not model, and each showed up as a
// request that got a result without having earned one.
//
// The oracle below re-derives the preconditions from the fuzz input rather than
// asking the handler what it decided. Where a guard IS the definition of its own
// precondition (originAllowed, hasJSONContentType) it is called directly, which
// is deliberate and not a tautology: the defect class is a guard that is not
// consulted, or consulted after the thing it guards, not a guard that computes
// the wrong answer in isolation. The _meta checks are written out longhand
// instead, because that is where the vacuous-check findings actually were.

var (
	fuzzProxyOnce sync.Once
	fuzzProxy     *Proxy
	fuzzProxyErr  error
)

// mcpFuzzProxy builds one proxy for the whole fuzzing process. Building it per
// iteration would put four key generations and a policy load in front of every
// exec and cut the rate by orders of magnitude, and it would buy nothing: no
// input the mutator can produce carries a verifiable delegation chain and a
// valid proof of possession, so nothing here reaches the append path and the
// proxy is immutable in practice.
func mcpFuzzProxy(t *testing.T) *Proxy {
	t.Helper()
	fuzzProxyOnce.Do(func() {
		var pol *policy.Policy
		pol, fuzzProxyErr = policy.Load(commercePol)
		if fuzzProxyErr != nil {
			return
		}
		var ep signer.Signer
		ep, fuzzProxyErr = signer.NewSoftwareSignerFromSeed(didProxy, seed32(seeds[didProxy]))
		if fuzzProxyErr != nil {
			return
		}
		fuzzProxy, fuzzProxyErr = NewProxy(Config{
			EnforcementPoint: ep,
			Policy:           pol,
			DIDs:             did.FileResolver{Root: didsRoot},
			Now:              func() time.Time { return fixedTime },
		})
	})
	if fuzzProxyErr != nil {
		t.Fatalf("building the fuzz proxy: %v", fuzzProxyErr)
	}
	return fuzzProxy
}

// FuzzMCPIngress drives the MCP listener with a request assembled from fuzzed
// parts: the JSON-RPC body, the three mirrored request-metadata headers, the
// content type, the Origin, and a flag byte that reaches the states a
// well-behaved client cannot produce (a repeated header, an omitted one, a
// non-POST method).
func FuzzMCPIngress(f *testing.F) {
	// Seeds are conformant requests first, so the mutator starts from bodies that
	// already pass every guard and has only to break one of them, then the
	// specific shapes the past findings used.
	meta := `"_meta":{"` + metaProtocolVersion + `":"` + mcpProtocolVersion + `","` + metaClientCapabilities + `":{}}`
	add := func(body, hdrProto, hdrMethod, hdrName, ct, origin string, flags uint8) {
		f.Add([]byte(body), hdrProto, hdrMethod, hdrName, ct, origin, flags)
	}
	add(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", 0)
	add(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+meta+`}}`,
		mcpProtocolVersion, "tools/list", "", "application/json", "", 0)
	add(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+toolTip+`","arguments":{},`+meta+`}}`,
		mcpProtocolVersion, "tools/call", toolTip, "application/json; charset=utf-8", "", 0)
	// A notification: no id, no response body.
	add(`{"jsonrpc":"2.0","method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", 0)
	// R5-03: an explicit null id is a third state, neither request nor notification.
	add(`{"jsonrpc":"2.0","id":null,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", 0)
	// R5-04: clientCapabilities present but null, which satisfies "required field"
	// while supplying nothing.
	add(`{"jsonrpc":"2.0","id":4,"method":"ping","params":{"_meta":{"`+metaProtocolVersion+`":"`+mcpProtocolVersion+`","`+metaClientCapabilities+`":null}}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", 0)
	// R5-02: a cross-origin caller, and the sandboxed-iframe "null" Origin.
	add(`{"jsonrpc":"2.0","id":5,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "https://evil.example", 0)
	add(`{"jsonrpc":"2.0","id":6,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "null", 0)
	// A batch, a bare array, and malformed JSON.
	add(`[{"jsonrpc":"2.0","id":7,"method":"ping"}]`, mcpProtocolVersion, "ping", "", "application/json", "", 0)
	add(`{`, mcpProtocolVersion, "ping", "", "application/json", "", 0)
	// The header/body split-brain: header names one method, body another.
	add(`{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", 0)
	// Repeated headers, omitted content type, and a non-POST method.
	add(`{"jsonrpc":"2.0","id":9,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", flagDupProto)
	add(`{"jsonrpc":"2.0","id":10,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "", "", flagNoContentType)
	add(`{"jsonrpc":"2.0","id":11,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "ping", "", "application/json", "", flagGET)
	// A Base64-sentinel header value.
	add(`{"jsonrpc":"2.0","id":12,"method":"ping","params":{`+meta+`}}`,
		mcpProtocolVersion, "=?base64?cGluZw==?=", "", "application/json", "", 0)

	f.Fuzz(func(t *testing.T, body []byte, hdrProto, hdrMethod, hdrName, ct, origin string, flags uint8) {
		px := mcpFuzzProxy(t)
		req := buildMCPRequest(body, hdrProto, hdrMethod, hdrName, ct, origin, flags)

		rec := httptest.NewRecorder()
		MCPHandler(px).ServeHTTP(rec, req)
		res := rec.Result()

		// 1. The listener answers with a status it defines. An unexpected code is
		//    a path that fell through a switch rather than refusing.
		switch res.StatusCode {
		case http.StatusOK, http.StatusAccepted, http.StatusBadRequest,
			http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed,
			http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType,
			http.StatusInternalServerError:
		default:
			t.Fatalf("unexpected status %d", res.StatusCode)
		}

		// 2. A 202 is the notification acknowledgement and carries no body. A
		//    response body under 202 would mean a request was treated as a
		//    notification and answered anyway.
		if res.StatusCode == http.StatusAccepted && rec.Body.Len() != 0 {
			t.Fatalf("202 carried a body: %q", rec.Body.String())
		}

		var resp rpcResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			// Not every refusal is JSON-RPC: the pre-dispatch guards answer with
			// http.Error, which is plain text by design. Only a 200 is required
			// to be a well-formed JSON-RPC message.
			if res.StatusCode == http.StatusOK && rec.Body.Len() > 0 {
				t.Fatalf("200 body is not a JSON-RPC message: %q", rec.Body.String())
			}
			return
		}

		hasResult := resp.Result != nil
		hasError := resp.Error != nil

		// 3. A JSON-RPC message carries exactly one of result or error, and says
		//    which version it speaks. Both at once, or neither, is a reply a
		//    conforming client cannot interpret.
		if rec.Body.Len() > 0 && resp.JSONRPC != "" {
			if hasResult && hasError {
				t.Fatalf("response carries both result and error: %q", rec.Body.String())
			}
			if resp.JSONRPC != "2.0" {
				t.Fatalf("response declares jsonrpc %q", resp.JSONRPC)
			}
		}

		if !hasResult {
			return
		}

		// 4. THE INVARIANT. A result was produced, so every precondition must
		//    have held. Each clause below is a guard that a past finding got
		//    past; a failure here names which one stopped being reachable.
		why := unearnedResult(req, body, flags)
		if why != "" {
			t.Fatalf("the listener produced a result for a request that should have been refused: %s\nbody: %q\nresponse: %q",
				why, body, rec.Body.String())
		}

		// 5. The reply is addressed to the request that asked. An id the caller
		//    did not send means one client can be answered with another's reply.
		var req2 rpcRequest
		if err := json.Unmarshal(bytes.TrimSpace(body), &req2); err == nil && len(req2.ID) > 0 {
			if !bytes.Equal(bytes.TrimSpace(resp.ID), bytes.TrimSpace(req2.ID)) {
				t.Fatalf("response id %q does not echo request id %q", resp.ID, req2.ID)
			}
		}
	})
}

// Flag bits reaching the request states a cooperating client cannot express.
const (
	flagDupProto uint8 = 1 << iota
	flagDupMethod
	flagDupOrigin
	flagNoContentType
	flagGET
	flagNoProtoHeader
	flagNoMethodHeader
	flagDelete
)

// buildMCPRequest assembles the request from the fuzzed parts. The handler is
// called directly rather than over a socket, so header values reach it verbatim:
// what the oracle inspects is exactly what the guards inspect.
func buildMCPRequest(body []byte, hdrProto, hdrMethod, hdrName, ct, origin string, flags uint8) *http.Request {
	method := http.MethodPost
	switch {
	case flags&flagGET != 0:
		method = http.MethodGet
	case flags&flagDelete != 0:
		method = http.MethodDelete
	}
	r := httptest.NewRequest(method, "/mcp", bytes.NewReader(body))
	if flags&flagNoContentType == 0 && ct != "" {
		r.Header.Set("Content-Type", ct)
	} else {
		r.Header.Del("Content-Type")
	}
	if flags&flagNoProtoHeader == 0 {
		r.Header.Add(hdrMCPProtocolVersion, hdrProto)
		if flags&flagDupProto != 0 {
			r.Header.Add(hdrMCPProtocolVersion, hdrProto)
		}
	}
	if flags&flagNoMethodHeader == 0 {
		r.Header.Add(hdrMCPMethod, hdrMethod)
		if flags&flagDupMethod != 0 {
			r.Header.Add(hdrMCPMethod, hdrMethod+"x")
		}
	}
	if hdrName != "" {
		r.Header.Add(hdrMCPName, hdrName)
	}
	if origin != "" {
		r.Header.Add("Origin", origin)
		if flags&flagDupOrigin != 0 {
			r.Header.Add("Origin", origin)
		}
	}
	return r
}

// unearnedResult reports why this request should not have produced a result, or
// "" if it legitimately earned one. It is the independent statement of the
// contract: every clause is a rule the listener documents, restated here so the
// fuzzer can find an input where the listener stops applying it.
func unearnedResult(r *http.Request, body []byte, flags uint8) string {
	if r.Method != http.MethodPost {
		return "the method was not POST"
	}
	if !originAllowed(r) {
		return "the Origin is not a loopback origin"
	}
	if !hasJSONContentType(r) {
		return "the Content-Type is not application/json"
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return "the body is a JSON-RPC batch"
	}

	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return "the body is not a JSON-RPC message"
	}
	if req.JSONRPC != "2.0" {
		return `the body does not declare jsonrpc "2.0"`
	}
	// An absent id is a notification, which gets a 202 and no result. A null id
	// is the third state R5-03 was filed for and must be refused outright.
	if len(req.ID) == 0 {
		return "the body carries no id, so it is a notification"
	}
	if bytes.Equal(bytes.TrimSpace(req.ID), []byte("null")) {
		return "the body carries a null id"
	}

	// The mirrored headers must each appear exactly once and agree with the body,
	// or an intermediary routing on the header acts on a value this server never
	// validated.
	hdrProto, protoPresent, protoDup := singleHeader(r, hdrMCPProtocolVersion)
	if !protoPresent || protoDup {
		return "the " + hdrMCPProtocolVersion + " header is missing or repeated"
	}
	hdrMethod, methodPresent, methodDup := singleHeader(r, hdrMCPMethod)
	if !methodPresent || methodDup {
		return "the " + hdrMCPMethod + " header is missing or repeated"
	}
	if hdrMethod != req.Method {
		return "the " + hdrMCPMethod + " header disagrees with the body method"
	}

	// params._meta, written out rather than delegated: the vacuous-check findings
	// were here, so the oracle states the requirement in its own words.
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return "params did not decode"
		}
	}
	rawVersion, ok := params.Meta[metaProtocolVersion]
	if !ok {
		return "params._meta carries no " + metaProtocolVersion
	}
	var bodyVersion string
	if err := json.Unmarshal(rawVersion, &bodyVersion); err != nil || bodyVersion == "" {
		return metaProtocolVersion + " is not a non-empty string"
	}
	rawCaps, ok := params.Meta[metaClientCapabilities]
	if !ok {
		return "params._meta carries no " + metaClientCapabilities
	}
	var caps map[string]json.RawMessage
	if err := json.Unmarshal(rawCaps, &caps); err != nil || caps == nil {
		return metaClientCapabilities + " is not a JSON object"
	}
	if hdrProto != bodyVersion {
		return "the " + hdrMCPProtocolVersion + " header disagrees with " + metaProtocolVersion
	}
	if bodyVersion != mcpProtocolVersion {
		return "the protocol version is not " + mcpProtocolVersion
	}

	// Only the methods this revision implements can produce a result.
	switch req.Method {
	case "ping", "tools/list", "tools/call":
	default:
		return "the method is not one this listener implements"
	}
	return ""
}
