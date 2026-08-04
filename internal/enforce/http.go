// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// The localhost HTTP transport. It is a thin shell over Proxy.Handle: the wire
// message IS enforce.Request and the reply IS enforce.Result, so the agent and
// the proxy share one protocol with nothing to keep in sync. This is a mock
// transport (spec §1): plain JSON, no mTLS, no service mesh. All the trust
// logic is in Handle; this file only moves bytes.

// maxRequestBody caps an inbound /enforce body (F6). A delegation chain with a
// handful of hops and a couple of signatures is a few KB; 1 MiB is generous while
// still refusing a crafted body that would otherwise stream unbounded into the
// JSON decoder on the evaluator's machine.
const maxRequestBody = 1 << 20

// Handler returns an http.Handler wrapping px:
//
//	POST /enforce   body = Request JSON. 200 + Result on a decision (allow OR
//	                deny), 422 if the request is unattributable (nothing logged),
//	                400 on a malformed body, 413 if the body exceeds the cap.
//	GET  /tip       the position the next entry will occupy {seq, prevHash}, so a
//	                caller can bind its PoP/approval to that slot (F4).
//	GET  /export    the accumulated signed audit export.
//
// This shell holds NO lock (R2-03/R2-04). It used to wrap every call in a bare
// package-level mutex with no deferred unlock, which was wrong in both directions
// at once: a panic escaping Handle, which net/http recovers per connection, so
// the process survived, left the mutex held forever and wedged every subsequent
// /enforce, /tip and /export, while the fact that the lock lived here at all meant
// Proxy itself was unsynchronized for any other caller. Proxy now guards its own
// invariants (see Proxy.mu), which is both panic-safe and correct for the
// in-process callers this transport knows nothing about.
func Handler(px *Proxy) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /enforce", func(w http.ResponseWriter, r *http.Request) {
		// This endpoint is the one that MUTATES: it can append to the audit log.
		// It also needs no custom header, which is what made it reachable by a
		// plain cross-origin form-style POST with no CORS preflight. Both ingress
		// guards run before the body is read.
		if !checkIngress(w, r, true) {
			return
		}
		// Cap the body before decoding. MaxBytesReader makes the decoder return an
		// error (rather than allocate unboundedly) once the cap is exceeded.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		res, err := px.Handle(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("GET /tip", func(w http.ResponseWriter, r *http.Request) {
		if !checkIngress(w, r, false) {
			return
		}
		tip := px.Tip()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tip)
	})

	// The read endpoints are guarded too, and /export especially. CORS stops a
	// foreign page READING an ordinary cross-origin response, but under DNS
	// rebinding the page is same-origin and reads it fine — and this response is
	// the entire signed audit history.
	mux.HandleFunc("GET /export", func(w http.ResponseWriter, r *http.Request) {
		if !checkIngress(w, r, false) {
			return
		}
		exp, err := px.Export()
		var data []byte
		if err == nil {
			data, err = exp.Marshal()
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	return mux
}

// ErrRejected is returned by Submit when the proxy rejected a request as
// unattributable (HTTP 422): the request never became an audit entry.
type ErrRejected struct{ Reason string }

func (e *ErrRejected) Error() string { return "proxy rejected request: " + e.Reason }

// Submit POSTs an action attempt to a proxy's /enforce endpoint and returns the
// decision. A 422 (unattributable request) is surfaced as *ErrRejected; other
// non-200s as a plain error. This is the agent side of the same one wire
// protocol Handler serves.
func Submit(client *http.Client, baseURL string, req Request) (*Result, error) {
	if client == nil {
		client = http.DefaultClient
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("enforce: marshal request: %w", err)
	}
	resp, err := client.Post(baseURL+"/enforce", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("enforce: POST %s/enforce: %w", baseURL, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		var res Result
		if err := json.Unmarshal(respBody, &res); err != nil {
			return nil, fmt.Errorf("enforce: decode result: %w", err)
		}
		return &res, nil
	case http.StatusUnprocessableEntity:
		return nil, &ErrRejected{Reason: trimmed(respBody)}
	default:
		return nil, fmt.Errorf("enforce: proxy returned %d: %s", resp.StatusCode, trimmed(respBody))
	}
}

// FetchTip GETs the proxy's next-entry position so the caller can bind its
// proof-of-possession and approval to that exact chain slot (F4) before it POSTs
// the enforce Request.
func FetchTip(client *http.Client, baseURL string) (Tip, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(baseURL + "/tip")
	if err != nil {
		return Tip{}, fmt.Errorf("enforce: GET %s/tip: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Tip{}, fmt.Errorf("enforce: /tip returned %d: %s", resp.StatusCode, trimmed(body))
	}
	var tip Tip
	if err := json.NewDecoder(resp.Body).Decode(&tip); err != nil {
		return Tip{}, fmt.Errorf("enforce: decode tip: %w", err)
	}
	return tip, nil
}

func trimmed(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
