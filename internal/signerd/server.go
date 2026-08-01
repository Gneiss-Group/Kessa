// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package signerd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Server holds a set of signers keyed by DID and brokers Sign/Public over a
// net.Listener. It is safe for concurrent connections. Two independent gates
// protect it: the socket's own filesystem permissions (set by the caller that
// creates the listener — 0700 dir + 0600 socket) and a per-connection peer-uid
// check enforced here, so a connection from any uid other than the daemon owner
// is refused before a single request is read.
type Server struct {
	mu       sync.RWMutex
	signers  map[types.DID]signer.Signer
	ownerUID uint32
	// Logf, if set, records refused connections and per-connection errors. Nil is
	// silent. It never logs key material or signed data.
	Logf func(format string, args ...any)
}

// New builds a Server over signers, binding the peer-uid gate to the current
// process owner. Every held signer is brokered; nil or empty is a legal (inert)
// daemon.
func New(signers map[types.DID]signer.Signer) *Server {
	m := make(map[types.DID]signer.Signer, len(signers))
	for d, s := range signers {
		m[d] = s
	}
	return &Server{signers: m, ownerUID: uint32(os.Getuid())}
}

// Add registers (or replaces) a signer after construction, e.g. as keys are
// enrolled. Safe to call while Serve is running.
func (s *Server) Add(sg signer.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signers[sg.DID()] = sg
}

// Serve accepts connections until l is closed (Accept then returns an error,
// which Serve returns). Each connection is handled on its own goroutine.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// handle enforces the peer-uid gate, then serves newline-delimited requests until
// the client closes the connection.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	uid, err := peerUID(conn)
	if err != nil {
		// Fail closed: if we cannot establish the peer's identity we do not serve.
		s.logf("signerd: refusing connection, peer-cred check failed: %v", err)
		_ = writeResponse(conn, Response{Error: "peer credential check failed"})
		return
	}
	if uid != s.ownerUID {
		s.logf("signerd: refusing connection from uid %d (owner is %d)", uid, s.ownerUID)
		_ = writeResponse(conn, Response{Error: "unauthorized: connection is not from the daemon owner"})
		return
	}

	r := bufio.NewReader(io.LimitReader(conn, maxMessage))
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if werr := writeResponse(conn, s.dispatch(line)); werr != nil {
				return
			}
		}
		if err != nil {
			// io.EOF is the normal end of a one-shot client; anything else ends the
			// connection too. A LimitReader hitting the cap surfaces as EOF here.
			return
		}
	}
}

// dispatch decodes and services one request. It never returns an error to the
// caller; a failure becomes a Response with Error set, so the client always gets
// a structured reply.
func (s *Server) dispatch(line []byte) Response {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return Response{Error: "malformed request: " + err.Error()}
	}
	switch req.Op {
	case OpList:
		return Response{OK: true, DIDs: s.list()}
	case OpPublic:
		sg, ok := s.lookup(req.DID)
		if !ok {
			return Response{Error: notHeld(req.DID)}
		}
		jwk, err := publicJWK(sg)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true, PubJWK: jwk}
	case OpSign:
		sg, ok := s.lookup(req.DID)
		if !ok {
			return Response{Error: notHeld(req.DID)}
		}
		sig, err := sg.Sign(req.Data)
		if err != nil {
			return Response{Error: "sign failed: " + err.Error()}
		}
		return Response{OK: true, Sig: sig}
	default:
		return Response{Error: "unknown op: " + req.Op}
	}
}

func (s *Server) lookup(d types.DID) (signer.Signer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sg, ok := s.signers[d]
	return sg, ok
}

func (s *Server) list() []types.DID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.DID, 0, len(s.signers))
	for d := range s.signers {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func notHeld(d types.DID) string {
	return fmt.Sprintf("daemon holds no key for %q", d)
}

// publicJWK projects a signer's public key into the wire JWK, rejecting an
// unsupported key type rather than letting did.PublicKeyToJWK panic across the
// socket boundary.
func publicJWK(sg signer.Signer) (*did.JWK, error) {
	pub := sg.Public()
	switch pub.(type) {
	case nil:
		return nil, errors.New("signer has no public key")
	default:
		// did.PublicKeyToJWK handles Ed25519 and P-256; guard the panic path.
		jwk, err := safeJWK(pub)
		if err != nil {
			return nil, err
		}
		return jwk, nil
	}
}

func safeJWK(pub any) (jwk *did.JWK, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unsupported public key type: %v", r)
		}
	}()
	return did.PublicKeyToJWK(pub), nil
}

func writeResponse(conn net.Conn, resp Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		// Last-ditch: a response we cannot marshal becomes a plain error line.
		b = []byte(`{"ok":false,"error":"internal: response marshal failed"}`)
	}
	b = append(b, '\n')
	_, werr := conn.Write(b)
	return werr
}
