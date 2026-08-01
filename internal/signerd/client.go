// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package signerd

import (
	"bufio"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// dialTimeout bounds how long a client waits to reach the daemon; a missing or
// wedged daemon should fail fast, not hang the caller.
const dialTimeout = 5 * time.Second

// Signer is a signer.Signer whose operations are brokered by a daemon over a Unix
// socket. The private key never reaches this process; Sign round-trips to the
// daemon. It caches the public key (fetched at Dial) so Public() is local and
// cheap. One request opens one short-lived connection, so a Signer is safe for
// concurrent use.
type Signer struct {
	sockPath string
	did      types.DID
	pub      crypto.PublicKey
}

var _ signer.Signer = (*Signer)(nil)

// Dial connects to the daemon at sockPath, confirms it holds a key for d, and
// caches that key's public half. It fails fast if the daemon is unreachable or
// does not hold the DID, so a caller never gets a Signer that cannot sign.
func Dial(sockPath string, d types.DID) (*Signer, error) {
	s := &Signer{sockPath: sockPath, did: d}
	resp, err := s.roundtrip(Request{Op: OpPublic, DID: d})
	if err != nil {
		return nil, err
	}
	if resp.PubJWK == nil {
		return nil, fmt.Errorf("signerd: daemon returned no public key for %q", d)
	}
	pub, err := resp.PubJWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("signerd: parse public key for %q: %w", d, err)
	}
	s.pub = pub
	return s, nil
}

// Sign brokers the signature through the daemon. The bytes signed and the
// algorithm are the held signer's; this side never sees the key.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	resp, err := s.roundtrip(Request{Op: OpSign, DID: s.did, Data: data})
	if err != nil {
		return nil, err
	}
	if len(resp.Sig) == 0 {
		return nil, errors.New("signerd: daemon returned an empty signature")
	}
	return resp.Sig, nil
}

// Public returns the cached public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// DID returns the identifier this signer speaks for.
func (s *Signer) DID() types.DID { return s.did }

// List returns the DIDs a daemon at sockPath currently holds. It is a
// package-level helper (not part of signer.Signer) for tooling and diagnostics.
func List(sockPath string) ([]types.DID, error) {
	resp, err := roundtrip(sockPath, Request{Op: OpList})
	if err != nil {
		return nil, err
	}
	return resp.DIDs, nil
}

func (s *Signer) roundtrip(req Request) (*Response, error) {
	return roundtrip(s.sockPath, req)
}

// roundtrip opens a short-lived connection, sends one request, reads one
// response, and surfaces a daemon-side Error as a Go error.
func roundtrip(sockPath string, req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("signerd: dial %q: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("signerd: marshal request: %w", err)
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
		return nil, fmt.Errorf("signerd: write request: %w", err)
	}

	r := bufio.NewReader(io.LimitReader(conn, maxMessage))
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("signerd: read response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("signerd: decode response: %w", err)
	}
	if !resp.OK {
		if resp.Error != "" {
			return nil, errors.New("signerd: " + resp.Error)
		}
		return nil, errors.New("signerd: request failed")
	}
	return &resp, nil
}
