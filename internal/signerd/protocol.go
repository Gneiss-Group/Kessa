// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package signerd is the on-device signing daemon and its client: the ssh-agent
// shape §2 settled on. A daemon (Server) holds one or more signer.Signer values
// and brokers Sign/Public over a local Unix domain socket; a client (Signer)
// dials that socket and satisfies signer.Signer itself, so a process like
// cmd/agent gets its key from the daemon without the private key ever crossing
// the socket. The key material stays wherever the held signer keeps it: in
// process memory for a software signer, or inside the Secure Enclave for an
// enclave signer, which the daemon holds without ever seeing the private key.
//
// The daemon is BACKEND-AGNOSTIC: it brokers whatever signer.Signer it is given.
// That is why this package is fully testable with software signers on every
// platform (Linux CI included) even though its production purpose is to front a
// hardware-backed key.
//
// Wire format: one newline-delimited JSON Request per line, one JSON Response
// back. Transport is a net.Listener/net.Conn, so a Windows named-pipe listener
// is a later drop-in without touching this protocol (§2's "defer Windows but stay
// ready" note). Licensed Apache-2.0: on-device key custody is part of the open
// mechanism (§2a), same tier as internal/signer.
package signerd

import (
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Wire operations.
const (
	OpList   = "list"   // no args; Response.DIDs lists the DIDs the daemon holds
	OpPublic = "public" // args: DID; Response.PubJWK is that key's public half
	OpSign   = "sign"   // args: DID, Data; Response.Sig is the signature over Data
)

// maxMessage caps a single wire message (F6-style): a delegation-sized payload is
// a few KB; 1 MiB is generous while refusing a crafted body that would stream
// unbounded into the decoder.
const maxMessage = 1 << 20

// Request is one client-to-daemon message.
type Request struct {
	Op   string    `json:"op"`
	DID  types.DID `json:"did,omitempty"`
	Data []byte    `json:"data,omitempty"` // sign input; base64 in JSON
}

// Response is one daemon-to-client message. OK reports success; on failure Error
// is set and the value fields are empty.
type Response struct {
	OK     bool        `json:"ok"`
	Error  string      `json:"error,omitempty"`
	Sig    []byte      `json:"sig,omitempty"`
	PubJWK *did.JWK    `json:"pubJwk,omitempty"`
	DIDs   []types.DID `json:"dids,omitempty"`
}
