// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package signerd

import (
	"errors"
	"net"
)

// peerUID has no implementation on this platform, so the daemon fails closed: it
// cannot establish the peer's identity and therefore refuses every connection.
// The daemon targets macOS and Linux; a Windows named-pipe peer-cred equivalent
// slots in here when Windows support is built (§2 defers it).
func peerUID(conn net.Conn) (uint32, error) {
	return 0, errors.New("signerd: peer credential check is unsupported on this platform")
}
