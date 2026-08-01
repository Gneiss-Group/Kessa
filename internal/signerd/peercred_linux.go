// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signerd

import (
	"errors"
	"net"
	"syscall"
)

// peerUID returns the uid of the process on the other end of a Unix socket, via
// SO_PEERCRED. Stdlib-only; no cgo.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("signerd: connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			opErr = e
			return
		}
		uid = ucred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, opErr
}
