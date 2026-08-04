// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package signerd

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// xucred mirrors <sys/ucred.h>: u_int cr_version; uid_t cr_uid; short cr_ngroups;
// gid_t cr_groups[NGROUPS] (NGROUPS = 16). Only cr_uid is read.
type xucred struct {
	version uint32
	uid     uint32
	ngroups int16
	groups  [16]uint32
}

const (
	solLocal      = 0     // SOL_LOCAL
	localPeercred = 0x001 // LOCAL_PEERCRED
)

// peerUID returns the uid of the process on the other end of a Unix socket via
// getsockopt(LOCAL_PEERCRED). Stdlib-only (raw getsockopt); no cgo: confirmed
// working on darwin/arm64. errno != 0 (e.g. an unconnected socket) is surfaced as
// an error, so the caller fails closed rather than trusting a zero uid.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("signerd: connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred xucred
	size := uint32(unsafe.Sizeof(cred))
	var opErr syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(solLocal), uintptr(localPeercred),
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
		opErr = e
	}); err != nil {
		return 0, err
	}
	if opErr != 0 {
		return 0, opErr
	}
	return cred.uid, nil
}
