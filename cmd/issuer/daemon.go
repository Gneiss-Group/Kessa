// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/enroll"
	"github.com/Gneiss-Group/Kessa/internal/signer/enclave"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// cmdDaemon runs the on-device signing daemon: it holds the device's key material
// and brokers signatures over a local Unix socket (the ssh-agent shape, §2), so a
// process like kessa-agent gets its key from here without the private key ever
// leaving the daemon.
//
// For now the brokered keys come from a keystore of software signers, which makes
// the daemon runnable and testable on every platform. The hardware path (an
// Enclave-held key, internal/signer/enclave) is the same signer.Signer seam and
// slots in behind this command when enrollment (B4) mints one.
func cmdDaemon(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ksPath := fs.String("keystore", "", "keystore JSON (DID -> hex seed): software keys brokered as ROUTINE (PoP) keys")
	mapPath := fs.String("mapping", "", "enrollment mapping: load enrolled Secure Enclave keys by tag as APPROVAL-capable keys")
	sock := fs.String("sock", defaultSockPath(), "Unix socket to listen on")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *ksPath == "" && *mapPath == "" {
		fmt.Fprintln(stderr, "kessa-issuer: one of --keystore or --mapping is required")
		return exitUsage
	}

	// Software keystore keys are ROUTINE-only (PoP). Enrolled keys from the mapping
	// are APPROVAL-capable and must be hardware-backed; signerd.NewKeys refuses an
	// approval key that is not (R4-02), and loadEnrolledKeys refuses to even offer a
	// software-enrolled key for that role.
	var keys []signerd.HeldKey
	if *ksPath != "" {
		ks, err := loadJSON[Keystore](*ksPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
			return exitUsage
		}
		for d := range ks {
			sg, err := ks.Signer(d)
			if err != nil {
				fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
				return exitUsage
			}
			keys = append(keys, signerd.HeldKey{Signer: sg, Policy: signerd.Routine})
		}
	}
	if *mapPath != "" {
		hk, err := loadEnrolledKeys(*mapPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
			return exitUsage
		}
		keys = append(keys, hk...)
	}
	if len(keys) == 0 {
		fmt.Fprintln(stderr, "kessa-issuer: no keys to broker")
		return exitUsage
	}

	l, err := listen(*sock, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}

	srv, err := signerd.NewKeys(keys)
	if err != nil {
		_ = l.Close()
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	srv.Logf = func(format string, a ...any) { fmt.Fprintf(stderr, "kessa-issuer: "+format+"\n", a...) }

	// Clean shutdown: close the listener (which unblocks Serve) and remove the
	// socket file so the next start is not tripped by a stale path.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		_ = l.Close()
	}()

	fmt.Fprintf(stdout, "kessa-issuer daemon: brokering %d key(s) on %s\n", len(keys), *sock)
	for _, d := range heldDIDs(keys) {
		fmt.Fprintf(stdout, "  %s\n", d)
	}

	serveErr := srv.Serve(l)
	_ = os.Remove(*sock)
	// A closed listener (our shutdown path) is a clean exit, not a failure.
	if serveErr != nil && !isClosedListener(serveErr) {
		fmt.Fprintf(stderr, "kessa-issuer: serve: %v\n", serveErr)
		return exitUsage
	}
	return exitOK
}

// listen prepares the socket: it creates the parent directory 0700, refuses to
// start if a live daemon already owns the path, clears a stale socket otherwise,
// binds, and tightens the socket to 0600. The 0700 dir + 0600 socket are the
// filesystem half of the daemon's access control; the peer-uid check is the other.
func listen(sock string, stderr io.Writer) (net.Listener, error) {
	dir := filepath.Dir(sock)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir %q: %w", dir, err)
	}
	// Belt-and-suspenders: enforce 0700 even if the dir pre-existed with looser bits.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure socket dir %q: %w", dir, err)
	}
	if _, err := os.Stat(sock); err == nil {
		if c, derr := net.DialTimeout("unix", sock, time.Second); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("a daemon is already listening on %s", sock)
		}
		// Present but not answering: a stale socket from a previous run.
		if err := os.Remove(sock); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", sock, err)
		}
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", sock, err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("secure socket %q: %w", sock, err)
	}
	return l, nil
}

// defaultSockPath is $XDG_RUNTIME_DIR/kessa/issuer.sock when that is set,
// otherwise $HOME/.kessa/issuer.sock. Both live under a 0700 directory.
func defaultSockPath() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "kessa", "issuer.sock")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".kessa", "issuer.sock")
}

// loadEnrolledKeys reads the enrollment mapping and loads each non-revoked
// enrolled key as an APPROVAL-capable key. Enrolled keys are the employee/device
// keys that issue and approve, so they must be hardware-backed: a Secure Enclave
// key is loaded by tag, and a key recorded as software is REFUSED here (R4-02) —
// the human-approval control cannot rest on a software key. Use --keystore for a
// non-production routine-only daemon.
func loadEnrolledKeys(mapPath string) ([]signerd.HeldKey, error) {
	m, err := enroll.LoadMapping(mapPath)
	if err != nil {
		return nil, err
	}
	var out []signerd.HeldKey
	for _, id := range m.Identities() {
		for _, c := range m.Employees[id].Credentials {
			if c.Revoked {
				continue
			}
			switch c.KeyBackend {
			case enroll.BackendSecureEnclave:
				sg, err := enclave.Load(c.DID, []byte(c.KeyTag))
				if err != nil {
					return nil, fmt.Errorf("load enrolled key %q (tag %q): %w", c.DID, c.KeyTag, err)
				}
				out = append(out, signerd.HeldKey{Signer: sg, Policy: signerd.Approval})
			case enroll.BackendSoftware:
				return nil, fmt.Errorf("refusing to broker enrolled approval key %q: it was enrolled as a SOFTWARE key "+
					"(--software-key), which cannot back the human approval/issuance control; re-enroll on hardware, "+
					"or run a non-production daemon from --keystore instead", c.DID)
			default:
				return nil, fmt.Errorf("enrolled key %q has unknown backend %q", c.DID, c.KeyBackend)
			}
		}
	}
	return out, nil
}

func heldDIDs(keys []signerd.HeldKey) []types.DID {
	out := make([]types.DID, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Signer.DID())
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isClosedListener(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
