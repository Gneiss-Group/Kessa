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
	cfgPath := fs.String("config", "", "JSON configuration file. When given it supplies the whole configuration, and any flag this schema covers is refused rather than merged: see cmd/issuer/config.go and docs/configuration.md")
	checkOnly := fs.Bool("check-config", false, "validate the configuration and exit without binding the socket or brokering anything, reporting which depth the check reached")
	var attest didList
	fs.Var(&attest, "attestation-key", "DID from --keystore to broker as an ATTESTATION key, an enforcement point's own audit-signing key, rather than a routine PoP key (repeatable). This is the key `kessa-proxy serve --signer-sock` asks for")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// The config file and the command line are mutually exclusive, exactly as for
	// `kessa-proxy serve`: no precedence relation, because the two sources are
	// never both allowed to speak. To run without the file, do not pass --config.
	if *cfgPath != "" {
		if bad := daemonConflictingFlags(fs); len(bad) > 0 {
			fmt.Fprintf(stderr, "kessa-issuer: --config supplies the whole configuration, so these flags cannot also be given: --%s\n",
				strings.Join(bad, ", --"))
			fmt.Fprintln(stderr, "  Put their values in the config file, or drop --config to configure entirely by flag.")
			return exitUsage
		}
		cfg, err := loadDaemonConfig(*cfgPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
			return exitUsage
		}
		// Assigned unconditionally, so a field the file omits overwrites the flag's
		// default rather than inheriting it. That is what makes absence mean "off"
		// rather than "whatever the flag would have done", and it is why `sock` is
		// required: its flag default is environment-derived, so inheriting it would
		// put the socket wherever the invoking shell pointed.
		*ksPath = cfg.Keystore
		*mapPath = cfg.Mapping
		*sock = cfg.Sock
		attest = cfg.AttestationKeys
	} else if *checkOnly {
		fmt.Fprintln(stderr, "kessa-issuer: --check-config needs a --config file to check")
		return exitUsage
	}

	if *ksPath == "" && *mapPath == "" {
		fmt.Fprintln(stderr, "kessa-issuer: one of --keystore or --mapping is required")
		return exitUsage
	}
	if len(attest) > 0 && *ksPath == "" {
		fmt.Fprintln(stderr, "kessa-issuer: --attestation-key names a DID from --keystore, which was not given")
		return exitUsage
	}

	// Software keystore keys are ROUTINE-only (PoP) unless --attestation-key names
	// one, which reclassifies it as the enforcement point's own audit-signing key.
	// Both are software-permitted, and the distinction is not a security boundary:
	// it is so the daemon's key table says which key attests a log and which proves
	// possession, rather than presenting one undifferentiated pile. Enrolled keys
	// from the mapping are APPROVAL-capable and must be hardware-backed;
	// signerd.NewKeys refuses an approval key that is not (R4-02), and
	// loadEnrolledKeys refuses to even offer a software-enrolled key for that role.
	var keys []signerd.HeldKey
	if *ksPath != "" {
		ks, err := loadJSON[Keystore](*ksPath)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
			return exitUsage
		}
		kk, err := keystoreKeys(ks, attest)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
			return exitUsage
		}
		keys = append(keys, kk...)
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

	// Build and validate the key set BEFORE binding the socket. NewKeys is the
	// gate that refuses a software approval key (R4-02) and an unknown policy, and
	// binding first meant a refused key set had already created a socket on a path
	// another daemon could be told to use. Closing the listener unlinks it, so the
	// old order was not leaking a file, but it did perform the side effect before
	// the check that can reject it, which is the ordering the house rules call out.
	srv, err := signerd.NewKeys(keys)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}

	// --check-config stops HERE, immediately before listen, which is the first
	// thing this function creates. Everything above has already run unchanged, so
	// the check is a prefix of the real start rather than a second opinion about
	// it: a standalone validator drifts, and its failure mode is reporting clean
	// against a daemon that then refuses to start.
	//
	// NewKeys above is the gate worth reaching. It is where a software key offered
	// for the APPROVAL role is refused (R4-02) and where an undefined policy is
	// rejected, so a config whose mapping would break that is caught here rather
	// than at the next restart.
	if *checkOnly {
		reportDaemonCheck(stdout, *cfgPath, keys)
		return exitOK
	}

	l, err := listen(*sock, stderr)
	if err != nil {
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
	for _, k := range heldKeysSorted(keys) {
		fmt.Fprintf(stdout, "  %-11s %s\n", k.Policy, k.Signer.DID())
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
// key is loaded by tag, and a key recorded as software is REFUSED here (R4-02):
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

// keystoreKeys turns the mock keystore into brokerable keys, classifying each as
// ROUTINE unless attest names it, in which case it becomes ATTESTATION: an
// enforcement point's own audit-signing key, which is what `kessa-proxy serve
// --signer-sock` asks the daemon for.
//
// Every named DID is checked against the keystore BEFORE any signer is
// materialized. Skipping that check would not fail: it would start a daemon that
// brokers the intended key as ROUTINE, so the flag would appear accepted and
// change nothing, which is the shape of a check that passes by not testing
// anything.
func keystoreKeys(ks Keystore, attest didList) ([]signerd.HeldKey, error) {
	for _, d := range attest {
		if _, ok := ks[d]; !ok {
			return nil, fmt.Errorf("--attestation-key %q is not in the keystore", d)
		}
	}
	attested := attest.set()
	principals := ks.Principals()
	keys := make([]signerd.HeldKey, 0, len(principals))
	for _, d := range principals {
		sg, err := ks.Signer(d)
		if err != nil {
			return nil, err
		}
		policy := signerd.Routine
		if attested[d] {
			policy = signerd.Attestation
		}
		keys = append(keys, signerd.HeldKey{Signer: sg, Policy: policy})
	}
	return keys, nil
}

// heldKeysSorted orders the brokered keys by DID for a stable listing. It carries
// the policy through rather than reducing to DIDs, because what an operator needs
// from this table is which key does what: an attestation key and a routine key
// look identical once the policy is dropped.
func heldKeysSorted(keys []signerd.HeldKey) []signerd.HeldKey {
	out := make([]signerd.HeldKey, len(keys))
	copy(out, keys)
	sort.Slice(out, func(i, j int) bool { return out[i].Signer.DID() < out[j].Signer.DID() })
	return out
}

// didList collects a repeatable DID-valued flag.
type didList []types.DID

func (l *didList) String() string {
	out := make([]string, 0, len(*l))
	for _, d := range *l {
		out = append(out, string(d))
	}
	return strings.Join(out, ",")
}

func (l *didList) Set(v string) error {
	if v == "" {
		return errors.New("empty DID")
	}
	*l = append(*l, types.DID(v))
	return nil
}

func (l *didList) set() map[types.DID]bool {
	m := make(map[types.DID]bool, len(*l))
	for _, d := range *l {
		m[d] = true
	}
	return m
}

func isClosedListener(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
