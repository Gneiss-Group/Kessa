// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package signerd

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// startDaemon runs a Server over a temp Unix socket brokering the given signers,
// and returns the socket path. It tears down on test cleanup.
func startDaemon(t *testing.T, signers ...signer.Signer) string {
	t.Helper()
	m := make(map[types.DID]signer.Signer)
	for _, s := range signers {
		m[s.DID()] = s
	}
	// Unix socket paths are length-capped (~104 bytes on macOS), and t.TempDir()
	// under /var/folders is too long, so use a short /tmp-rooted dir.
	dir, err := os.MkdirTemp("/tmp", "ks")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(m)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return sock
}

func softwareSigner(t *testing.T, d string, seed byte) signer.Signer {
	t.Helper()
	s := make([]byte, 32)
	for i := range s {
		s[i] = seed
	}
	sg, err := signer.NewSoftwareSignerFromSeed(types.DID(d), s)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return sg
}

// The core loop: a client dials the daemon, signs through it, and the signature
// verifies under the held key's public half, with the private key never leaving
// the daemon.
func TestDaemon_SignBrokered(t *testing.T) {
	held := softwareSigner(t, "did:web:localhost:agents:worker", 0x33)
	sock := startDaemon(t, held)

	cl, err := Dial(sock, held.DID())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if !signer.KeysEqual(cl.Public(), held.Public()) {
		t.Fatal("client public key differs from the held key")
	}
	if cl.DID() != held.DID() {
		t.Fatalf("client DID = %q, want %q", cl.DID(), held.DID())
	}

	msg := []byte("proof-of-possession input")
	sig, err := cl.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !signer.Verify(held.Public(), msg, sig) {
		t.Fatal("brokered signature must verify under the held key")
	}
}

// The client signer is a drop-in signer.Signer, so it flows through the exact PoP
// path cmd/agent uses: the whole point of the seam.
func TestDaemon_ClientSatisfiesSignerSeam(t *testing.T) {
	held := softwareSigner(t, "did:web:localhost:agents:worker", 0x44)
	sock := startDaemon(t, held)
	cl, err := Dial(sock, held.DID())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	var s signer.Signer = cl // compile-time and behavioral: it IS a signer.Signer
	msg := []byte("seam check")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign via seam: %v", err)
	}
	if !signer.Verify(s.Public(), msg, sig) {
		t.Fatal("signature via the seam must verify")
	}
}

func TestDaemon_List(t *testing.T) {
	a := softwareSigner(t, "did:web:localhost:orgs:acme", 0x11)
	w := softwareSigner(t, "did:web:localhost:agents:worker", 0x33)
	sock := startDaemon(t, a, w)

	dids, err := List(sock)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(dids) != 2 {
		t.Fatalf("List returned %d DIDs, want 2: %v", len(dids), dids)
	}
	// list() sorts ascending, so "did:web:localhost:agents:worker" (a...) precedes
	// "did:web:localhost:orgs:acme" (o...).
	if dids[0] != w.DID() || dids[1] != a.DID() {
		t.Fatalf("unexpected DIDs (want [worker, acme]): %v", dids)
	}
}

func TestDaemon_UnknownDID(t *testing.T) {
	sock := startDaemon(t, softwareSigner(t, "did:web:localhost:agents:worker", 0x33))
	if _, err := Dial(sock, "did:web:localhost:agents:ghost"); err == nil {
		t.Fatal("Dial for a DID the daemon does not hold must fail")
	}
}

func TestDaemon_PeerUIDIsOwner(t *testing.T) {
	// The in-process client runs as the same uid as the daemon, so the peer-uid
	// gate must ADMIT it: a successful Sign proves the gate passed. (Rejection of a
	// different uid cannot be exercised from a single-uid test process; the gate
	// logic itself is small and reviewed, and fails closed on any peerUID error.)
	held := softwareSigner(t, "did:web:localhost:agents:worker", 0x33)
	sock := startDaemon(t, held)

	cl, err := Dial(sock, held.DID())
	if err != nil {
		t.Fatalf("Dial (same-uid must be admitted): %v", err)
	}
	if _, err := cl.Sign([]byte("x")); err != nil {
		t.Fatalf("Sign (same-uid must be admitted): %v", err)
	}
}

func TestDaemon_MissingSocket(t *testing.T) {
	if _, err := Dial(filepath.Join(t.TempDir(), "nope.sock"), "did:x"); err == nil {
		t.Fatal("Dial to a nonexistent socket must fail fast")
	}
}

// hwSigner wraps a software signer but reports hardware backing, standing in for
// an enclave signer so the R4-02 policy check can be exercised without a real
// Secure Enclave.
type hwSigner struct{ signer.Signer }

func (hwSigner) Hardware() bool { return true }

// TestNewKeys_RefusesSoftwareApprovalKey is the R4-02 regression: an
// approval-capable key that is not hardware-backed must be refused at
// construction, so the human-approval control can never silently rest on a
// software key. Routine software keys and hardware-backed approval keys are fine.
func TestNewKeys_RefusesSoftwareApprovalKey(t *testing.T) {
	soft := softwareSigner(t, "did:web:localhost:employees:alice", 0x33)

	// Software + Approval: refused.
	if _, err := NewKeys([]HeldKey{{Signer: soft, Policy: Approval}}); err == nil {
		t.Fatal("a software approval key must be refused")
	}
	// Software + Routine: fine (PoP is bound to action+slot by the proxy).
	if _, err := NewKeys([]HeldKey{{Signer: soft, Policy: Routine}}); err != nil {
		t.Fatalf("a software routine key must be accepted: %v", err)
	}
	// Hardware-backed + Approval: fine.
	if _, err := NewKeys([]HeldKey{{Signer: hwSigner{soft}, Policy: Approval}}); err != nil {
		t.Fatalf("a hardware-backed approval key must be accepted: %v", err)
	}
	// A hardware-backed approval key is brokered end to end like any other.
	sock := startDaemonKeys(t, HeldKey{Signer: hwSigner{soft}, Policy: Approval})
	cl, err := Dial(sock, soft.DID())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := cl.Sign([]byte("approval bytes")); err != nil {
		t.Fatalf("Sign through a hardware approval key: %v", err)
	}
}

// startDaemonKeys is startDaemon's policy-aware sibling.
func startDaemonKeys(t *testing.T, keys ...HeldKey) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ks")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := NewKeys(keys)
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return sock
}

// TestNewKeys_AttestationPolicy pins what the third policy does and, just as
// importantly, what it does not. An attestation key is an enforcement point's own
// audit-signing key: software is acceptable (there is no human present to make a
// per-use gesture, so Approval's hardware rule would buy something different from
// what it exists to buy), and it is brokered end to end like any other key.
func TestNewKeys_AttestationPolicy(t *testing.T) {
	soft := softwareSigner(t, "did:web:localhost:proxies:gatekeeper", 0x51)

	if _, err := NewKeys([]HeldKey{{Signer: soft, Policy: Attestation}}); err != nil {
		t.Fatalf("a software attestation key must be accepted: %v", err)
	}
	// Hardware backing is permitted, never required: the policy must not quietly
	// acquire Approval's rule.
	if _, err := NewKeys([]HeldKey{{Signer: hwSigner{soft}, Policy: Attestation}}); err != nil {
		t.Fatalf("a hardware-backed attestation key must be accepted: %v", err)
	}

	sock := startDaemonKeys(t, HeldKey{Signer: soft, Policy: Attestation})
	cl, err := Dial(sock, soft.DID())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sig, err := cl.Sign([]byte("an audit entry"))
	if err != nil {
		t.Fatalf("Sign through an attestation key: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("brokered attestation signature is empty")
	}
}

// TestNewKeys_RefusesUnknownPolicy is the guard on the shape of the hardware
// check rather than on any one policy. The check asks the policy whether it needs
// hardware instead of testing for Approval, so a value this package does not
// define has no answer and must be refused. Testing `p == Approval` would have
// let this through as software-acceptable, which is the permissive answer arrived
// at by never being asked.
func TestNewKeys_RefusesUnknownPolicy(t *testing.T) {
	soft := softwareSigner(t, "did:web:localhost:employees:mallory", 0x52)

	for _, p := range []KeyPolicy{KeyPolicy(99), KeyPolicy(-1)} {
		if _, err := NewKeys([]HeldKey{{Signer: soft, Policy: p}}); err == nil {
			t.Fatalf("policy %s must be refused, not brokered", p)
		}
		// Even a hardware-backed signer must not rescue an undefined policy: the
		// objection is that nobody decided how to handle it, not that the key is weak.
		if _, err := NewKeys([]HeldKey{{Signer: hwSigner{soft}, Policy: p}}); err == nil {
			t.Fatalf("policy %s must be refused even with a hardware-backed key", p)
		}
	}
}

// TestKeyPolicyString keeps the operator-facing names stable: the daemon prints
// them in its key table, and an unrecognized value must render rather than vanish.
func TestKeyPolicyString(t *testing.T) {
	for _, tc := range []struct {
		p    KeyPolicy
		want string
	}{
		{Routine, "routine"},
		{Approval, "approval"},
		{Attestation, "attestation"},
		{KeyPolicy(99), "unknown(99)"},
	} {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("KeyPolicy(%d).String() = %q, want %q", int(tc.p), got, tc.want)
		}
	}
}
