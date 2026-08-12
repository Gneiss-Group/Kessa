// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/keystore"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// startBroker runs an in-process signing daemon holding the enforcement point's
// key as an ATTESTATION key, and returns its socket path.
//
// The socket lives under /tmp rather than t.TempDir() because a Unix socket path
// is capped near 104 bytes on darwin and the default temp root is long enough to
// blow that on its own.
func startBroker(t *testing.T, d types.DID) string {
	t.Helper()

	ks, err := keystore.Load(ksExample)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ks.Signer(d)
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("/tmp", "kbroker")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := signerd.NewKeys([]signerd.HeldKey{{Signer: sg, Policy: signerd.Attestation}})
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return sock
}

// TestBrokeredEnforcementKeySignsTheExport is the point of the whole change: the
// enforcement point's private key stays in the daemon, and the export is still
// signed by that enforcement point.
//
// It asserts on the artifact rather than on the wiring. "enforcementPointSigner
// returned a signer" would pass against a signer that signs with the wrong key or
// cannot sign at all; an envelope that names this DID and carries a signature can
// only come from the key having actually been exercised over the socket.
func TestBrokeredEnforcementKeySignsTheExport(t *testing.T) {
	sock := startBroker(t, epDID)

	ep, ok := enforcementPointSigner("", sock, epDID, io.Discard)
	if !ok {
		t.Fatal("enforcementPointSigner refused a live daemon socket")
	}
	if got := string(ep.DID()); got != epDID {
		t.Fatalf("brokered signer reports DID %q, want %q", got, epDID)
	}

	px, ok := buildProxy(commercePol, didsRoot, ep,
		statusFlag{acmeListURL + "=" + acmeStatus}, nil, nil, nil, io.Discard)
	if !ok {
		t.Fatal("buildProxy failed with a brokered enforcement key")
	}

	srv := httptest.NewServer(enforce.Handler(px))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var env struct {
		Signer            string `json:"signer"`
		EnvelopeSignature []byte `json:"envelopeSignature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Signer != epDID {
		t.Fatalf("export names signer %q, want %q", env.Signer, epDID)
	}
	if len(env.EnvelopeSignature) == 0 {
		t.Fatal("export carries no envelope signature, so the brokered key never signed anything")
	}
}

// TestEnforcementPointSignerRequiresExactlyOneSource covers the refusals. Both
// sources and neither source are separate failures on purpose: defaulting either
// way would pick a key custody model for the operator, and the two sources differ
// in whether the private key is in this process at all.
func TestEnforcementPointSignerRequiresExactlyOneSource(t *testing.T) {
	sock := startBroker(t, epDID)

	for _, tc := range []struct {
		name    string
		ks      string
		sock    string
		ep      string
		wantErr string
	}{
		{"neither source", "", "", epDID, "one of --keystore or --signer-sock"},
		{"both sources", ksExample, sock, epDID, "mutually exclusive"},
		{"no enforcement point, keystore", ksExample, "", "", "--enforcement-point is required"},
		{"no enforcement point, socket", "", sock, "", "--enforcement-point is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errb strings.Builder
			sg, ok := enforcementPointSigner(tc.ks, tc.sock, tc.ep, &errb)
			if ok {
				t.Fatal("want refusal, got a signer")
			}
			if sg != nil {
				t.Fatal("a refused key source must not also return a signer")
			}
			if !strings.Contains(errb.String(), tc.wantErr) {
				t.Fatalf("message %q does not mention %q", errb.String(), tc.wantErr)
			}
		})
	}
}

// TestBrokeredSignerFailsAtStartup: a daemon that is absent, or present but
// holding some other key, must stop the proxy from starting rather than surface
// at the first request. A proxy that starts and then cannot sign has already
// accepted traffic it cannot record.
func TestBrokeredSignerFailsAtStartup(t *testing.T) {
	t.Run("no daemon", func(t *testing.T) {
		var errb strings.Builder
		if _, ok := enforcementPointSigner("", "/tmp/kessa-no-such-daemon.sock", epDID, &errb); ok {
			t.Fatal("a missing daemon must refuse at startup")
		}
	})

	t.Run("daemon does not hold this key", func(t *testing.T) {
		sock := startBroker(t, didAcme) // holds acme's key, not the gatekeeper's
		var errb strings.Builder
		if _, ok := enforcementPointSigner("", sock, epDID, &errb); ok {
			t.Fatal("a daemon that does not hold the enforcement point's key must refuse at startup")
		}
	})
}

// TestServeRefusesAmbiguousKeySource runs the refusal through the CLI, because
// the flag surface is what an operator actually touches. Both these invocations
// would otherwise reach the listeners.
func TestServeRefusesAmbiguousKeySource(t *testing.T) {
	sock := startBroker(t, epDID)

	code, _, errOut := invoke(t, "serve",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID,
		"--keystore", ksExample, "--signer-sock", sock,
		"--audit-log", "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "mutually exclusive") {
		t.Fatalf("stderr %q does not explain the conflict", errOut)
	}

	code, _, errOut = invoke(t, "serve",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID,
		"--audit-log", "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "one of --keystore or --signer-sock") {
		t.Fatalf("stderr %q does not name the missing key source", errOut)
	}
}

// TestServeValidatesBeforeCreatingFiles: a serve that is going to be refused must
// not leave an audit-log file behind. The sink and the WAL both create files, and
// they used to be opened before the bind address and the key source were checked,
// so a rejected invocation still wrote to the operator's disk.
func TestServeValidatesBeforeCreatingFiles(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit-log.jsonl")
	wal := filepath.Join(dir, "audit.wal")

	// Refused for its key source (neither given), with both file paths set.
	code, _, _ := invoke(t, "serve",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID,
		"--audit-log", log, "--audit-wal", wal)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	for _, p := range []string{log, wal} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was created by an invocation that was refused", p)
		}
	}

	// Same for a refused bind address, which is checked earlier still.
	code, _, _ = invoke(t, "serve",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID, "--keystore", ksExample,
		"--http-addr", "0.0.0.0:8181",
		"--audit-log", log, "--audit-wal", wal)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	for _, p := range []string{log, wal} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was created by an invocation refused for its bind address", p)
		}
	}
}
