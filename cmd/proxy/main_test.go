// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/auditsink"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/enforce"
	"github.com/Gneiss-Group/Kessa/internal/keystore"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
)

const (
	didsRoot    = "../../testdata/dids"
	commercePol = "../../examples/policies/commerce-security.json"
	ksExample   = "../../examples/issuer/keystore.json"
	acmeStatus  = "../../testdata/status/acme_status.json"
	acmeListURL = "https://localhost/orgs/acme/status.json"
	epDID       = "did:web:localhost:proxies:gatekeeper"

	didAcme   = "did:web:localhost:orgs:acme"
	didWorker = "did:web:localhost:agents:worker"
)

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	return run(args, &out, &errb), out.String(), errb.String()
}

// buildChainFile writes a one-hop acme->worker chain, keyed from the example
// keystore so it verifies against testdata/dids. Worker is scoped to
// payment.transfer with amount <= 100.
func buildChainFile(t *testing.T, path string) {
	t.Helper()
	ks, err := keystore.Load(ksExample)
	if err != nil {
		t.Fatal(err)
	}
	acme, err := ks.Signer(didAcme)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ks.Signer(didWorker)
	if err != nil {
		t.Fatal(err)
	}
	m := macaroon.Mint([]byte("proxy-cli-test-rootkey-0000000000"), "cred-cli", didAcme)
	m, err = macaroon.Attenuate(m, macaroon.Caveat{Field: "action.type", Op: macaroon.OpEq, Value: "payment.transfer"})
	if err != nil {
		t.Fatal(err)
	}
	m, err = macaroon.Attenuate(m, macaroon.Caveat{Field: "amount", Op: macaroon.OpLe, Value: "100"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := credential.New(credential.Options{Subject: didWorker, Issuer: didAcme, Macaroon: m, HolderKey: worker.Public()})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := chain.SignIssuance(acme, c)
	if err != nil {
		t.Fatal(err)
	}
	ch := &chain.Chain{Links: []chain.Link{{Credential: *c, IssuerProof: proof}}}
	data, err := ch.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A batch run: one allow (amount 10), one deny (amount 9999 exceeds the ceiling).
func TestRun_BatchProducesExport(t *testing.T) {
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "chain.json")
	buildChainFile(t, chainFile)

	reqFile := filepath.Join(dir, "requests.json")
	writeJSON(t, reqFile, []map[string]any{
		{"chainFile": chainFile, "nonce": "r1", "action": action("10")},
		{"chainFile": chainFile, "nonce": "r2", "action": action("9999")},
	})

	exportFile := filepath.Join(dir, "export.json")
	auditLog := filepath.Join(dir, "audit.jsonl")
	code, out, errb := invoke(t, "run",
		"--requests", reqFile, "--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID, "--keystore", ksExample,
		"--status", acmeListURL+"="+acmeStatus, "--out", exportFile, "--audit-log", auditLog)
	if code != exitOK {
		t.Fatalf("run exit=%d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "req 0  ALLOW") || !strings.Contains(out, "req 1  DENY") {
		t.Fatalf("unexpected run output:\n%s", out)
	}
	if _, err := os.Stat(exportFile); err != nil {
		t.Fatalf("export not written: %v", err)
	}

	// The default local-file audit sink forwarded one JSON-Lines record per entry
	// (one allow, one deny), each mirroring the decision recorded in the export.
	logged := readJSONL(t, auditLog)
	if len(logged) != 2 {
		t.Fatalf("audit sink wrote %d records, want 2:\n%s", len(logged), out)
	}
	if !logged[0].Allowed || logged[0].ActionTarget != "acct/999" {
		t.Fatalf("record 0 = %+v", logged[0])
	}
	if logged[1].Allowed {
		t.Fatalf("record 1 should be the denied action, got %+v", logged[1])
	}
	for i, r := range logged {
		if r.Seq != uint64(i) || len(r.EntryHash) == 0 {
			t.Fatalf("record %d has bad seq/hash: %+v", i, r)
		}
	}
}

// A durable batch run followed by a second run against the same WAL: the second
// recovers the first's entries and appends its own, so the export grows rather
// than restarting.
func TestRun_WALRecoversAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "chain.json")
	buildChainFile(t, chainFile)
	reqFile := filepath.Join(dir, "requests.json")
	writeJSON(t, reqFile, []map[string]any{
		{"chainFile": chainFile, "nonce": "r1", "action": action("10")},
		{"chainFile": chainFile, "nonce": "r2", "action": action("20")},
	})
	wal := filepath.Join(dir, "audit.wal")

	do := func(out string) {
		code, o, e := invoke(t, "run",
			"--requests", reqFile, "--policy", commercePol, "--dids", didsRoot,
			"--enforcement-point", epDID, "--keystore", ksExample,
			"--status", acmeListURL+"="+acmeStatus, "--out", out, "--audit-wal", wal, "--audit-log", "")
		if code != exitOK {
			t.Fatalf("run exit=%d\n%s\n%s", code, o, e)
		}
	}

	do(filepath.Join(dir, "export1.json"))
	exp2 := filepath.Join(dir, "export2.json")
	do(exp2)

	if n := readExportEntries(t, exp2); n != 4 {
		t.Fatalf("second run should recover 2 and append 2 = 4 entries, got %d", n)
	}
}

// readExportEntries counts the entries in a written export envelope.
func readExportEntries(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return len(env.Entries)
}

// readJSONL decodes a JSON-Lines audit-sink file into records.
func readJSONL(t *testing.T, path string) []auditsink.AuditRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []auditsink.AuditRecord
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r auditsink.AuditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad JSONL line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// The serve command is a thin shell over enforce.Handler; confirm buildProxy
// wires up and the handler answers /export with a v2 envelope.
func TestServe_Wiring(t *testing.T) {
	px, _, ok := buildProxy(commercePol, didsRoot, epDID, ksExample,
		statusFlag{acmeListURL + "=" + acmeStatus}, nil, nil, nil, io.Discard)
	if !ok {
		t.Fatal("buildProxy failed")
	}
	srv := httptest.NewServer(enforce.Handler(px))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env["version"] != "kessa-audit-export/v2" {
		t.Fatalf("unexpected export version %v", env["version"])
	}

	bad, err := http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	if bad.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route status %d", bad.StatusCode)
	}
}

// TestEnabledListeners is the §3 config decision in isolation: a listener is on
// when it has an address and off when its address is cleared, and both-off is a
// legal (empty) result.
func TestEnabledListeners(t *testing.T) {
	both := []listener{{name: "HTTP", addr: "127.0.0.1:8181"}, {name: "MCP", addr: "127.0.0.1:8182"}}
	cases := []struct {
		name string
		in   []listener
		want []string
	}{
		{"both on", both, []string{"HTTP", "MCP"}},
		{"http only", []listener{{name: "HTTP", addr: "127.0.0.1:8181"}, {name: "MCP", addr: ""}}, []string{"HTTP"}},
		{"mcp only", []listener{{name: "HTTP", addr: "  "}, {name: "MCP", addr: "127.0.0.1:8182"}}, []string{"MCP"}},
		{"both off", []listener{{name: "HTTP", addr: ""}, {name: "MCP", addr: ""}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := enabledListeners(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("enabled = %d listeners, want %d", len(got), len(tc.want))
			}
			for i, l := range got {
				if l.name != tc.want[i] {
					t.Fatalf("enabled[%d] = %q, want %q", i, l.name, tc.want[i])
				}
			}
		})
	}
}

// TestServe_BothListenersDisabled confirms clearing both addresses is a legal,
// inert configuration: serve reports it and exits 0 without binding anything.
func TestServe_BothListenersDisabled(t *testing.T) {
	code, out, errb := invoke(t, "serve",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID, "--keystore", ksExample,
		"--http-addr", "", "--mcp-addr", "", "--audit-log", "")
	if code != exitOK {
		t.Fatalf("both-off serve exit=%d, want %d\n%s\n%s", code, exitOK, out, errb)
	}
	if !strings.Contains(out, "no listeners enabled") {
		t.Fatalf("expected a 'no listeners enabled' note, got:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"run"}, // missing required flags
	} {
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Fatalf("args %v: exit=%d want %d", args, code, exitUsage)
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func action(amount string) map[string]any {
	return map[string]any{"type": "payment.transfer", "target": "acct/999",
		"attributes": map[string]string{"amount": amount}, "timestamp": "2026-07-09T12:00:00Z"}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRefuseRemoteBind pins the fail-closed default. It removes the accidental
// exposure — an operator who binds a reachable address without meaning to — while
// leaving the deliberate one available, because containerized serving requires it
// (a container's loopback is unreachable through -p).
func TestRefuseRemoteBind(t *testing.T) {
	cases := []struct {
		name       string
		http, mcp  string
		allow      bool
		wantOK     bool
		wantMsgHas string
	}{
		{"loopback ipv4", "127.0.0.1:8181", "127.0.0.1:8182", false, true, ""},
		{"loopback ipv6", "[::1]:8181", "", false, true, ""},
		{"localhost name", "localhost:8181", "", false, true, ""},
		{"both disabled", "", "", false, true, ""},
		{"wildcard v4", "0.0.0.0:8181", "", false, false, "refusing to bind"},
		{"bare port binds all", ":8181", "", false, false, "refusing to bind"},
		{"routable address", "10.0.0.5:8181", "", false, false, "refusing to bind"},
		{"only the mcp listener is remote", "127.0.0.1:8181", "0.0.0.0:8182", false, false, "refusing to bind"},
		{"unparseable is refused, not guessed", "not-an-addr", "", false, false, "refusing to bind"},
		{"opt-in permits it, with a warning", "0.0.0.0:8181", "", true, true, "WARNING"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, ok := refuseRemoteBind(tc.http, tc.mcp, tc.allow)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (msg %q)", ok, tc.wantOK, msg)
			}
			if tc.wantMsgHas != "" && !strings.Contains(msg, tc.wantMsgHas) {
				t.Fatalf("message %q should mention %q", msg, tc.wantMsgHas)
			}
			if tc.wantMsgHas == "" && msg != "" {
				t.Fatalf("expected no message, got %q", msg)
			}
		})
	}
}
