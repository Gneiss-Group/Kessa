// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDaemonConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func validDaemonConfig(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		// A directory of its OWN, not the temp root. The daemon settles the socket's
		// parent to 0700 and will not modify a directory it did not create, so a
		// socket dropped straight into a general-purpose 0755 directory is refused.
		// That is the deployment shape the default already uses
		// ($XDG_RUNTIME_DIR/kessa/issuer.sock) and the one docs/daemon.md documents.
		"sock":             filepath.Join(t.TempDir(), "kessa", "issuer.sock"),
		"keystore":         ksPath,
		"attestation_keys": []string{epDIDForConfig},
	}
}

const epDIDForConfig = "did:web:localhost:proxies:gatekeeper"

func TestDaemonConfigLoads(t *testing.T) {
	cfg, err := loadDaemonConfig(writeDaemonConfig(t, validDaemonConfig(t)))
	if err != nil {
		t.Fatalf("loadDaemonConfig: %v", err)
	}
	if cfg.Keystore != ksPath || len(cfg.AttestationKeys) != 1 {
		t.Fatalf("config did not round-trip: %+v", cfg)
	}
}

// TestDaemonConfigSockIsRequired is the field with no absent state, and the
// reason differs from every other required field: the FLAG's default is derived
// from the environment ($XDG_RUNTIME_DIR, else $HOME). Inheriting it would put
// the socket wherever the invoking shell pointed, while a proxy's broker_socket
// always names a literal path, so the two could silently disagree and the daemon
// would come up somewhere the proxy is not looking.
func TestDaemonConfigSockIsRequired(t *testing.T) {
	for _, tc := range []struct{ name, sock string }{
		{"absent", ""},
		{"blank", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDaemonConfig(t)
			if tc.sock == "" {
				delete(cfg, "sock")
			} else {
				cfg["sock"] = tc.sock
			}
			_, err := loadDaemonConfig(writeDaemonConfig(t, cfg))
			if err == nil || !strings.Contains(err.Error(), "sock is required") {
				t.Fatalf("want a sock-required error, got: %v", err)
			}
		})
	}
}

func TestDaemonConfigNeedsAKeySource(t *testing.T) {
	cfg := validDaemonConfig(t)
	delete(cfg, "keystore")
	delete(cfg, "attestation_keys")
	_, err := loadDaemonConfig(writeDaemonConfig(t, cfg))
	if err == nil || !strings.Contains(err.Error(), "keystore or mapping") {
		t.Fatalf("a daemon with no key source has nothing to broker, got: %v", err)
	}
}

// TestDaemonConfigAttestationKeysNeedAKeystore mirrors the flag-path rule. An
// ignored attestation_keys would broker the intended enforcement-point key as
// ROUTINE and still report success, which is the shape of a check that passes by
// not testing anything.
func TestDaemonConfigAttestationKeysNeedAKeystore(t *testing.T) {
	cfg := validDaemonConfig(t)
	delete(cfg, "keystore")
	cfg["mapping"] = filepath.Join(t.TempDir(), "map.json")
	_, err := loadDaemonConfig(writeDaemonConfig(t, cfg))
	if err == nil || !strings.Contains(err.Error(), "attestation_keys") {
		t.Fatalf("want an attestation_keys error, got: %v", err)
	}
}

func TestDaemonConfigRefusesUnknownFields(t *testing.T) {
	for _, key := range []string{"keystor", "attestation_key", "_comment"} {
		t.Run(key, func(t *testing.T) {
			cfg := validDaemonConfig(t)
			cfg[key] = "anything"
			if _, err := loadDaemonConfig(writeDaemonConfig(t, cfg)); err == nil {
				t.Fatalf("unknown field %q was accepted", key)
			}
		})
	}
}

// TestDaemonSchemaFlagsAreTheWholeSchema is the counterpart to the proxy's, and
// exists for the same reason: the test below iterates daemonSchemaFlags(), so a
// tag the derivation cannot see is never iterated and never checked. A list
// written by reading the struct is the only thing that notices an omission.
func TestDaemonSchemaFlagsAreTheWholeSchema(t *testing.T) {
	want := map[string]bool{"sock": true, "keystore": true, "mapping": true, "attestation-key": true}
	got := daemonSchemaFlags()
	for name := range want {
		if !got[name] {
			t.Errorf("--%s is in the schema but not in the refused set, so it stays overridable alongside --config", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("--%s is refused alongside --config but this test did not expect it; if the schema grew, decide deliberately and add it here", name)
		}
	}
}

// TestDaemonSchemaFlagsExistOnDaemon is the typo guard: a tag naming a flag that
// does not exist means the real flag is never refused, so a stale launcher script
// silently overrides the config. It fails permissively, which is the direction
// that matters.
func TestDaemonSchemaFlagsExistOnDaemon(t *testing.T) {
	for name := range daemonSchemaFlags() {
		t.Run(name, func(t *testing.T) {
			_, _, errb := invoke(t, "daemon", "--"+name+"=\x00not-a-valid-value")
			if strings.Contains(errb, "not defined") {
				t.Fatalf("schema tags a flag %q that daemon does not define:\n%s", name, errb)
			}
		})
	}
}

func TestDaemonConfigAndCheckAreOutsideTheSchema(t *testing.T) {
	for _, name := range []string{"config", "check-config"} {
		if daemonSchemaFlags()[name] {
			t.Errorf("--%s must stay outside the schema so it remains usable with --config", name)
		}
	}
}

func TestDaemonRefusesFlagsAlongsideConfig(t *testing.T) {
	path := writeDaemonConfig(t, validDaemonConfig(t))
	code, _, errb := invoke(t, "daemon", "--config", path, "--keystore", ksPath)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "--keystore") || !strings.Contains(errb, "drop --config") {
		t.Fatalf("the refusal must name the flag and say how to proceed:\n%s", errb)
	}
}

// TestDaemonCheckConfigBindsNothing: the check stops immediately before listen,
// which is the first thing cmdDaemon creates. A check that bound the socket would
// also make a second, concurrent check fail against a healthy config.
func TestDaemonCheckConfigBindsNothing(t *testing.T) {
	cfg := validDaemonConfig(t)
	sock := cfg["sock"].(string)

	code, out, errb := invoke(t, "daemon", "--config", writeDaemonConfig(t, cfg), "--check-config")
	if code != exitOK {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, exitOK, out, errb)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("--check-config created the socket at %s", sock)
	}
	// It must report the depth rather than a bare OK, and must not claim a live
	// depth it has no way to reach: the daemon dials nothing.
	if !strings.Contains(out, "depth 2") {
		t.Errorf("the report should state the depth it reached:\n%s", out)
	}
	if strings.Contains(out, "depth 3") {
		t.Errorf("the daemon binds rather than dials, so there is no depth 3 to claim:\n%s", out)
	}
	// The key table is the point of running it: it says which key attests a log.
	if !strings.Contains(out, "attestation") {
		t.Errorf("the check should show the key policies it resolved:\n%s", out)
	}
}

func TestDaemonCheckConfigNeedsAConfig(t *testing.T) {
	code, _, errb := invoke(t, "daemon", "--check-config", "--keystore", ksPath)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "needs a --config") {
		t.Fatalf("stderr should explain:\n%s", errb)
	}
}

// TestShippedDaemonExampleChecksOut runs the example an operator is pointed at.
// A sample that no longer matches the schema is worse than none, since it teaches
// a shape the parser refuses, and every other test here builds its own config so
// none of them would notice.
func TestShippedDaemonExampleChecksOut(t *testing.T) {
	// The example documents its paths as relative to the repository root so a
	// reader can run it from a checkout. Honour that rather than rewriting the
	// example to suit the test's working directory.
	t.Chdir("../..")

	const path = "examples/issuer-daemon-config.json"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the documented example is missing: %v", err)
	}
	code, out, errb := invoke(t, "daemon", "--config", path, "--check-config")
	if code != exitOK {
		t.Fatalf("the shipped example does not pass its own check: exit %d\n%s\n%s", code, out, errb)
	}
	cfg, err := loadDaemonConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AttestationKeys) == 0 {
		t.Error("the example should demonstrate attestation_keys, which is what a proxy's broker_socket needs")
	}
	if cfg.Comment == "" {
		t.Error("the example should show the comment field, the only way to annotate a config")
	}
}
