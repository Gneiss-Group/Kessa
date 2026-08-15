// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig renders a config object to a temp file and returns its path.
func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// validConfig is a minimal config that passes every check, as a map so tests can
// delete or corrupt one key at a time without restating the rest.
func validConfig() map[string]any {
	return map[string]any{
		"policy": commercePol,
		"dids":   didsRoot,
		"enforcement_point": map[string]any{
			"did": epDID,
			"key": map[string]any{"mock_keystore": ksExample},
		},
		"http_addr": "127.0.0.1:18301",
		"audit_log": "",
		"audit_wal": nil,
		"status":    map[string]any{acmeListURL: acmeStatus},
	}
}

func TestConfigLoads(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, validConfig()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Policy != commercePol || cfg.EnforcementPoint.DID != epDID {
		t.Fatalf("config did not round-trip: %+v", cfg)
	}
	if got := cfg.statusPairs(); len(got) != 1 || got[0] != acmeListURL+"="+acmeStatus {
		t.Fatalf("statusPairs = %v", got)
	}
}

// TestConfigRefusesUnknownFields is the anti-silent-typo rule. A config that
// ignored a misspelled field would report success while the proxy ran under a
// posture the operator believed they had changed.
func TestConfigRefusesUnknownFields(t *testing.T) {
	for _, key := range []string{
		"audit_logg",                  // a plausible typo
		"allow_unauthenticated_remot", // the one that would matter most
		"_comment",                    // the fixtures' habit gets NO special treatment
		"_",                           // nor does the bare prefix
		"comments",                    // near-miss on the field that does exist
	} {
		t.Run(key, func(t *testing.T) {
			cfg := validConfig()
			cfg[key] = "anything"
			_, err := loadConfig(writeConfig(t, cfg))
			if err == nil {
				t.Fatalf("unknown field %q was accepted", key)
			}
			if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("error should name the unknown field, got: %v", err)
			}
		})
	}
}

// TestConfigCommentIsDeclared: `comment` is accepted because it is part of the
// schema, not because unknown keys are tolerated. The test above proves the
// second half; this proves the first.
func TestConfigCommentIsDeclared(t *testing.T) {
	cfg := validConfig()
	cfg["comment"] = "why this deployment runs without durability"
	loaded, err := loadConfig(writeConfig(t, cfg))
	if err != nil {
		t.Fatalf("a declared comment must be accepted: %v", err)
	}
	if loaded.Comment != "why this deployment runs without durability" {
		t.Fatalf("comment did not round-trip: %q", loaded.Comment)
	}
}

// TestConfigKeySourceExclusivity: both-set and neither-set are separate failures.
// Defaulting either way would pick a key custody model for the operator, and the
// two differ in whether the private key is in this process at all.
func TestConfigKeySourceExclusivity(t *testing.T) {
	cases := []struct {
		name    string
		key     map[string]any
		wantErr string
	}{
		{"both", map[string]any{"mock_keystore": ksExample, "broker_socket": "/tmp/s"}, "exactly one"},
		{"neither", map[string]any{}, "exactly one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg["enforcement_point"] = map[string]any{"did": epDID, "key": tc.key}
			_, err := loadConfig(writeConfig(t, cfg))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want an %q error, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestConfigAuditWALIsRequired is the field where "off" means the process
// promises less about what it recorded, so it has no default in either direction.
//
// The absent case is the one that needs a real implementation: *string decodes
// both "absent" and "null" to nil, so a required check built on one would accept
// an omitted key as a deliberate "off", which is a check that passes without
// testing anything.
func TestConfigAuditWALIsRequired(t *testing.T) {
	t.Run("absent is refused", func(t *testing.T) {
		cfg := validConfig()
		delete(cfg, "audit_wal")
		_, err := loadConfig(writeConfig(t, cfg))
		if err == nil || !strings.Contains(err.Error(), "audit_wal is required") {
			t.Fatalf("an omitted audit_wal must be refused, got: %v", err)
		}
	})

	t.Run("null disables durability", func(t *testing.T) {
		cfg := validConfig()
		cfg["audit_wal"] = nil
		loaded, err := loadConfig(writeConfig(t, cfg))
		if err != nil {
			t.Fatalf("explicit null must be accepted: %v", err)
		}
		path, enabled, err := loaded.auditWAL()
		if err != nil || enabled || path != "" {
			t.Fatalf("null should disable: path=%q enabled=%v err=%v", path, enabled, err)
		}
	})

	t.Run("a path enables durability", func(t *testing.T) {
		cfg := validConfig()
		cfg["audit_wal"] = "/var/lib/kessa/audit.wal"
		loaded, err := loadConfig(writeConfig(t, cfg))
		if err != nil {
			t.Fatal(err)
		}
		path, enabled, err := loaded.auditWAL()
		if err != nil || !enabled || path != "/var/lib/kessa/audit.wal" {
			t.Fatalf("path=%q enabled=%v err=%v", path, enabled, err)
		}
	})

	t.Run("empty string is refused rather than read as off", func(t *testing.T) {
		cfg := validConfig()
		cfg["audit_wal"] = ""
		_, err := loadConfig(writeConfig(t, cfg))
		if err == nil || !strings.Contains(err.Error(), "null") {
			t.Fatalf("an empty audit_wal should point at null, got: %v", err)
		}
	})
}

func TestConfigRequiredFields(t *testing.T) {
	for _, field := range []string{"policy", "dids"} {
		t.Run(field, func(t *testing.T) {
			cfg := validConfig()
			delete(cfg, field)
			if _, err := loadConfig(writeConfig(t, cfg)); err == nil {
				t.Fatalf("%s must be required", field)
			}
		})
	}
	t.Run("enforcement_point.did", func(t *testing.T) {
		cfg := validConfig()
		cfg["enforcement_point"] = map[string]any{"key": map[string]any{"mock_keystore": ksExample}}
		if _, err := loadConfig(writeConfig(t, cfg)); err == nil {
			t.Fatal("enforcement_point.did must be required")
		}
	})
}

// TestConfigRefusesTrailingContent: two concatenated objects would otherwise load
// silently as the first one, which is a config nobody wrote.
func TestConfigRefusesTrailingContent(t *testing.T) {
	path := writeConfig(t, validConfig())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("\n{\"policy\":\"other\"}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("trailing content must be refused")
	}
}

// ---- the derived refused-flag set ------------------------------------------

// TestSchemaFlagsExistOnServe catches the failure this whole design is exposed
// to: a typo'd tag (`flag:"http-adr"`) names a flag that does not exist, so the
// real flag is never refused and the config is silently overridable. That fails
// PERMISSIVELY, which is the direction that matters.
// TestSchemaFlagsAreTheWholeSchema pins the refused set to a list written by
// reading the struct, which is the one thing the tests around it cannot do.
//
// Every other assertion here iterates schemaFlags(), so a tag the derivation
// FAILS TO SEE is absent from the iteration and every one of them passes
// vacuously: the missing flag is never checked because it was never listed. That
// is the enumerated-inclusion shape the house rules name, and it applies to a
// coverage check as readily as to a policy.
//
// The list rots on purpose. A field added to Config makes this fail, and the
// person adding it has to look at the diff and confirm the flag really should
// become un-overridable alongside --config. That is a decision worth interrupting
// someone for, since getting it wrong leaves a launcher script silently
// overriding the reviewed file.
func TestSchemaFlagsAreTheWholeSchema(t *testing.T) {
	want := map[string]bool{
		"policy": true, "dids": true, "enforcement-point": true,
		"signer-sock": true, "keystore": true,
		"http-addr": true, "mcp-addr": true,
		"allow-unauthenticated-remote": true,
		"export":                       true, "audit-log": true, "audit-wal": true,
		"status": true,
	}
	got := schemaFlags()
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

func TestSchemaFlagsExistOnServe(t *testing.T) {
	for name := range schemaFlags() {
		t.Run(name, func(t *testing.T) {
			// A value that is wrong for every flag type, so parsing always fails.
			// What matters is HOW it fails: "not defined" means the tag names a flag
			// that does not exist.
			_, _, errb := invoke(t, "serve", "--"+name+"=\x00not-a-valid-value")
			if strings.Contains(errb, "not defined") {
				t.Fatalf("schema tags a flag %q that serve does not define:\n%s", name, errb)
			}
		})
	}
}

// TestNowIsNotInTheSchema pins the deliberate exclusion. --now is a determinism
// fixture for reproducible runs; putting it in the schema would expose a test
// seam as operator-facing surface, and would also make it unusable alongside
// --config, since the schema is exactly the refused set.
func TestNowIsNotInTheSchema(t *testing.T) {
	for _, name := range []string{"now", "config", "check-config"} {
		if schemaFlags()[name] {
			t.Errorf("--%s must stay outside the schema so it remains usable with --config", name)
		}
	}
}

func TestConflictingFlagsUsesExplicitlySetFlags(t *testing.T) {
	newSet := func() (*flag.FlagSet, *string, *bool) {
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		addr := fs.String("http-addr", "127.0.0.1:8181", "")
		allow := fs.Bool("allow-unauthenticated-remote", false, "")
		fs.String("now", "", "")
		return fs, addr, allow
	}

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"nothing set", nil, nil},
		{"a flag at a non-default value", []string{"--http-addr", "0.0.0.0:1"}, []string{"http-addr"}},
		// The two that a default-comparison implementation would miss entirely.
		{"a flag set to its own default", []string{"--http-addr", "127.0.0.1:8181"}, []string{"http-addr"}},
		{"a boolean set to false", []string{"--allow-unauthenticated-remote=false"}, []string{"allow-unauthenticated-remote"}},
		// Outside the schema, so never a conflict.
		{"a flag outside the schema", []string{"--now", "2026-07-09T12:00:00Z"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, _, _ := newSet()
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got := conflictingFlags(fs)
			if len(got) != len(tc.want) {
				t.Fatalf("conflictingFlags = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("conflictingFlags = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// ---- serve, driven by a config file ----------------------------------------

func TestServeRefusesFlagsAlongsideConfig(t *testing.T) {
	path := writeConfig(t, validConfig())

	code, _, errb := invoke(t, "serve", "--config", path, "--http-addr", "127.0.0.1:1")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "--http-addr") {
		t.Fatalf("the refusal must name the offending flag:\n%s", errb)
	}
	// It has to say how to proceed, because the escape hatch is not a flag: it is
	// dropping --config, which nobody guesses from "refused".
	if !strings.Contains(errb, "drop --config") {
		t.Fatalf("the refusal must say how to proceed:\n%s", errb)
	}
}

func TestServeAllowsNonSchemaFlagsAlongsideConfig(t *testing.T) {
	path := writeConfig(t, validConfig())
	code, out, errb := invoke(t, "serve", "--config", path, "--check-config",
		"--now", "2026-07-09T12:00:00Z")
	if code != exitOK {
		t.Fatalf("--now must remain usable with --config: exit %d\n%s\n%s", code, out, errb)
	}
}

// TestCheckConfigReportsItsDepth: a bare "OK" would be the misleading version,
// since most of what breaks a real start lives in the files the config names
// rather than in its syntax.
func TestCheckConfigReportsItsDepth(t *testing.T) {
	path := writeConfig(t, validConfig())
	code, out, errb := invoke(t, "serve", "--config", path, "--check-config")
	if code != exitOK {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, exitOK, out, errb)
	}
	// "policy" and the DID trust root are named separately, because they were one
	// line making two claims of different strengths and the weaker one was untrue.
	for _, want := range []string{"schema", "listeners", "policy", "DID trust root", "status lists", "depth 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report should mention %q:\n%s", want, out)
		}
	}
	// A mock keystore means there is no daemon to reach, and the report must say
	// that rather than claiming a depth it did not get to.
	if strings.Contains(out, "depth 3") {
		t.Errorf("a config naming no daemon cannot have reached depth 3:\n%s", out)
	}
}

// TestCheckConfigCreatesNothing: the check stops at the last instruction before
// buildSink, so a config naming an audit log must not bring one into existence.
func TestCheckConfigCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit-log.jsonl")
	walPath := filepath.Join(dir, "audit.wal")

	cfg := validConfig()
	cfg["audit_log"] = logPath
	cfg["audit_wal"] = walPath

	code, _, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb)
	}
	for _, p := range []string{logPath, walPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("--check-config created %s", p)
		}
	}
}

func TestCheckConfigNeedsAConfig(t *testing.T) {
	code, _, errb := invoke(t, "serve", "--check-config",
		"--policy", commercePol, "--dids", didsRoot,
		"--enforcement-point", epDID, "--keystore", ksExample)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "needs a --config") {
		t.Fatalf("stderr should explain:\n%s", errb)
	}
}

// TestConfigAbsentMeansOff covers the rule one field at a time rather than
// letting a single case stand in for three.
//
// The listener arms are observable end to end: the check's report lists exactly
// the addresses that would bind. The audit_log arm is asserted at the decode
// level, because "no sink" is only observable from a running server, and what
// makes it off is that cmdServe assigns cfg.AuditLog unconditionally.
func TestConfigAbsentMeansOff(t *testing.T) {
	t.Run("mcp_addr absent closes the MCP listener", func(t *testing.T) {
		cfg := validConfig() // sets http_addr only
		code, out, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, errb)
		}
		if strings.Contains(out, "8182") {
			t.Errorf("an absent mcp_addr must not inherit the flag default:\n%s", out)
		}
		if !strings.Contains(out, "127.0.0.1:18301") {
			t.Errorf("the configured listener should be reported:\n%s", out)
		}
	})

	t.Run("http_addr absent closes the HTTP listener", func(t *testing.T) {
		cfg := validConfig()
		delete(cfg, "http_addr")
		cfg["mcp_addr"] = "127.0.0.1:18302"
		code, out, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, errb)
		}
		if strings.Contains(out, "8181") {
			t.Errorf("an absent http_addr must not inherit the flag default:\n%s", out)
		}
	})

	t.Run("both listeners absent is refused", func(t *testing.T) {
		cfg := validConfig()
		delete(cfg, "http_addr")
		code, _, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
		if code != exitUsage {
			t.Fatalf("exit %d, want %d", code, exitUsage)
		}
		if !strings.Contains(errb, "no listeners enabled") {
			t.Fatalf("an incomplete config must not start a chokepoint nothing can reach:\n%s", errb)
		}
	})

	t.Run("audit_log absent decodes to off", func(t *testing.T) {
		cfg := validConfig()
		delete(cfg, "audit_log")
		loaded, err := loadConfig(writeConfig(t, cfg))
		if err != nil {
			t.Fatal(err)
		}
		if loaded.AuditLog != "" {
			t.Fatalf("audit_log = %q, want the zero value that disables the sink", loaded.AuditLog)
		}
	})
}

// TestShippedExampleConfigChecksOut runs the example an operator is pointed at.
// A sample config is only useful if it is the thing people start from, and one
// that no longer matches the schema is worse than none: it teaches a shape the
// parser refuses. The tests above all build their own config, so none of them
// would notice.
func TestShippedExampleConfigChecksOut(t *testing.T) {
	// The example documents its paths as relative to the repository root, so that
	// a reader can run it as-is from a checkout. Honour that here rather than
	// rewriting the example to suit the test's working directory, which would make
	// the file pass this test and fail the operator.
	t.Chdir("../..")

	const path = "examples/proxy-config.json"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the documented example is missing: %v", err)
	}
	code, out, errb := invoke(t, "serve", "--config", path, "--check-config")
	if code != exitOK {
		t.Fatalf("the shipped example does not pass its own check: exit %d\n%s\n%s", code, out, errb)
	}
	// It must also demonstrate the rule most likely to surprise someone: mcp_addr
	// is omitted on purpose, so that listener is closed rather than defaulted on.
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCPAddr != "" {
		t.Error("the example no longer demonstrates absent-means-off for mcp_addr")
	}
	if cfg.Comment == "" {
		t.Error("the example should show the comment field, since it is the only way to annotate a config")
	}
}
