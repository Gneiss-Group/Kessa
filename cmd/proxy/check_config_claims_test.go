// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --check-config exists to tell an operator whether a deployment will start, and
// the value of that answer is exactly the accuracy of the claims it prints. Two
// of them were overstated: status lists were reported "signature-checked" when
// status.Load only parses, and the DID directory was reported loaded when
// FileResolver had never opened it.
//
// These tests assert the claims are EARNED, one property per case, because a
// report is the one place where a check that quietly does less than it says is
// invisible by construction: the output looks the same either way.

// mutateStatus rewrites the example status list through fn and returns a config
// naming the result.
func mutateStatus(t *testing.T, fn func(m map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile(acmeStatus)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	listPath := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(listPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg["status"] = map[string]any{acmeListURL: listPath}
	return writeConfig(t, cfg)
}

func TestCheckConfigRefusesAStatusListItCannotVouchFor(t *testing.T) {
	for _, tc := range []struct {
		name, wantIn string
		mutate       func(m map[string]any)
	}{
		{
			// Verify refuses an unsigned list by name. Parse never looked.
			name:   "unsigned",
			wantIn: "unsigned",
			mutate: func(m map[string]any) { m["signature"] = "" },
		},
		{
			// The herd-privacy floor is a property of the published artifact, and a
			// list too small to hide a credential in is not one a deployment should
			// start with.
			name:   "below the herd-privacy floor",
			wantIn: "herd-privacy",
			mutate: func(m map[string]any) {
				m["bitstring"] = base64.RawURLEncoding.EncodeToString(make([]byte, 8))
			},
		},
		{
			// Signed, correctly sized, and the bits no longer match the signature.
			name:   "tampered bits",
			wantIn: "signature verification failed",
			mutate: func(m map[string]any) {
				bits, err := base64.RawURLEncoding.DecodeString(m["bitstring"].(string))
				if err != nil {
					t.Fatal(err)
				}
				bits[0] ^= 0xFF
				m["bitstring"] = base64.RawURLEncoding.EncodeToString(bits)
			},
		},
		{
			// A list whose self-declared issuer is not resolvable under the trust
			// root cannot be checked at all, which is itself the answer.
			name:   "issuer that does not resolve",
			wantIn: "does not resolve",
			mutate: func(m map[string]any) { m["issuer"] = "did:web:localhost:orgs:nobody" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errb := invoke(t, "serve", "--config", mutateStatus(t, tc.mutate), "--check-config")
			if code != exitUsage {
				t.Fatalf("exit %d, want %d: the report claimed a check it had not performed\n%s", code, exitUsage, out)
			}
			if !strings.Contains(errb, tc.wantIn) {
				t.Fatalf("refused, but not for the stated reason (want %q):\n%s", tc.wantIn, errb)
			}
		})
	}
}

// The control, and it is not optional: every case above passes if --check-config
// started refusing every status list, which would be a worse regression wearing
// these tests as a green light.
func TestCheckConfigStillAcceptsAGoodStatusList(t *testing.T) {
	code, out, errb := invoke(t, "serve", "--config", writeConfig(t, validConfig()), "--check-config")
	if code != exitOK {
		t.Fatalf("a valid config was refused, so the cases above prove nothing: exit %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "self-signature checked") {
		t.Errorf("the report no longer names what it checked:\n%s", out)
	}
	// The claim it must NOT make. Authority is per-credential (R6-01) and cannot
	// be established before a request carries one, so a report saying only
	// "signature-checked" would invite a reader to assume the question that
	// matters had been answered.
	if strings.Contains(out, "loaded and signature-checked") {
		t.Errorf("the overstated claim is back:\n%s", out)
	}
	if !strings.Contains(out, "AUTHORITY is per-credential") {
		t.Errorf("the report does not say which check it deliberately did not perform:\n%s", out)
	}
}

// The DID directory is the trust root: every signature is checked against a key
// from it. FileResolver opens files lazily, so nothing had ever established the
// root existed, and a config naming a path that does not exist reported OK and
// would have failed on its first request.
func TestCheckConfigRefusesAnAbsentTrustRoot(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		cfg := validConfig()
		cfg["dids"] = filepath.Join(t.TempDir(), "nonesuch")
		code, out, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
		if code != exitUsage {
			t.Fatalf("exit %d, want %d: an absent trust root reported OK\n%s", code, exitUsage, out)
		}
		if !strings.Contains(errb, "trust root") {
			t.Errorf("the refusal does not say what the directory is:\n%s", errb)
		}
	})
	t.Run("a file where a directory belongs", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "dids")
		if err := os.WriteFile(f, []byte("not a directory"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := validConfig()
		cfg["dids"] = f
		code, _, errb := invoke(t, "serve", "--config", writeConfig(t, cfg), "--check-config")
		if code != exitUsage {
			t.Fatalf("exit %d, want %d: a plain file passed as the trust root", code, exitUsage)
		}
		if !strings.Contains(errb, "not a directory") {
			t.Errorf("unexpected refusal:\n%s", errb)
		}
	})
}
