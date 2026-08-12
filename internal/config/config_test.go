// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nested struct {
	Deep string `json:"deep" flag:"deep-flag"`
}

type schema struct {
	Tagged   string            `json:"tagged" flag:"tagged-flag"`
	Group    nested            `json:"group"`
	Untagged string            `json:"untagged"`
	Raw      []byte            `json:"raw" flag:"raw-flag"`
	Mapped   map[string]string `json:"mapped" flag:"mapped-flag"`
}

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFlagNamesIsDerived tests the MECHANISM rather than a snapshot of any one
// command's schema. Adding a tagged field has to extend the set by itself; a test
// asserting against a hand-written list would be circular, and the rule would rot
// the first time someone added a field under time pressure.
func TestFlagNamesIsDerived(t *testing.T) {
	got := FlagNames(schema{})

	for _, want := range []string{"tagged-flag", "raw-flag", "mapped-flag"} {
		if !got[want] {
			t.Errorf("a tagged field %q was not collected", want)
		}
	}
	if !got["deep-flag"] {
		t.Error("a tag inside a nested struct was missed; grouped fields like enforcement_point.key live there")
	}
	if len(got) != 4 {
		t.Errorf("an untagged field was collected: %v", got)
	}
}

func TestFlagNamesAcceptsAPointer(t *testing.T) {
	if got := FlagNames(&schema{}); !got["tagged-flag"] {
		t.Errorf("a pointer schema should behave like the value: %v", got)
	}
}

// TestConflictingUsesExplicitlySetFlags is the guard on the one implementation
// choice that fails silently. Both subtests below pass against fs.Visit and fail
// against a VisitAll plus compare-to-default implementation, which is the obvious
// wrong way to write this.
func TestConflictingUsesExplicitlySetFlags(t *testing.T) {
	covered := map[string]bool{"addr": true, "allow": true}

	newSet := func() *flag.FlagSet {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.String("addr", "127.0.0.1:8181", "")
		fs.Bool("allow", false, "")
		fs.String("outside", "", "")
		return fs
	}

	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"nothing set", nil, nil},
		{"set to a different value", []string{"--addr", "0.0.0.0:1"}, []string{"addr"}},
		// A flag passed at its own default value: invisible to a value comparison.
		{"set to its own default", []string{"--addr", "127.0.0.1:8181"}, []string{"addr"}},
		// A boolean passed as false: "unset" and "false" are the same value.
		{"boolean set to false", []string{"--allow=false"}, []string{"allow"}},
		{"both", []string{"--addr", "x", "--allow=true"}, []string{"addr", "allow"}},
		{"a flag the schema does not cover", []string{"--outside", "x"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newSet()
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got := Conflicting(fs, covered)
			if len(got) != len(tc.want) {
				t.Fatalf("Conflicting = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("Conflicting = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestLoadRefusesUnknownFields(t *testing.T) {
	var s schema
	err := Load(write(t, `{"tagged":"x","taggd":"typo"}`), &s)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an unknown field must be refused, got: %v", err)
	}
}

// TestLoadGivesUnderscoreKeysNoSpecialTreatment: the keystore fixtures annotate
// themselves with a "_comment" key, and that habit must not leak into a config
// file. A prefix carve-out would be exactly the tolerated-unknown-key rule this
// package exists to refuse, under another name.
func TestLoadGivesUnderscoreKeysNoSpecialTreatment(t *testing.T) {
	var s schema
	if err := Load(write(t, `{"tagged":"x","_comment":"why"}`), &s); err == nil {
		t.Fatal(`"_comment" was accepted; a config file annotates itself with a DECLARED field`)
	}
}

func TestLoadRefusesTrailingContent(t *testing.T) {
	var s schema
	if err := Load(write(t, `{"tagged":"x"}{"tagged":"y"}`), &s); err == nil {
		t.Fatal("two concatenated objects must be refused, not read as the first")
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	var s schema
	if err := Load(filepath.Join(t.TempDir(), "absent.json"), &s); err == nil {
		t.Fatal("a missing config file must be an error")
	}
}
