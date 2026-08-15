// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

type keysNested struct {
	Sock     string `json:"sock"`
	Keystore string `json:"keystore,omitempty"`
}

type keysSchema struct {
	Comment  string            `json:"comment,omitempty"`
	Policy   string            `json:"policy"`
	Key      keysNested        `json:"key"`
	WAL      json.RawMessage   `json:"audit_wal"`
	Status   map[string]string `json:"status,omitempty"`
	Rules    []keysNested      `json:"rules,omitempty"`
	Ignored  string            `json:"-"`
	unexpKey string            //nolint:unused // present to prove it is not addressable
}

// A duplicate key resolves last-wins in encoding/json, at every level and inside
// maps too, so it is refused everywhere and needs no schema to judge.
func TestDecodeStrict_RefusesDuplicateKeys(t *testing.T) {
	for _, tc := range []struct{ name, doc, wantIn string }{
		{"at the top level", `{"policy":"a","policy":"b","audit_wal":null,"key":{"sock":"s"}}`, `duplicate key "policy"`},
		{"nested in an object", `{"policy":"a","audit_wal":null,"key":{"sock":"s","sock":"t"}}`, `duplicate key "key.sock"`},
		{"inside a map, where names are arbitrary but repetition is still wrong",
			`{"policy":"a","audit_wal":null,"key":{"sock":"s"},"status":{"u":"f1","u":"f2"}}`, `duplicate key "status.u"`},
		{"inside an array element",
			`{"policy":"a","audit_wal":null,"key":{"sock":"s"},"rules":[{"sock":"a","sock":"b"}]}`, `duplicate key "rules[].sock"`},
		{"on the field whose absent state is load-bearing",
			`{"policy":"a","key":{"sock":"s"},"audit_wal":"/var/lib/kessa/audit.wal","audit_wal":null}`, `duplicate key "audit_wal"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v keysSchema
			err := DecodeStrict([]byte(tc.doc), &v)
			if err == nil {
				t.Fatalf("accepted a duplicate key; decoded to %+v", v)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("error does not name the offending key: got %q, want it to contain %q", err, tc.wantIn)
			}
		})
	}
}

// A differently-cased key is the sharper shape: encoding/json matches it
// case-insensitively when no exact match was consumed, so it is NOT an unknown
// field, DisallowUnknownFields never fires, and it can override a correctly-cased
// key on the line above.
func TestDecodeStrict_RefusesCaseVariantKeys(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"alone, satisfying a required field the file never spells correctly",
			`{"policy":"a","key":{"sock":"s"},"AUDIT_WAL":null}`},
		{"shadowing a correctly-cased key above it",
			`{"policy":"a","key":{"sock":"s"},"audit_wal":"/var/lib/kessa/audit.wal","AUDIT_WAL":null}`},
		{"nested", `{"policy":"a","audit_wal":null,"key":{"SOCK":"s"}}`},
		{"differing only in the middle", `{"Policy":"a","audit_wal":null,"key":{"sock":"s"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v keysSchema
			err := DecodeStrict([]byte(tc.doc), &v)
			if err == nil {
				t.Fatalf("accepted a case-variant key; decoded to %+v", v)
			}
			if !strings.Contains(err.Error(), "only by case") {
				t.Fatalf("refused, but not as a case variant: %v", err)
			}
		})
	}
}

// The two rules have different scopes on purpose, and this is the case that
// separates them: a map's keys are arbitrary, so two keys differing by case are
// two different legitimate keys and must both survive.
func TestDecodeStrict_MapKeysMayDifferByCase(t *testing.T) {
	var v keysSchema
	doc := `{"policy":"a","audit_wal":null,"key":{"sock":"s"},"status":{"https://a/x":"f1","https://A/X":"f2"}}`
	if err := DecodeStrict([]byte(doc), &v); err != nil {
		t.Fatalf("refused two distinct map keys as though one were a variant of the other: %v", err)
	}
	if len(v.Status) != 2 {
		t.Fatalf("expected both map keys to survive, got %+v", v.Status)
	}
}

// An unknown key stays the decoder's own error, reported in its own words. This
// pins that checkKeys does not get in front of it and rephrase it, which would
// leave two messages for one condition that could drift apart.
func TestDecodeStrict_UnknownKeyStillReportedByTheDecoder(t *testing.T) {
	var v keysSchema
	err := DecodeStrict([]byte(`{"policy":"a","audit_wal":null,"key":{"sock":"s"},"nonesuch":1}`), &v)
	if err == nil {
		t.Fatal("accepted an unknown field")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field reported by something other than the decoder: %v", err)
	}
}

// The existing contract has to survive intact, since these checks run before it.
func TestDecodeStrict_ExistingContractUnchanged(t *testing.T) {
	t.Run("a well-formed document still decodes", func(t *testing.T) {
		var v keysSchema
		doc := `{"comment":"c","policy":"a","audit_wal":"/w","key":{"sock":"s","keystore":"k"},"status":{"u":"f"}}`
		if err := DecodeStrict([]byte(doc), &v); err != nil {
			t.Fatalf("rejected a valid document: %v", err)
		}
		if v.Policy != "a" || v.Key.Sock != "s" || string(v.WAL) != `"/w"` {
			t.Fatalf("decoded to the wrong value: %+v", v)
		}
	})
	t.Run("trailing content is still refused", func(t *testing.T) {
		var v keysSchema
		doc := `{"policy":"a","audit_wal":null,"key":{"sock":"s"}} {"policy":"b"}`
		err := DecodeStrict([]byte(doc), &v)
		if err == nil || !strings.Contains(err.Error(), "unexpected content") {
			t.Fatalf("trailing content no longer refused: %v", err)
		}
	})
	t.Run("malformed JSON is left to the decoder to describe", func(t *testing.T) {
		var v keysSchema
		if err := DecodeStrict([]byte(`{"policy":`), &v); err == nil {
			t.Fatal("accepted truncated JSON")
		}
	})
	t.Run("a json:\"-\" field is not addressable by that name", func(t *testing.T) {
		var v keysSchema
		err := DecodeStrict([]byte(`{"policy":"a","audit_wal":null,"key":{"sock":"s"},"Ignored":"x"}`), &v)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("a dash-tagged field was addressable: %v", err)
		}
	})
}

// json.RawMessage carries whatever it is given, so its contents are not fields to
// be name-checked. Duplicates inside it are still the document's problem though,
// which is the distinction structTarget draws by stopping at json.Unmarshaler.
func TestDecodeStrict_RawMessageIsOpaqueToNamesButNotToDuplicates(t *testing.T) {
	type rawSchema struct {
		Raw json.RawMessage `json:"raw"`
	}
	t.Run("a key that would be a variant of nothing is fine inside it", func(t *testing.T) {
		var v rawSchema
		if err := DecodeStrict([]byte(`{"raw":{"Anything":1,"anything":2}}`), &v); err != nil {
			t.Fatalf("name-checked inside an opaque value: %v", err)
		}
	})
	t.Run("a duplicate inside it is still refused", func(t *testing.T) {
		var v rawSchema
		err := DecodeStrict([]byte(`{"raw":{"a":1,"a":2}}`), &v)
		if err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("duplicate inside a raw value was accepted: %v", err)
		}
	})
}
