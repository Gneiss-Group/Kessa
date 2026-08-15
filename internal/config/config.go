// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package config holds the mechanics every Kessa binary shares when it takes a
// --config file: strict loading, and the derivation of which flags a schema
// displaces.
//
// It deliberately holds no schema. Each command declares its own struct and its
// own validation, because what is required, and what an absent field means, is a
// question about that command rather than about JSON. What lives here is the part
// that must not be implemented twice.
//
// WHY NOT TWICE. `cmd/issuer` carried its own copy of the `Keystore` type and its
// own copy of `Signer`, differing only in the wording of two error strings, and
// the cost surfaced later: a fix to one was invisible to the other, and the
// daemon spent months unable to load a keystore the proxy read fine. The rules
// below (an unknown field is an error; a flag is refused if the schema names it;
// "explicitly set" means Visit and never a comparison against defaults) are
// exactly the kind that decay when there are two copies, because the second copy
// is the one nobody remembers.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
)

// Load reads path and decodes it strictly into v, which must be a pointer to a
// schema struct. It performs no side effects beyond reading the file.
//
// Strict means an unknown field is an ERROR. A config that silently ignored a
// misspelled field would report success while the process ran under a setting the
// operator believed they had changed, and the failure would be invisible because
// the wrong thing looks exactly like the right thing.
func Load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	if err := DecodeStrict(data, v); err != nil {
		return fmt.Errorf("parse config %q: %w", path, err)
	}
	return nil
}

// DecodeStrict decodes one JSON document from data into v, rejecting unknown
// fields and trailing content. It adds no context to its errors: the caller knows
// what the file is and names it.
//
// Split out from Load because the issuer's spec and keystore files want the same
// strictness under different words. They are not configs, and "parse config
// %q: ..." pointed at a spec file would be a message that misnames what the
// operator was editing. Sharing the mechanism while leaving the wording to the
// caller is the alternative to a second copy that drifts, which is the failure
// this package's doc comment already records.
//
// NOTE ON MAPS. DisallowUnknownFields governs decoding into STRUCTS. A map type
// has no unknown fields by construction, so calling this on one is legal and
// buys nothing for NAMES. It still gets the duplicate-key check below, which
// needs no schema: a repeated key is malformed on the document's own terms. What
// it does not get is the case check, because a map's keys are arbitrary and two
// keys differing by case are two different, legitimate keys. See the keystore,
// where a "_comment" entry is a legitimate map key and no decoder setting would
// ever have caught the bug that internal/keystore.Principals exists to fix.
//
// TWO SHAPES THE DECODER CANNOT SEE are refused by checkKeys before the decode
// runs: a duplicate key, which resolves last-wins, and a differently-cased key,
// which encoding/json matches anyway and which is therefore never an unknown
// field. Both let a file state one value and be read as another, which is the
// same failure the unknown-field rule exists to prevent, reached by a spelling
// the decoder does not classify as unknown. See keys.go.
//
// It runs FIRST, before the decode, so a file carrying one of these shapes is
// refused rather than half-applied. The alternative, checking afterwards, would
// mean the caller had already been handed a populated value by the time it was
// told the file was ambiguous.
func DecodeStrict(data []byte, v any) error {
	if err := checkKeys(data, v); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Trailing content means the file is not the single object it claims to be,
	// e.g. two concatenated objects where only the first would ever be read.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected content after the top-level object")
	}
	return nil
}

// FlagNames returns every CLI flag name a schema can express, read from the
// `flag` struct tags on it and on any struct it nests.
//
// The DERIVATION is the point. It makes "a flag is refused alongside --config if
// and only if the schema covers it" a property of the schema rather than of a
// list kept beside it. A hand-maintained list fails permissively: a field added
// later stays silently overridable until someone remembers to update it, and
// nothing complains in the meantime.
//
// A field with no `flag` tag is outside the schema on purpose and stays usable
// alongside --config. That is how the proxy keeps --now available: it is a
// determinism fixture for reproducible runs, and it appears in no schema.
//
// schema may be a struct or a pointer to one.
func FlagNames(schema any) map[string]bool {
	t := reflect.TypeOf(schema)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]bool{}
	if t == nil || t.Kind() != reflect.Struct {
		return out
	}
	collect(t, out)
	return out
}

func collect(t reflect.Type, out map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if name := f.Tag.Get("flag"); name != "" {
			out[name] = true
		}
		// Recurse into nested schema structs, so a tag on a grouped field is found
		// too. Only structs: json.RawMessage, slices and maps are terminals that
		// carry their own tag.
		if f.Type.Kind() == reflect.Struct {
			collect(f.Type, out)
		}
	}
}

// Conflicting returns the flags that were EXPLICITLY SET on fs and are also named
// by covered, sorted.
//
// It uses fs.Visit, which walks only the flags actually provided. Comparing each
// flag's value against its default is the obvious alternative and it is wrong in
// the permissive direction: a flag passed at its own default value reads as
// unset, and a boolean passed as false is indistinguishable from unset by value,
// so both would slip past the refusal entirely.
func Conflicting(fs *flag.FlagSet, covered map[string]bool) []string {
	var bad []string
	fs.Visit(func(f *flag.Flag) {
		if covered[f.Name] {
			bad = append(bad, f.Name)
		}
	})
	sort.Strings(bad)
	return bad
}
