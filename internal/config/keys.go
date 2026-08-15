// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// checkKeys walks a JSON document alongside the type it is about to be decoded
// into, refusing two shapes encoding/json resolves without complaint.
//
// WHY A SECOND PASS EXISTS AT ALL. DisallowUnknownFields is the only strictness
// the decoder offers, and it answers exactly one question: was this key matched
// to a field? Both shapes below answer yes, so the decoder is satisfied and the
// resulting value is still not the one a reader of the file would predict.
//
//   - A DUPLICATE key resolves last-wins, silently. Nothing in the decoder's model
//     treats a repeated key as remarkable.
//   - A DIFFERENTLY-CASED key is matched case-insensitively when no exact match
//     has already been consumed, so it is not an "unknown field" and never reaches
//     the unknown-field check. It can also SHADOW a correctly-cased key above it,
//     which is the shape worth naming: the file visibly states one value and the
//     process runs with another.
//
// Both are refused here rather than documented, because this package's contract
// is already that a config which parses is the config that was reviewed, and the
// reason recorded for the unknown-field rule applies unchanged to these two: the
// wrong thing looks exactly like the right thing.
//
// THE TWO RULES HAVE DIFFERENT SCOPES, deliberately. Duplicates are refused
// EVERYWHERE, including inside maps, because a repeated key is malformed on the
// document's own terms and needs no schema to judge. Case-variants are refused
// only where the target is a struct, because that is where an exact field name
// exists to compare against; a map's keys are arbitrary by construction and two
// keys differing by case are two different, legitimate keys.
func checkKeys(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkValue(dec, reflect.TypeOf(v), "")
}

// walkValue consumes exactly one JSON value, descending with the type it is
// expected to decode into. A nil or unusable type means "keep checking
// duplicates, stop checking names", which is how maps, interfaces and types with
// their own UnmarshalJSON are handled.
func walkValue(dec *json.Decoder, t reflect.Type, path string) error {
	tok, err := dec.Token()
	if err != nil {
		// Malformed or truncated JSON. Not this function's error to report: the
		// real decode runs next and produces the message the caller expects.
		return nil //nolint:nilerr // deliberate, see comment
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar, already consumed
	}
	switch d {
	case '{':
		return walkObject(dec, structTarget(t), path)
	case '[':
		elem := elemType(t)
		for dec.More() {
			if err := walkValue(dec, elem, path+"[]"); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return err
	}
	return nil
}

// walkObject consumes the body of one JSON object. t, when non-nil, is the struct
// this object decodes into and is what makes the case check possible.
func walkObject(dec *json.Decoder, t reflect.Type, path string) error {
	var fields map[string]reflect.Type
	if t != nil {
		fields = jsonFields(t)
	}
	seen := make(map[string]bool)

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil //nolint:nilerr // leave malformed input to the real decode
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		at := key
		if path != "" {
			at = path + "." + key
		}

		if seen[key] {
			return fmt.Errorf("duplicate key %q: JSON resolves a repeated key to its LAST value, "+
				"so the file states one thing and would be read as another", at)
		}
		seen[key] = true

		var next reflect.Type
		if fields != nil {
			ft, exact := fields[key]
			switch {
			case exact:
				next = ft
			default:
				// Not an exact field name. If some field matches apart from case, the
				// decoder would take it: that is the shape DisallowUnknownFields cannot
				// see, because such a key is not unknown to it. If nothing matches at
				// all the key IS unknown, and reporting it here would duplicate the
				// decoder's own message in different words, so it is left alone.
				if want, isVariant := caseVariantOf(fields, key); isVariant {
					return fmt.Errorf("key %q differs from field %q only by case: "+
						"encoding/json would match it anyway, so it sets that field without ever "+
						"being an unknown one, and it silently overrides a correctly-cased key", at, want)
				}
			}
		}
		if err := walkValue(dec, next, at); err != nil {
			return err
		}
	}
	_, err := dec.Token() // '}'
	return err
}

// structTarget reduces t to the struct it will decode into, or nil when names
// cannot be checked against it.
//
// It stops at any type implementing json.Unmarshaler. Such a type decides for
// itself what its keys mean, so the fields reflect reports about it are not the
// names the decoder will actually match. json.RawMessage is the case in this
// repository: it is a []byte that swallows whatever it is given.
func structTarget(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		if implementsUnmarshaler(t) {
			return nil
		}
		t = t.Elem()
	}
	if t == nil || implementsUnmarshaler(t) {
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil // a map, an interface, anything without fixed field names
	}
	return t
}

func implementsUnmarshaler(t reflect.Type) bool {
	var u *json.Unmarshaler
	iface := reflect.TypeOf(u).Elem()
	if t.Implements(iface) {
		return true
	}
	return t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(iface)
}

// elemType is the type a JSON array's elements decode into, or nil when that
// cannot be determined.
func elemType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return nil
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return t.Elem()
	}
	return nil
}

// jsonFields maps the exact key each of t's fields is matched by, to that field's
// type.
//
// It follows encoding/json's own rules rather than approximating them: the name
// comes from the json tag when present and the field name otherwise, a "-" tag
// means the field is not addressable by any key, unexported fields are invisible,
// and an embedded struct's fields are flattened into the parent. Getting the
// flattening wrong in either direction would matter: too few names and a real
// field reads as a case-variant, too many and a genuinely unknown key does.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type)
	collectJSONFields(t, out)
	return out
}

func collectJSONFields(t reflect.Type, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue // unexported
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && !strings.HasPrefix(tag, "-,") {
			continue
		}
		if name == "" {
			// An embedded struct with no tag is flattened by encoding/json: its
			// fields are matched at this level, not under the field's own name.
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if f.Anonymous && ft.Kind() == reflect.Struct {
				collectJSONFields(ft, out)
				continue
			}
			name = f.Name
		}
		out[name] = f.Type
	}
}

// caseVariantOf reports the field name key differs from only by case, if there is
// one. The search is the decoder's own fallback: an exact match is tried first by
// the caller, and only then does case-insensitive matching apply.
func caseVariantOf(fields map[string]reflect.Type, key string) (string, bool) {
	for name := range fields {
		if strings.EqualFold(name, key) {
			return name, true
		}
	}
	return "", false
}
