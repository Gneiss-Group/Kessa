// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// FlagNames is the refused set, so a name it omits is a flag that stays usable
// alongside --config and silently overrides the reviewed file for that field.
// Every case here is therefore about a MISS being impossible, not about the map
// being tidy.

type inPointer struct {
	V string `json:"v" flag:"pointer-nested"`
}
type inSlice struct {
	V string `json:"v" flag:"slice-nested"`
}
type inArray struct {
	V string `json:"v" flag:"array-nested"`
}
type inMapValue struct {
	V string `json:"v" flag:"map-nested"`
}
type inValue struct {
	V string `json:"v" flag:"value-nested"`
	// One level deeper, to prove the walk does not stop at the first struct.
	Deeper *inPointer `json:"deeper"`
}

type nestedShapes struct {
	Direct  string                `json:"direct" flag:"direct"`
	ByValue inValue               `json:"by_value"`
	ByPtr   *inPointer            `json:"by_ptr"`
	InSlice []inSlice             `json:"in_slice"`
	InArray [2]inArray            `json:"in_array"`
	InMap   map[string]inMapValue `json:"in_map"`

	// Terminals: these must NOT be walked into, and must not blow up either.
	Raw    json.RawMessage   `json:"raw" flag:"raw"`
	Strs   map[string]string `json:"strs" flag:"strs"`
	Bytes  []byte            `json:"bytes"`
	NoFlag string            `json:"no_flag"`
}

func TestFlagNamesReachesEveryNestingShape(t *testing.T) {
	got := FlagNames(nestedShapes{})
	for _, want := range []string{
		"direct", "value-nested", "pointer-nested", "slice-nested",
		"array-nested", "map-nested", "raw", "strs",
	} {
		if !got[want] {
			t.Errorf("%q is missing, so --%s stays usable alongside --config and overrides the file", want, want)
		}
	}
	if got["no_flag"] {
		t.Error("a field with no flag tag must stay outside the schema")
	}
}

// The property the fixture above only samples: every `flag` tag anywhere in a
// schema tree appears in the result.
//
// The walker here is deliberately a SECOND implementation rather than a call into
// collect, because a test that reuses the code under test cannot disagree with
// it. It is written the dumbest way that works: visit everything, unwrap
// everything, remember nothing except which types have been seen.
func allFlagTags(t reflect.Type, seen map[reflect.Type]bool, out map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice ||
		t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if name := f.Tag.Get("flag"); name != "" {
			out[name] = true
		}
		allFlagTags(f.Type, seen, out)
	}
}

func TestFlagNamesMissesNoTagInTheTree(t *testing.T) {
	want := map[string]bool{}
	allFlagTags(reflect.TypeOf(nestedShapes{}), map[reflect.Type]bool{}, want)
	got := FlagNames(nestedShapes{})

	var missing []string
	for name := range want {
		if !got[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("tags present in the schema tree but absent from the refused set: %s", strings.Join(missing, ", "))
	}
	// The other direction too: a name the schema does not carry would refuse a
	// flag for no reason, which breaks a legitimate invocation.
	for name := range got {
		if !want[name] {
			t.Errorf("FlagNames invented %q, which no tag in the tree names", name)
		}
	}
}

// A schema that refers to itself is a hang rather than a wrong answer, and a hang
// at startup is indistinguishable from a daemon that is simply slow to boot.
func TestFlagNamesTerminatesOnASelfReferentialSchema(t *testing.T) {
	type recursive struct {
		Name string      `json:"name" flag:"recursive-name"`
		Next *recursive  `json:"next"`
		More []recursive `json:"more"`
	}
	done := make(chan map[string]bool, 1)
	go func() { done <- FlagNames(recursive{}) }()
	select {
	case got := <-done:
		if !got["recursive-name"] {
			t.Error("the tag on a self-referential schema was not collected")
		}
	case <-t.Context().Done():
		t.Fatal("FlagNames did not terminate on a self-referential schema")
	}
}

func TestFlagNamesHandlesNonStructInput(t *testing.T) {
	for _, v := range []any{nil, "string", 42, map[string]string{}, []int{}} {
		if n := len(FlagNames(v)); n != 0 {
			t.Errorf("FlagNames(%T) returned %d names, want 0", v, n)
		}
	}
	// A pointer to a schema is documented as accepted.
	if !FlagNames(&nestedShapes{})["direct"] {
		t.Error("FlagNames must accept a pointer to a schema")
	}
}
