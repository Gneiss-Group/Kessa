// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package scalar

import (
	"math"
	"strconv"
	"testing"
	"time"
)

func mustParse(t *testing.T, s string) Value {
	t.Helper()
	v, ok := Parse(s)
	if !ok {
		t.Fatalf("Parse(%q) refused a value the test needs", s)
	}
	return v
}

func TestParse_AcceptsInstantsAndNumbersAndNothingElse(t *testing.T) {
	cases := []struct {
		in     string
		accept bool
	}{
		{"2026-07-09T12:00:00Z", true},
		{"2026-07-09T12:00:00.000000100Z", true},
		{"2026-07-09T12:00:00+01:00", true},
		{"100", true},
		{"100.5", true},
		{"-0", true},
		{"1e18", true},
		{"NaN", true},   // parses; ordering it is a separate question, below
		{"", false},     //
		{"abc", false},  //
		{"0x10", false}, // ParseFloat's hex form needs a p exponent
		{"2026-07-09", false},
		// Out of float64's range, which ParseFloat reports as an error while
		// still handing back an infinity. Refusing it is the older behaviour,
		// kept: a bound nobody can write down is not a bound.
		{"1e400", false},
		// The same infinity reached by a spelling ParseFloat accepts WITHOUT an
		// error. These were taken while 1e400 was refused, so one bound was both
		// rejected and honoured depending on how it was written. Every spelling
		// ParseFloat knows is listed, because refusing "Inf" while taking
		// "Infinity" would just move the inconsistency rather than remove it.
		{"Inf", false},
		{"+Inf", false},
		{"-Inf", false},
		{"inf", false},
		{"Infinity", false},
		{"-infinity", false},
	}
	for _, tc := range cases {
		if _, ok := Parse(tc.in); ok != tc.accept {
			t.Errorf("Parse(%q) accepted=%v, want %v", tc.in, ok, tc.accept)
		}
	}
}

// TestParse_ReadsATimestampAsAnInstantNotANumber pins the ordering of the two
// branches. A timestamp cannot be read as a float today, so this is not
// currently load-bearing; it becomes load-bearing the moment the number branch
// is widened (to accept "1_000", say, or a leading +), and that is exactly the
// change that would not think to check.
func TestParse_ReadsATimestampAsAnInstantNotANumber(t *testing.T) {
	v := mustParse(t, "2026-07-09T12:00:00Z")
	if !v.isTime {
		t.Fatal("an RFC3339 timestamp must parse as an instant")
	}
}

// TestCompare_OrdersInstantsToTheNanosecond is the defect this package was
// hoisted to fix. Both copies of the old asScalar compared float64(UnixNano()),
// which at a 2026 epoch cannot represent two instants less than 256ns apart as
// different numbers.
func TestCompare_OrdersInstantsToTheNanosecond(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	later := base.Add(100 * time.Nanosecond)

	// Confirm the premise rather than assuming it: if float64 ever stops
	// collapsing these, this test passes without exercising the fix.
	if float64(base.UnixNano()) != float64(later.UnixNano()) {
		t.Fatal("premise no longer holds: float64 now distinguishes a 100ns delta at this epoch")
	}

	lo := mustParse(t, base.Format(time.RFC3339Nano))
	hi := mustParse(t, later.Format(time.RFC3339Nano))

	if cmp, ok := lo.Compare(hi); !ok || cmp != -1 {
		t.Fatalf("Compare(base, base+100ns) = (%d, %v), want (-1, true)", cmp, ok)
	}
	if cmp, ok := hi.Compare(lo); !ok || cmp != 1 {
		t.Fatalf("Compare(base+100ns, base) = (%d, %v), want (1, true)", cmp, ok)
	}
	if !lo.Satisfies(OpLt, hi) {
		t.Error("base < base+100ns must hold")
	}
	if lo.Satisfies(OpGe, hi) {
		t.Error("base >= base+100ns must not hold")
	}
}

// TestParse_RefusesAnInstantUnixNanoCannotRepresent covers the far-future bound
// a policy author reaches for to mean "never": UnixNano is undefined past 2262
// and wraps, so "9999-12-31T23:59:59Z" would otherwise compare as some arbitrary
// instant, quite possibly one already in the past.
func TestParse_RefusesAnInstantUnixNanoCannotRepresent(t *testing.T) {
	for _, s := range []string{"9999-12-31T23:59:59Z", "1600-01-01T00:00:00Z"} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) accepted an instant outside the representable range", s)
		}
	}
	// The edges themselves are representable and must still be accepted.
	for _, tm := range []time.Time{time.Unix(0, math.MinInt64), time.Unix(0, math.MaxInt64)} {
		s := tm.UTC().Format(time.RFC3339Nano)
		if _, ok := Parse(s); !ok {
			t.Errorf("Parse(%q) refused a representable endpoint", s)
		}
	}
}

// TestCompare_NaNIsUnorderedAndNoOperatorHolds keeps the fail-closed behaviour a
// bare float64 comparison used to give for free: every comparison against NaN is
// false, including NaN against itself.
func TestCompare_NaNIsUnorderedAndNoOperatorHolds(t *testing.T) {
	nan := mustParse(t, "NaN")
	for _, other := range []string{"NaN", "100", "2026-07-09T12:00:00Z"} {
		w := mustParse(t, other)
		if _, ok := nan.Compare(w); ok {
			t.Errorf("Compare(NaN, %q) claims an ordering", other)
		}
		if _, ok := w.Compare(nan); ok {
			t.Errorf("Compare(%q, NaN) claims an ordering", other)
		}
		for _, op := range []Op{OpLe, OpLt, OpGe, OpGt} {
			if nan.Satisfies(op, w) {
				t.Errorf("NaN %s %q holds", op, other)
			}
			if w.Satisfies(op, nan) {
				t.Errorf("%q %s NaN holds", other, op)
			}
		}
	}
}

func TestSatisfies_RefusesAnOperatorItDoesNotKnow(t *testing.T) {
	a, b := mustParse(t, "1"), mustParse(t, "2")
	for _, op := range []Op{"==", "!=", "in", "=<", ""} {
		if a.Satisfies(op, b) {
			t.Errorf("Satisfies accepted the unknown operator %q", op)
		}
	}
}

// TestCompare_OrdersAnInstantAgainstANumberWithoutRounding is the mixed-kind
// case. It is a nonsensical comparison to write, but any field may carry any
// value, so it has an answer, and that answer has to be exact for the same
// reason the instant-to-instant one does: see the package comment on why an
// order that is lossy only between the two kinds is not transitive.
func TestCompare_OrdersAnInstantAgainstANumberWithoutRounding(t *testing.T) {
	instant := time.Date(2026, 6, 1, 12, 0, 0, 100, time.UTC)
	nanos := instant.UnixNano()
	widened := float64(nanos)

	// Premise: widening this instant to float64 moves it. |widened| is far below
	// 2^63 and is already integral, so int64(widened) is an exact reading of it.
	if int64(widened) == nanos {
		t.Fatal("premise no longer holds: this instant survives a float64 round trip")
	}
	want := 1
	if int64(widened) > nanos {
		want = -1
	}

	v := mustParse(t, instant.Format(time.RFC3339Nano))
	w := mustParse(t, strconv.FormatFloat(widened, 'f', -1, 64))
	if cmp, ok := v.Compare(w); !ok || cmp != want {
		t.Fatalf("Compare(instant, its own float64 widening) = (%d, %v), want (%d, true)", cmp, ok, want)
	}
}

// TestParse_RefusesAnInfinityHoweverSpelled replaces a test that pinned the
// ordering of infinities against instants and numbers. That ordering was real
// and the test was correct about it; refusing the values is what changed, and
// the reason it changed is worth keeping next to the assertion.
//
// An infinity orders against everything, so "-Inf" sat below every upper bound.
// An action attribute spelled that way satisfied any "<=" or "<" condition, and
// against the shipped allow-list policy amount="-Inf" matched the `amount <= 25`
// ROUTINE rule and was classified not consequential, skipping the approval gate
// that a plain 26 correctly triggers. Attributes arrive on the proxied request
// and the agent is the untrusted party, so it was reachable input.
//
// internal/policy carries that end to end in
// TestEvaluate_InfinityCannotBypassARoutineRule. This is the same fact at the
// layer where the cause is, and it is a parse question rather than an ordering
// one: nothing downstream has to know about infinities, because none reach it.
func TestParse_RefusesAnInfinityHoweverSpelled(t *testing.T) {
	// Every spelling strconv.ParseFloat accepts without an error, plus the
	// overflow route that was already refused. Refusing one spelling while
	// taking another would move the inconsistency rather than remove it.
	for _, s := range []string{
		"Inf", "+Inf", "-Inf", "inf", "INF",
		"Infinity", "+Infinity", "-Infinity", "infinity", "-infinity",
		"1e400", "-1e400",
	} {
		if v, ok := Parse(s); ok {
			t.Errorf("Parse(%q) = (%+v, true), want refused", s, v)
		}
	}
}

// TestCompare_IsATotalOrder is the property macaroon.narrows rests on, so it is
// checked rather than argued. narrows decides containment by comparing two
// bounds, and caveat satisfaction later compares a context value against one of
// them; if those comparisons do not come from one consistent order, narrows can
// certify a child as a subset of its parent and satisfaction can then accept a
// context under the child that the parent refuses, which is authority
// broadening through a hop that claims to be an attenuation.
//
// The corpus deliberately mixes the two kinds, and includes instants close
// enough together that widening them to float64 would collapse them, which is
// the shape that made the old implementation intransitive across kinds.
func TestCompare_IsATotalOrder(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	corpus := []string{
		// The infinities that used to sit at the ends of this corpus are gone,
		// because Parse now refuses them and mustParse would fail. Their job here
		// was to be the extremes of the order; the two int64-boundary values below
		// do that within the range Parse still accepts.
		"0", "-0", "-1", "1", "100", "100.0", "100.5",
		"1e18", "1.7833968e18", "9223372036854775807", "9223372036854775808",
		base.Format(time.RFC3339Nano),
		base.Add(1 * time.Nanosecond).Format(time.RFC3339Nano),
		base.Add(100 * time.Nanosecond).Format(time.RFC3339Nano),
		base.Add(time.Hour).Format(time.RFC3339Nano),
		"1970-01-01T00:00:00Z",
	}
	vals := make([]Value, len(corpus))
	for i, s := range corpus {
		vals[i] = mustParse(t, s)
	}

	cmp := func(i, j int) int {
		c, ok := vals[i].Compare(vals[j])
		if !ok {
			t.Fatalf("Compare(%q, %q) is unordered; the corpus holds no NaN", corpus[i], corpus[j])
		}
		return c
	}

	for i := range vals {
		if c := cmp(i, i); c != 0 {
			t.Errorf("Compare(%q, itself) = %d, want 0", corpus[i], c)
		}
		for j := range vals {
			if c, r := cmp(i, j), cmp(j, i); c != -r {
				t.Errorf("Compare(%q, %q) = %d but the reverse is %d", corpus[i], corpus[j], c, r)
			}
			for k := range vals {
				ij, jk, ik := cmp(i, j), cmp(j, k), cmp(i, k)
				if ij <= 0 && jk <= 0 && ik > 0 {
					t.Errorf("not transitive: %q <= %q <= %q but %q > %q",
						corpus[i], corpus[j], corpus[k], corpus[i], corpus[k])
				}
				if ij == 0 && jk == 0 && ik != 0 {
					t.Errorf("equality is not transitive: %q == %q == %q but Compare(%q, %q) = %d",
						corpus[i], corpus[j], corpus[k], corpus[i], corpus[k], ik)
				}
			}
		}
	}
}
