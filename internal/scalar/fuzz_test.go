// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package scalar

import "testing"

// FuzzCompareIsATotalOrder searches for three values whose ordering is
// inconsistent.
//
// TestCompare_IsATotalOrder checks the same property over a corpus somebody
// wrote down, which can only cover the shapes that somebody thought of. This is
// the arithmetic that decides whether one caveat is contained in another
// (macaroon.narrows) and, separately, whether a context value satisfies a caveat.
// Those two are only guaranteed to agree while the order underneath them is a
// consistent one, and it is an order over two representations at once, integer
// nanoseconds and float64, which is exactly where an inconsistency hides from a
// hand-written case list.
//
// A false claim here is authority broadening through a hop that presents itself
// as an attenuation, which is the property the whole construction exists to
// make impossible, so it is searched for rather than argued.
func FuzzCompareIsATotalOrder(f *testing.F) {
	seeds := []string{
		"100", "100.0", "-0", "0", "-1", "Inf", "-Inf", "NaN", "1e18",
		"9223372036854775807", "1.7833968e18",
		"2026-06-01T12:00:00Z",
		"2026-06-01T12:00:00.000000001Z",
		"2026-06-01T12:00:00.000000100Z",
		"1970-01-01T00:00:00Z",
		"", "abc",
	}
	for _, a := range seeds {
		for _, b := range seeds {
			f.Add(a, b, "100")
		}
	}

	f.Fuzz(func(t *testing.T, as, bs, cs string) {
		a, aok := Parse(as)
		b, bok := Parse(bs)
		c, cok := Parse(cs)
		if !aok || !bok || !cok {
			// A value that does not coerce is refused by both callers before
			// any comparison happens, so it is not a case this has an opinion
			// about.
			return
		}

		ab, abOrdered := a.Compare(b)
		ba, baOrdered := b.Compare(a)

		// Ordering is symmetric in whether it exists at all, and antisymmetric
		// in its result. Without this, "a <= b" and "b >= a" could disagree,
		// and narrows and satisfaction do read the pair in opposite directions.
		if abOrdered != baOrdered {
			t.Fatalf("Compare(%q, %q) is ordered=%v but the reverse is ordered=%v", as, bs, abOrdered, baOrdered)
		}
		if !abOrdered {
			return
		}
		if ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", as, bs, ab, bs, as, ba)
		}
		if as == bs && ab != 0 {
			t.Fatalf("Compare(%q, itself) = %d", as, ab)
		}

		bc, bcOrdered := b.Compare(c)
		ac, acOrdered := a.Compare(c)
		if !bcOrdered || !acOrdered {
			// c is a NaN, which orders against nothing, including itself.
			return
		}
		if ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q, but Compare(%q, %q) = %d", as, bs, cs, as, cs, ac)
		}
		if ab == 0 && bc == 0 && ac != 0 {
			t.Fatalf("equality is not transitive: %q == %q == %q, but Compare(%q, %q) = %d", as, bs, cs, as, cs, ac)
		}
	})
}
