// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package scalar is the one implementation of the ordering semantics that
// macaroon caveat satisfaction and policy rule evaluation are both written
// against.
//
// pkg/types.Action.Context() is the single source of truth for the FIELD
// VOCABULARY those two share, and its doc comment says why that has to be one
// function: the enforcement proxy decides with it and the independent verifier
// re-derives that decision with it, so if the two ever read an action
// differently, the verifier could pass an action the proxy denied. Deciding what
// "amount <= 100" or "expiry < 2026-07-09T12:00:00Z" MEANS carries exactly the
// same requirement one level up, and until this package existed it was a
// byte-identical copy of a function called asScalar in each of internal/policy
// and internal/macaroon, with nothing holding the two together. Their agreement
// was a property of two files happening to match, and correcting one of them
// alone is a silent split between the proxy's verdict and the verifier's. That
// is what this package replaces.
//
// # Timestamps are compared as exact integer nanoseconds
//
// Both copies parsed an RFC3339 timestamp to float64(t.UnixNano()). A 2026
// instant is about 1.78e18, which needs 61 bits against float64's 53-bit
// mantissa, so the representable values were 256ns apart and any two instants
// inside one of those windows compared equal. Action contexts carry expiry at
// full RFC3339Nano precision, so the lost digits were real ones. Nothing
// observable was wrong, because both copies lost the same bits in the same
// place, which is precisely the reassurance a shared implementation makes
// unnecessary.
//
// A timestamp outside the window where time.Time.UnixNano is defined (roughly
// 1678 to 2262, beyond which it silently wraps) is refused rather than
// compared. Both callers coerce a bound while validating it, before it is stored
// in a policy or hashed into a caveat chain, so such a bound is rejected where
// it is written rather than mis-compared later where it is used.
//
// # A timestamp and a number are still ordered, and exactly
//
// Comparing an expiry against 100 is nonsense, but it is nonsense the callers
// permit, since any field may carry any value, so it needs an answer. The answer
// is the numeric one it has always been: the instant's nanosecond count against
// the number. It is computed exactly instead of by widening the nanoseconds back
// to float64, and exactness here is not fastidiousness. macaroon.narrows is
// sound only while the order it reasons about is the order that caveat
// satisfaction later applies, and an order that is exact on instants, exact on
// numbers, and lossy between them is not transitive: two instants a nanosecond
// apart would order correctly against each other while both comparing equal to
// one number, which is enough for narrows to claim a containment that
// satisfaction then refuses.
package scalar

import (
	"math"
	"strconv"
	"time"
)

// Op is an ordering comparison. The four operators are spelled identically in
// policy conditions and in macaroon caveats; each package converts its own
// operator type to this one rather than restating what the operators mean.
type Op string

const (
	OpLe Op = "<="
	OpLt Op = "<"
	OpGe Op = ">="
	OpGt Op = ">"
)

// Value is a parsed scalar: either an instant, held as exact nanoseconds since
// the Unix epoch, or a number.
type Value struct {
	nanos  int64
	num    float64
	isTime bool
}

// The instants time.Time.UnixNano can represent. Outside this window it is
// documented as undefined and in practice wraps, so a bound written there would
// compare as an arbitrary instant rather than the far-future one its author
// meant.
var (
	minUnixNano = time.Unix(0, math.MinInt64)
	maxUnixNano = time.Unix(0, math.MaxInt64)
)

// Parse coerces s to a comparable value, reporting false for anything that is
// neither an instant nor a number. RFC3339 is tried first so that
// "2026-07-09T00:00:00Z" cannot be read as a number.
func Parse(s string) (Value, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		if t.Before(minUnixNano) || t.After(maxUnixNano) {
			return Value{}, false
		}
		return Value{nanos: t.UnixNano(), isTime: true}, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		// An infinity is refused however it is SPELLED, which is a consistency
		// fix rather than a new rule. "1e400" was already refused, because
		// ParseFloat reports ErrRange for it while still handing back +Inf, and
		// the reason recorded for that was that a bound nobody can write down is
		// not a bound. "Inf", "-Infinity" and the rest are the same value reached
		// by a spelling ParseFloat accepts without complaint, so refusing one and
		// taking the other was the same bound being both rejected and honoured.
		//
		// It also closes a fail-open, which is what actually forced the question.
		// An infinity ORDERS against everything, so an action attribute of "-Inf"
		// satisfied any upper bound: against the shipped allow-list policy,
		// amount="-Inf" matched the `amount <= 25` routine rule and was classified
		// NOT consequential, skipping the approval gate that a plain 26 correctly
		// triggers. Attributes come from the proxied request and the agent is the
		// untrusted party, so that was reachable input, not a curiosity.
		//
		// NaN is deliberately NOT refused here. It is the opposite shape: it
		// orders against nothing, so it already fails closed, and Compare is where
		// "unordered" belongs. Refusing it here would leave that path unreachable
		// through Parse and turn a live, tested guard into dead code.
		if math.IsInf(f, 0) {
			return Value{}, false
		}
		return Value{num: f}, true
	}
	return Value{}, false
}

// Satisfies reports whether "v op w" holds. An unknown operator and an unordered
// pair both report false, so every caller fails closed without restating that
// choice.
func (v Value) Satisfies(op Op, w Value) bool {
	cmp, ok := v.Compare(w)
	if !ok {
		return false
	}
	switch op {
	case OpLe:
		return cmp <= 0
	case OpLt:
		return cmp < 0
	case OpGe:
		return cmp >= 0
	case OpGt:
		return cmp > 0
	}
	return false
}

// Compare orders v against w as -1, 0 or +1. The second result is false when the
// two are not ordered at all, which happens only when one of them is NaN: a
// caller that treats "not ordered" as "the comparison does not hold" gets the
// float64 behaviour it would have had from a bare < or >.
func (v Value) Compare(w Value) (int, bool) {
	switch {
	case v.isTime && w.isTime:
		return cmpInt64(v.nanos, w.nanos), true
	case v.isTime:
		return cmpInt64Float(v.nanos, w.num)
	case w.isTime:
		cmp, ok := cmpInt64Float(w.nanos, v.num)
		return -cmp, ok
	default:
		return cmpFloat64(v.num, w.num)
	}
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpFloat64(a, b float64) (int, bool) {
	switch {
	case math.IsNaN(a) || math.IsNaN(b):
		return 0, false
	case a < b:
		return -1, true
	case a > b:
		return 1, true
	}
	return 0, true
}

// twoPow63 is one past the largest int64, and is exactly representable as a
// float64, so the comparison against it is not itself a rounding.
const twoPow63 float64 = 1 << 63

// cmpInt64Float orders an integer against a float without converting either to
// the other's type, which is the only way to keep the two exact where their
// ranges overlap: above 2^53 a float64 conversion of n would round, and int64
// cannot hold f's fraction.
func cmpInt64Float(n int64, f float64) (int, bool) {
	switch {
	case math.IsNaN(f):
		return 0, false
	case f >= twoPow63: // includes +Inf: beyond every int64
		return -1, true
	case f < -twoPow63: // includes -Inf
		return 1, true
	}
	// |f| is now below 2^63, so its integer part converts to int64 exactly, and
	// what the truncation dropped decides any tie on the integers.
	whole := math.Trunc(f)
	if cmp := cmpInt64(n, int64(whole)); cmp != 0 {
		return cmp, true
	}
	switch frac := f - whole; {
	case frac > 0:
		return -1, true
	case frac < 0:
		return 1, true
	}
	return 0, true
}
