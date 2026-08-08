// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package macaroon

import (
	"testing"
)

// This package has no Parse function, so the untrusted input is not a byte
// stream: it is the CAVEAT VALUES, which arrive inside a credential minted by
// somebody upstream and are compared by a lattice this package implements by
// hand. That lattice is where the authority guarantee actually lives, and it is
// arithmetic over parsed scalars with inclusive and exclusive endpoints, sets,
// and an RFC3339-or-float value grammar. It is exactly the kind of code a table
// of examples tests thinly and a fuzzer tests properly.
//
// Two properties, both of which the package documents about itself:
//
//  1. SOUNDNESS OF narrows. If narrows(parent, child) says the child is a
//     subset, then every context satisfying the child must satisfy the parent.
//     A false positive here is authority BROADENING through a hop that claims
//     to be an attenuation, which is the one thing the whole construction
//     exists to make impossible.
//
//  2. Attenuate AND Extends AGREE. Attenuate runs at delegation time on the
//     issuer, Extends runs at verification time in a verifier that holds no
//     root key. They apply "the same rule" by intent. If they can disagree, a
//     credential is minted that the independent verifier then refuses, and the
//     split is between two parties who cannot compare notes.

// The operator and value shapes both targets seed from: both
// endpoint kinds on both directions of bound, sets, the RFC3339 branch of the
// value grammar, and the float literals that make the comparison arithmetic
// interesting (negative zero, infinities, NaN, exponent forms).
var (
	fuzzOps    = []string{"==", "!=", "<=", "<", ">=", ">", "in", "", "=", "IN"}
	fuzzValues = []string{
		"100", "100.0", "99", "101", "0", "-0", "-1",
		"1e309", "Inf", "-Inf", "NaN", "0x10",
		"2026-07-09T12:00:00Z", "2026-07-09T12:00:00+01:00",
		"a,b,c", "a, b", "a", ",", " ", "",
	}
)

// FuzzNarrowsIsSound searches for a parent and child caveat on one field where
// narrows claims containment that the satisfaction check does not honour.
func FuzzNarrowsIsSound(f *testing.F) {
	for _, op := range fuzzOps {
		for _, v := range fuzzValues {
			f.Add("amount", op, v, op, v, "100")
		}
	}
	// The bound-endpoint cases, where inclusive against exclusive decides it.
	f.Add("amount", "<=", "100", "<", "100", "100")
	f.Add("amount", "<", "100", "<=", "100", "100")
	f.Add("amount", ">=", "0", ">", "0", "0")
	f.Add("amount", "<=", "100", "==", "100", "100")
	f.Add("amount", "in", "a,b", "==", "a", "a")
	f.Add("amount", "in", "a,b", "in", "a", "a")
	f.Add("expiry", "<=", "2026-07-09T12:00:00Z", "<=", "2026-07-08T12:00:00Z", "2026-07-01T00:00:00Z")

	f.Fuzz(func(t *testing.T, field, parentOp, parentValue, childOp, childValue, ctxValue string) {
		// One field for both: narrows is only ever consulted for caveats that
		// constrain the same field, so a pair on different fields is not a case
		// this function has an opinion about.
		parent := Caveat{Field: field, Op: Op(parentOp), Value: parentValue}
		child := Caveat{Field: field, Op: Op(childOp), Value: childValue}
		if parent.validate() != nil || child.validate() != nil {
			return
		}

		ok, err := narrows(parent, child)
		if err != nil || !ok {
			// Anything narrows cannot prove is refused by Attenuate, which is
			// the fail-closed direction and not a defect.
			return
		}

		// narrows has asserted that child is a subset of parent. So there must
		// be no context that satisfies the child and not the parent.
		ctx := Context{field: ctxValue}
		if child.satisfied(ctx) == nil && parent.satisfied(ctx) != nil {
			t.Fatalf("narrows(%q, %q) claimed the child is a subset, but %s=%q satisfies the child and not the parent (%v)",
				parent, child, field, ctxValue, parent.satisfied(ctx))
		}
	})
}

// FuzzAttenuateAgreesWithExtends drives the public delegation API: mint, two
// attenuation hops, then check what the issuer produced against what a
// key-free verifier would accept.
func FuzzAttenuateAgreesWithExtends(f *testing.F) {
	f.Add("cred-1", "amount", "<=", "100", "amount", "<=", "50", "50")
	f.Add("cred-1", "amount", "<=", "100", "amount", "==", "100", "100")
	f.Add("cred-1", "action.type", "in", "a,b", "action.type", "==", "a", "a")
	f.Add("cred-1", "amount", "<=", "100", "target", "==", "acct/999", "100")
	f.Add("cred-1", "expiry", "<=", "2026-07-09T12:00:00Z", "expiry", "<", "2026-07-09T12:00:00Z", "2026-07-01T00:00:00Z")
	f.Add("", "", "", "", "", "", "", "")

	rootKey := []byte("fuzz-root-key-not-a-secret")

	f.Fuzz(func(t *testing.T, identifier, f1, o1, v1, f2, o2, v2, ctxValue string) {
		m0 := Mint(rootKey, identifier, "fuzz")

		c1 := Caveat{Field: f1, Op: Op(o1), Value: v1}
		m1, err := Attenuate(m0, c1)
		if err != nil {
			return
		}
		c2 := Caveat{Field: f2, Op: Op(o2), Value: v2}
		m2, err := Attenuate(m1, c2)
		if err != nil {
			return
		}

		// 1. Attenuate never mutates its input. The copy in Attenuate is what
		//    stops two delegation chains built from one parent from sharing a
		//    backing array, where appending to one would rewrite the other's
		//    caveat in place and leave a signature that no longer covers its own
		//    caveat list.
		if len(m0.Caveats) != 0 {
			t.Fatalf("Attenuate mutated the root macaroon: %v", m0.Caveats)
		}
		if len(m1.Caveats) != 1 || m1.Caveats[0] != c1 {
			t.Fatalf("Attenuate mutated its input: m1 caveats are %v, expected [%v]", m1.Caveats, c1)
		}

		// 2. THE AGREEMENT PROPERTY. Attenuate accepted these hops at delegation
		//    time, so Extends must accept them at verification time. A
		//    disagreement means the issuer mints a credential the independent
		//    verifier refuses, and neither party can see the other's reasoning.
		for _, tc := range []struct {
			name          string
			child, parent Macaroon
		}{
			{"m1 over m0", m1, m0},
			{"m2 over m1", m2, m1},
			{"m2 over m0", m2, m0},
		} {
			if err := tc.child.Extends(tc.parent); err != nil {
				t.Fatalf("Attenuate produced %s but Extends refuses it: %v\n  c1=%v c2=%v", tc.name, err, c1, c2)
			}
		}

		// 3. The HMAC chain covers what was actually attenuated, so the macaroon
		//    the issuer holds verifies against the root key it minted from.
		if err := Verify(m2, rootKey, satisfyingContext(m2, ctxValue)); err != nil {
			// Verify also runs caveat satisfaction, so an unsatisfied caveat is
			// an expected outcome here. Only an integrity failure is a defect.
			if err.Error() == "macaroon: signature mismatch (tampered or wrong root key)" {
				t.Fatalf("a macaroon built entirely by Attenuate failed its own signature check: c1=%v c2=%v", c1, c2)
			}
		}

		// 4. TAMPER EVIDENCE. Dropping the last caveat while keeping the
		//    signature is the forgery that matters: it is how a bearer would
		//    shed a restriction. The signature is chained, so the shortened
		//    caveat list must no longer reproduce it.
		stripped := Macaroon{
			Location:   m2.Location,
			Identifier: m2.Identifier,
			Caveats:    m2.Caveats[:1],
			Signature:  m2.Signature,
		}
		if err := Verify(stripped, rootKey, Context{}); err == nil {
			t.Fatalf("Verify accepted a macaroon with its last caveat removed: c1=%v c2=%v", c1, c2)
		}

		// 5. Rewriting a caveat in place must break the chain too. Skipped when
		//    the rewrite is not actually a change, which is not a forgery.
		if c2.Value != c1.Value {
			edited := Macaroon{
				Location:   m2.Location,
				Identifier: m2.Identifier,
				Caveats:    []Caveat{m2.Caveats[0], {Field: c2.Field, Op: c2.Op, Value: c1.Value}},
				Signature:  m2.Signature,
			}
			if err := Verify(edited, rootKey, Context{}); err == nil {
				t.Fatalf("Verify accepted a macaroon whose second caveat was rewritten: c1=%v c2=%v", c1, c2)
			}
		}
	})
}

// satisfyingContext offers one value under every field the macaroon constrains.
// It is not trying to satisfy the caveats, only to reach the satisfaction code
// rather than stopping at the first missing field.
func satisfyingContext(m Macaroon, value string) Context {
	ctx := Context{}
	for _, c := range m.Caveats {
		ctx[c.Field] = value
	}
	return ctx
}
