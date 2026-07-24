// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package macaroon

import (
	"bytes"
	"testing"
)

var rootKey = []byte("root-secret-key-for-tests-000000")

func mustAttenuate(t *testing.T, m Macaroon, c Caveat) Macaroon {
	t.Helper()
	out, err := Attenuate(m, c)
	if err != nil {
		t.Fatalf("Attenuate(%v): %v", c, err)
	}
	return out
}

func TestMintAndVerify_NoCaveats(t *testing.T) {
	m := Mint(rootKey, "cred-1", "did:web:localhost:orgs:acme")
	if err := Verify(m, rootKey, Context{}); err != nil {
		t.Fatalf("fresh macaroon should verify: %v", err)
	}
	// Wrong root key must fail.
	if err := Verify(m, []byte("wrong-key-wrong-key-wrong-key-00"), Context{}); err == nil {
		t.Fatal("verify accepted the wrong root key")
	}
}

func TestAttenuate_NarrowsAndVerifies(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"action.type", OpEq, "payment.transfer"})
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "1000"})
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"}) // strictly narrower

	// A below-threshold transfer is authorized.
	ok := Context{"action.type": "payment.transfer", "amount": "50"}
	if err := Verify(m, rootKey, ok); err != nil {
		t.Fatalf("in-scope action should verify: %v", err)
	}

	// $500 exceeds the attenuated $100 ceiling → blocked (scenario 2).
	over := Context{"action.type": "payment.transfer", "amount": "500"}
	if err := Verify(m, rootKey, over); err == nil {
		t.Fatal("action above the attenuated ceiling should fail")
	}

	// Wrong action type → blocked.
	wrong := Context{"action.type": "post.publish", "amount": "10"}
	if err := Verify(m, rootKey, wrong); err == nil {
		t.Fatal("action of the wrong type should fail")
	}
}

func TestAttenuate_RejectsBroadening(t *testing.T) {
	base := Mint(rootKey, "cred-1", "acme")
	base = mustAttenuate(t, base, Caveat{"amount", OpLe, "100"})

	cases := []struct {
		name   string
		caveat Caveat
	}{
		{"looser upper bound", Caveat{"amount", OpLe, "500"}},
		{"exclusive vs inclusive at same bound is fine, but higher is not", Caveat{"amount", OpLt, "1000"}},
		{"opposite direction bound", Caveat{"amount", OpGe, "50"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Attenuate(base, tc.caveat); err == nil {
				t.Fatalf("Attenuate should reject broadening caveat %v", tc.caveat)
			}
		})
	}
}

func TestAttenuate_BoundEdgeCases(t *testing.T) {
	base := Mint(rootKey, "cred-1", "acme")
	base = mustAttenuate(t, base, Caveat{"amount", OpLe, "100"})

	// <= 100 narrowing to < 100 is allowed (excludes the endpoint).
	if _, err := Attenuate(base, Caveat{"amount", OpLt, "100"}); err != nil {
		t.Fatalf("`< 100` should narrow `<= 100`: %v", err)
	}
	// <= 100 to <= 100 (equal, inclusive both) is allowed (subset, redundant).
	if _, err := Attenuate(base, Caveat{"amount", OpLe, "100"}); err != nil {
		t.Fatalf("`<= 100` should be a subset of `<= 100`: %v", err)
	}

	// Now start from an exclusive bound: < 100. Narrowing to <= 100 must be
	// rejected because it re-admits the endpoint 100.
	excl := Mint(rootKey, "cred-1", "acme")
	excl = mustAttenuate(t, excl, Caveat{"amount", OpLt, "100"})
	if _, err := Attenuate(excl, Caveat{"amount", OpLe, "100"}); err == nil {
		t.Fatal("`<= 100` should NOT be a subset of `< 100` (re-admits endpoint)")
	}
}

func TestAttenuate_FreshFieldAlwaysAllowed(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"})
	// A caveat on a brand-new field only adds restriction; always allowed.
	if _, err := Attenuate(m, Caveat{"target", OpEq, "repo/foo"}); err != nil {
		t.Fatalf("fresh-field caveat should be allowed: %v", err)
	}
}

func TestAttenuate_SetAndEquality(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"action.type", OpIn, "post.publish, post.draft, comment.create"})

	// Narrow the set to a single equality within the set → allowed.
	if _, err := Attenuate(m, Caveat{"action.type", OpEq, "post.publish"}); err != nil {
		t.Fatalf("== within set should narrow: %v", err)
	}
	// Narrow to a subset → allowed.
	if _, err := Attenuate(m, Caveat{"action.type", OpIn, "post.publish, post.draft"}); err != nil {
		t.Fatalf("subset should narrow: %v", err)
	}
	// Equality to a value NOT in the set → rejected (would broaden).
	if _, err := Attenuate(m, Caveat{"action.type", OpEq, "payment.transfer"}); err == nil {
		t.Fatal("== outside the set should be rejected")
	}
	// A superset → rejected.
	if _, err := Attenuate(m, Caveat{"action.type", OpIn, "post.publish, payment.transfer"}); err == nil {
		t.Fatal("superset should be rejected")
	}
}

func TestVerify_TimeBoundExpiry(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"expiry", OpLt, "2026-07-09T00:00:00Z"})

	before := Context{"expiry": "2026-07-08T12:00:00Z"}
	if err := Verify(m, rootKey, before); err != nil {
		t.Fatalf("action before expiry should verify: %v", err)
	}
	after := Context{"expiry": "2026-07-10T12:00:00Z"}
	if err := Verify(m, rootKey, after); err == nil {
		t.Fatal("action after expiry should fail")
	}
}

func TestVerify_MissingContextFieldFailsClosed(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"})
	if err := Verify(m, rootKey, Context{}); err == nil {
		t.Fatal("missing context field should fail closed")
	}
}

func TestAttenuate_DoesNotMutateOriginal(t *testing.T) {
	parent := Mint(rootKey, "cred-1", "acme")
	parent = mustAttenuate(t, parent, Caveat{"amount", OpLe, "1000"})
	parentSig := bytes.Clone(parent.Signature)
	parentCaveats := len(parent.Caveats)

	child := mustAttenuate(t, parent, Caveat{"amount", OpLe, "100"})

	if len(parent.Caveats) != parentCaveats {
		t.Fatal("Attenuate mutated the parent's caveat slice")
	}
	if !bytes.Equal(parent.Signature, parentSig) {
		t.Fatal("Attenuate mutated the parent's signature")
	}
	if bytes.Equal(child.Signature, parent.Signature) {
		t.Fatal("child and parent share a signature")
	}
	// Parent still verifies at its own (broader) authority.
	if err := Verify(parent, rootKey, Context{"amount": "500"}); err != nil {
		t.Fatalf("parent should still verify independently: %v", err)
	}
}

func TestVerify_TamperedSignatureFails(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"})
	m.Signature[0] ^= 0xff
	if err := Verify(m, rootKey, Context{"amount": "10"}); err == nil {
		t.Fatal("tampered signature should fail verification")
	}
}

func TestVerify_TamperedCaveatFails(t *testing.T) {
	// An attacker edits a caveat value without re-deriving the HMAC chain.
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"})
	m.Caveats[0].Value = "100000" // try to raise the ceiling
	if err := Verify(m, rootKey, Context{"amount": "50000"}); err == nil {
		t.Fatal("editing a caveat without re-chaining should break the signature")
	}
}

// TestSatisfies_IsKeyFreeAndAgreesWithVerify documents the enforcement/verifier
// split: Verify checks the HMAC chain AND caveat satisfaction (the proxy holds
// the root key); Satisfies checks only caveat satisfaction (the independent
// verifier holds no root key). They share one satisfaction implementation, so
// they can never disagree about what a caveat set permits.
func TestSatisfies_IsKeyFreeAndAgreesWithVerify(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	m = mustAttenuate(t, m, Caveat{"amount", OpLe, "100"})

	inScope := Context{"amount": "50"}
	outOfScope := Context{"amount": "500"}

	// Satisfies needs no root key, and agrees with Verify on authority.
	if err := Satisfies(m, inScope); err != nil {
		t.Fatalf("in-scope action should satisfy: %v", err)
	}
	if err := Satisfies(m, outOfScope); err == nil {
		t.Fatal("out-of-scope action must not satisfy")
	}
	if err := Verify(m, rootKey, inScope); err != nil {
		t.Fatalf("Verify disagrees with Satisfies on an in-scope action: %v", err)
	}
	if err := Verify(m, rootKey, outOfScope); err == nil {
		t.Fatal("Verify disagrees with Satisfies on an out-of-scope action")
	}

	// Satisfies deliberately does NOT check the HMAC; Verify does. Caveat
	// integrity is established for the verifier by the issuance signature and
	// the entry's hash-covered credential ID, not by the HMAC.
	tampered := m
	tampered.Signature = bytes.Repeat([]byte{0xAA}, 32)
	if err := Satisfies(tampered, inScope); err != nil {
		t.Fatalf("Satisfies must ignore the HMAC signature: %v", err)
	}
	if err := Verify(tampered, rootKey, inScope); err == nil {
		t.Fatal("Verify must reject a tampered HMAC signature")
	}
}

func TestExtends(t *testing.T) {
	parent := Mint(rootKey, "cred-1", "acme")
	parent = mustAttenuate(t, parent, Caveat{"action.type", OpEq, "payment.transfer"})
	parent = mustAttenuate(t, parent, Caveat{"amount", OpLe, "1000"})

	// A genuine further-attenuated child extends the parent.
	child := mustAttenuate(t, parent, Caveat{"amount", OpLe, "100"})
	if err := child.Extends(parent); err != nil {
		t.Fatalf("valid attenuation should extend parent: %v", err)
	}
	// A macaroon extends itself (zero added caveats).
	if err := parent.Extends(parent); err != nil {
		t.Fatalf("macaroon should extend itself: %v", err)
	}

	t.Run("different identifier", func(t *testing.T) {
		other := Mint(rootKey, "cred-2", "acme")
		other = mustAttenuate(t, other, Caveat{"action.type", OpEq, "payment.transfer"})
		other = mustAttenuate(t, other, Caveat{"amount", OpLe, "1000"})
		other = mustAttenuate(t, other, Caveat{"amount", OpLe, "100"})
		if err := other.Extends(parent); err == nil {
			t.Fatal("different identifier should not extend")
		}
	})

	t.Run("fewer caveats", func(t *testing.T) {
		if err := parent.Extends(child); err == nil {
			t.Fatal("parent has fewer caveats than child; should not extend it")
		}
	})

	t.Run("diverging prefix", func(t *testing.T) {
		diverged := Mint(rootKey, "cred-1", "acme")
		diverged = mustAttenuate(t, diverged, Caveat{"action.type", OpEq, "post.publish"}) // differs at caveat 0
		diverged = mustAttenuate(t, diverged, Caveat{"amount", OpLe, "1000"})
		if err := diverged.Extends(parent); err == nil {
			t.Fatal("diverging prefix should not extend")
		}
	})

	t.Run("broadening added caveat", func(t *testing.T) {
		// Hand-construct a child that appends a broadening caveat (Attenuate
		// would refuse to build this).
		bad := parent
		bad.Caveats = append(append([]Caveat{}, parent.Caveats...), Caveat{"amount", OpLe, "5000"})
		if err := bad.Extends(parent); err == nil {
			t.Fatal("a broadening added caveat must not count as extending")
		}
	})
}

func TestAttenuate_InvalidCaveatRejected(t *testing.T) {
	m := Mint(rootKey, "cred-1", "acme")
	cases := []Caveat{
		{"", OpEq, "x"},               // empty field
		{"amount", "≤", "100"},        // unknown op
		{"amount", OpLe, "not-a-num"}, // non-scalar bound
		{"action.type", OpEq, ""},     // empty value
	}
	for _, c := range cases {
		if _, err := Attenuate(m, c); err == nil {
			t.Fatalf("expected invalid caveat %v to be rejected", c)
		}
	}
}
