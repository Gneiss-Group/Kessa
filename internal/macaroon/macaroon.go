// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package macaroon implements attenuation-first delegation: a bearer credential
// whose authority can only ever be NARROWED as it is handed down a chain, never
// broadened, and which carries a tamper-evident HMAC chain proving that.
//
// The design follows the macaroon paper's construction, a root HMAC key seeds
// a signature, and each caveat re-keys the HMAC with the previous signature, so
// no party downstream can add authority without invalidating the chain. Kessa
// adds one thing on top: caveats are STRUCTURED (field / operator / value)
// rather than opaque strings, which lets Attenuate mechanically reject a caveat
// that would broaden authority, and lets the independent verifier re-check that
// each hop is a strict subset of its parent.
//
// This package is a leaf: it reaches the standard library and internal/scalar,
// which is itself stdlib-only, so the standalone verifier can import it without
// dragging in any server code. Verify takes a plain Context (map[string]string),
// not a types.Action, on purpose.
package macaroon

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/scalar"
)

// Op is a caveat comparison operator.
type Op string

const (
	OpEq Op = "==" // string or scalar equality
	OpNe Op = "!=" // string or scalar inequality
	OpLe Op = "<=" // scalar/time upper bound (inclusive)
	OpLt Op = "<"  // scalar/time upper bound (exclusive)
	OpGe Op = ">=" // scalar/time lower bound (inclusive)
	OpGt Op = ">"  // scalar/time lower bound (exclusive)
	OpIn Op = "in" // membership: Value is a comma-separated set
)

// Caveat is a single restriction on authority. It constrains one Field of the
// action context (e.g. "amount", "action.type", "target", "expiry").
type Caveat struct {
	Field string
	Op    Op
	Value string
}

// Macaroon is an attenuation-first bearer credential.
type Macaroon struct {
	Location   string   // issuing context (informational)
	Identifier string   // root key id / credential id
	Caveats    []Caveat // each caveat only RESTRICTS authority
	Signature  []byte   // HMAC chain over the caveats
}

// Context is the set of concrete values an action presents at verification time,
// keyed by caveat Field. Kept as a plain map so this package stays free of any
// dependency on pkg/types.
type Context map[string]string

// ---- construction & delegation -------------------------------------------

// Mint creates a root macaroon with no caveats. rootKey is the issuer's secret
// HMAC key for this credential id; it is never embedded in the macaroon.
func Mint(rootKey []byte, identifier, location string) Macaroon {
	return Macaroon{
		Location:   location,
		Identifier: identifier,
		Signature:  hmacSum(rootKey, []byte(identifier)),
	}
}

// Attenuate returns a NEW macaroon with one additional caveat. It never mutates
// its input. The caveat must NARROW authority: if it constrains a field an
// existing caveat already constrains, it must be a strict subset of that
// existing constraint. A broadening (or incomparable) caveat is rejected, this
// is the property step 3 exists to guarantee.
func Attenuate(m Macaroon, c Caveat) (Macaroon, error) {
	if err := c.validate(); err != nil {
		return Macaroon{}, err
	}
	for _, existing := range m.Caveats {
		if existing.Field != c.Field {
			continue
		}
		ok, err := narrows(existing, c)
		if err != nil {
			return Macaroon{}, fmt.Errorf("macaroon: cannot attenuate %q against %q: %w", c, existing, err)
		}
		if !ok {
			return Macaroon{}, fmt.Errorf("macaroon: caveat %q does not narrow existing caveat %q", c, existing)
		}
	}
	caveats := make([]Caveat, len(m.Caveats), len(m.Caveats)+1)
	copy(caveats, m.Caveats)
	caveats = append(caveats, c)
	return Macaroon{
		Location:   m.Location,
		Identifier: m.Identifier,
		Caveats:    caveats,
		Signature:  hmacSum(m.Signature, c.canonical()),
	}, nil
}

// Extends reports (via a nil error) that m is a valid attenuation of parent:
// the same macaroon, further narrowed. Concretely: same Identifier, parent's
// caveats are a prefix of m's, and every additional caveat only narrows
// authority. This is the structural, key-free subset check the delegation-chain
// resolver and the independent verifier use to confirm each hop restricts, and
// never broadens, its parent's authority. It deliberately does NOT check the
// HMAC signature (the verifier holds no root key).
func (m Macaroon) Extends(parent Macaroon) error {
	if m.Identifier != parent.Identifier {
		return fmt.Errorf("macaroon: identifier mismatch (%q vs parent %q)", m.Identifier, parent.Identifier)
	}
	if len(m.Caveats) < len(parent.Caveats) {
		return fmt.Errorf("macaroon: child has fewer caveats (%d) than parent (%d)", len(m.Caveats), len(parent.Caveats))
	}
	for i := range parent.Caveats {
		if m.Caveats[i] != parent.Caveats[i] {
			return fmt.Errorf("macaroon: child diverges from parent at caveat %d", i)
		}
	}
	// Each caveat added beyond the parent's prefix must narrow the authority
	// accumulated so far, the same rule Attenuate enforces at delegation time.
	acc := make([]Caveat, len(parent.Caveats))
	copy(acc, parent.Caveats)
	for _, c := range m.Caveats[len(parent.Caveats):] {
		if err := c.validate(); err != nil {
			return err
		}
		for _, e := range acc {
			if e.Field != c.Field {
				continue
			}
			ok, err := narrows(e, c)
			if err != nil {
				return fmt.Errorf("macaroon: added caveat %q incomparable to %q: %w", c, e, err)
			}
			if !ok {
				return fmt.Errorf("macaroon: added caveat %q broadens %q", c, e)
			}
		}
		acc = append(acc, c)
	}
	return nil
}

// ---- verification ---------------------------------------------------------

// Verify recomputes the HMAC chain from rootKey and confirms it matches the
// macaroon's signature (integrity), then confirms every caveat is satisfied by
// ctx (authority). Any failure returns a descriptive error; nil means the bearer
// is authorized for the action described by ctx.
//
// NOT ON ANY LIVE PATH, and structurally cannot be (round 2). Verify needs the
// macaroon root key, and neither the proxy nor the independent verifier holds
// one: the root key stays with the minting issuer, which is what lets the whole
// system be re-verified offline from public DID documents alone. Both live paths
// therefore call Satisfies, and the caveats' integrity comes from the issuer's
// Ed25519 issuance signature instead, which, since R2-01, covers the entire
// credential including the macaroon and every one of its caveats.
//
// So this is not dead code awaiting wiring; it is the issuer-side check, kept
// because an issuer holding its own root key can meaningfully run it, and used by
// this package's and internal/credential's tests. Wiring it into enforcement or
// verification would require shipping the root key to parties that must not have
// it, and would catch nothing the issuance signature does not already catch.
//
// It was previously cited in internal/credential's package doc as one of two
// active holder-binding defenses. That claim was wrong, nothing ever called this
// , and has been corrected there rather than left standing next to code that does
// not run. The property it claimed still holds, for the reason given above.
func Verify(m Macaroon, rootKey []byte, ctx Context) error {
	sig := hmacSum(rootKey, []byte(m.Identifier))
	for _, c := range m.Caveats {
		sig = hmacSum(sig, c.canonical())
	}
	if !hmac.Equal(sig, m.Signature) {
		return errors.New("macaroon: signature mismatch (tampered or wrong root key)")
	}
	return Satisfies(m, ctx)
}

// Satisfies checks that every caveat is satisfied by ctx, WITHOUT verifying the
// HMAC chain. This is what the independent verifier uses: it holds no root key,
// so it cannot call Verify, but it can and must re-run caveat satisfaction
// against the action recorded in an audit entry.
//
// Skipping the HMAC here is not a weakening. The caveats' integrity is
// established by other means the verifier *can* check offline: the issuer's
// Ed25519 issuance signature covers the macaroon's caveats (internal/chain), and
// the audit entry's hash-covered credential ID binds the entry to that exact
// credential. Verify and Satisfies share this one implementation so enforcement
// and verification can never disagree about what a caveat set permits.
func Satisfies(m Macaroon, ctx Context) error {
	for _, c := range m.Caveats {
		if err := c.satisfied(ctx); err != nil {
			return err
		}
	}
	return nil
}

// satisfied reports whether ctx meets this caveat. A missing field fails closed.
func (c Caveat) satisfied(ctx Context) error {
	got, ok := ctx[c.Field]
	if !ok {
		return fmt.Errorf("macaroon: caveat %q unsatisfied: context has no %q", c, c.Field)
	}
	fail := fmt.Errorf("macaroon: caveat %q unsatisfied: %s=%q", c, c.Field, got)
	switch c.Op {
	case OpEq:
		if got == c.Value {
			return nil
		}
	case OpNe:
		if got != c.Value {
			return nil
		}
	case OpLe, OpLt, OpGe, OpGt:
		gs, ok1 := scalar.Parse(got)
		vs, ok2 := scalar.Parse(c.Value)
		if !ok1 || !ok2 {
			return fmt.Errorf("macaroon: caveat %q unsatisfied: %q or %q not a scalar", c, got, c.Value)
		}
		if compareOK(c.Op, gs, vs) {
			return nil
		}
	case OpIn:
		for _, member := range splitSet(c.Value) {
			if got == member {
				return nil
			}
		}
	}
	return fail
}

// ---- narrowing lattice ----------------------------------------------------

// narrows reports whether child is a strict-subset restriction of parent, i.e.
// every context that satisfies child also satisfies parent. Both caveats
// constrain the same field. Anything it cannot prove to be narrowing returns
// false (fail closed), so Attenuate rejects it.
func narrows(parent, child Caveat) (bool, error) {
	switch parent.Op {
	case OpLe, OpLt, OpGe, OpGt:
		return narrowsBound(parent, child)
	case OpEq:
		// The only subset of "== v" is "== v" itself.
		return child.Op == OpEq && child.Value == parent.Value, nil
	case OpNe:
		// Conservatively, only an identical "!= v" is a provable subset.
		return child.Op == OpNe && child.Value == parent.Value, nil
	case OpIn:
		return narrowsSet(parent, child)
	default:
		return false, fmt.Errorf("unsupported parent operator %q", parent.Op)
	}
}

// narrowsBound handles a parent that is a scalar/time bound.
func narrowsBound(parent, child Caveat) (bool, error) {
	pv, ok := scalar.Parse(parent.Value)
	if !ok {
		return false, fmt.Errorf("parent value %q is not a scalar", parent.Value)
	}
	parentUpper := parent.Op == OpLe || parent.Op == OpLt

	switch child.Op {
	case OpLe, OpLt, OpGe, OpGt:
		cv, ok := scalar.Parse(child.Value)
		if !ok {
			return false, fmt.Errorf("child value %q is not a scalar", child.Value)
		}
		childUpper := child.Op == OpLe || child.Op == OpLt
		if parentUpper != childUpper {
			// Opposite-direction bounds constrain different ends; a lower bound
			// is never a subset of an upper bound (or vice versa).
			return false, nil
		}
		if parentUpper {
			return boundSubset(child.Op, cv, parent.Op, pv, true), nil
		}
		return boundSubset(child.Op, cv, parent.Op, pv, false), nil
	case OpEq:
		// "== v" is a subset of a bound iff v satisfies the bound.
		cv, ok := scalar.Parse(child.Value)
		if !ok {
			return false, nil
		}
		return compareOK(parent.Op, cv, pv), nil
	case OpIn:
		// Every member must satisfy the parent bound.
		for _, m := range splitSet(child.Value) {
			cv, ok := scalar.Parse(m)
			if !ok || !compareOK(parent.Op, cv, pv) {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

// boundSubset reports whether the child bound is contained in the parent bound,
// both being upper bounds (upper=true) or both lower bounds (upper=false).
func boundSubset(childOp Op, childVal scalar.Value, parentOp Op, parentVal scalar.Value, upper bool) bool {
	cmp, ordered := childVal.Compare(parentVal)
	if !ordered {
		// Nothing can be proved about a bound that does not order (a NaN
		// endpoint), so it is not a subset. Attenuate rejects it.
		return false
	}
	childInclusive := childOp == OpLe || childOp == OpGe
	parentInclusive := parentOp == OpLe || parentOp == OpGe
	if cmp == 0 {
		// equal bounds: subset unless child includes the endpoint the parent
		// excludes.
		return !childInclusive || parentInclusive
	}
	if upper {
		// child ⊆ parent iff child's sup <= parent's sup.
		return cmp < 0
	}
	// lower bounds: child ⊆ parent iff child's inf >= parent's inf.
	return cmp > 0
}

// narrowsSet handles a parent that is a set membership caveat.
func narrowsSet(parent, child Caveat) (bool, error) {
	set := make(map[string]bool)
	for _, m := range splitSet(parent.Value) {
		set[m] = true
	}
	switch child.Op {
	case OpEq:
		return set[child.Value], nil
	case OpIn:
		for _, m := range splitSet(child.Value) {
			if !set[m] {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

// ---- helpers --------------------------------------------------------------

func (c Caveat) validate() error {
	if strings.TrimSpace(c.Field) == "" {
		return errors.New("macaroon: caveat has empty field")
	}
	switch c.Op {
	case OpEq, OpNe, OpIn:
		if c.Value == "" {
			return fmt.Errorf("macaroon: caveat %q has empty value", c)
		}
	case OpLe, OpLt, OpGe, OpGt:
		if _, ok := scalar.Parse(c.Value); !ok {
			return fmt.Errorf("macaroon: caveat %q bound value %q is not a scalar", c, c.Value)
		}
	default:
		return fmt.Errorf("macaroon: caveat %q has unknown operator %q", c, c.Op)
	}
	return nil
}

// canonical is the byte serialization hashed into the HMAC chain. It must be
// deterministic and unambiguous; a unit separator (0x1f) keeps fields from
// colliding across values.
func (c Caveat) canonical() []byte {
	return []byte(c.Field + "\x1f" + string(c.Op) + "\x1f" + c.Value)
}

// String renders the human-readable predicate, used in errors and (later) in
// audit output.
func (c Caveat) String() string {
	return fmt.Sprintf("%s %s %s", c.Field, c.Op, c.Value)
}

func hmacSum(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// compareOK reports whether "got op want" holds, for the four ordering
// operators. The semantics are internal/scalar's, which internal/policy applies
// to the same field vocabulary: a caveat and a policy condition written over one
// field must not be able to reach different answers about it.
func compareOK(op Op, got, want scalar.Value) bool {
	return got.Satisfies(scalar.Op(op), want)
}

func splitSet(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
