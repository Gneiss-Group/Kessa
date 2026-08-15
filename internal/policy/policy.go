// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package policy externalizes the consequentiality decision: given an action, it
// decides whether the action is consequential (and therefore demands a live
// status check plus human approval) and whether it is outright denied. Crucially,
// "consequential" is environment-defined, the same action can be routine in one
// deployment and consequential in another, which is why policies are loaded from
// versioned config files and the version is recorded in every audit entry.
//
// This is the zero-dependency Option B from spec §5: a minimal rule evaluator
// over the action's fields, no OPA/Rego. The Evaluator interface is deliberately
// shaped so a real OPA-backed evaluator can drop in later without touching the
// proxy.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/scalar"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Field names in a condition map onto an action via types.Action.Context(), the
// single canonical flattening shared with macaroon caveat satisfaction. These
// alias the reserved names; any other field resolves against Action.Attributes.
const (
	FieldActionType = types.FieldActionType
	FieldTarget     = types.FieldTarget
	FieldExpiry     = types.FieldExpiry

	// DefaultRule is the RuleFired value when no rule matches.
	DefaultRule = "default"
)

// Evaluator is the seam that lets Option A (OPA/Rego) replace Option B later.
type Evaluator interface {
	// Evaluate classifies an action, returning a Decision with Allowed,
	// Consequential, RuleFired, Reason, and PolicyVersion set. StatusChecked is
	// left false, that is the enforcement point's concern, not policy's.
	Evaluate(a types.Action) (types.Decision, error)
	Version() string
}

// Op is a condition comparison operator (mirrors the macaroon caveat operators).
type Op string

const (
	OpEq Op = "=="
	OpNe Op = "!="
	OpLe Op = "<="
	OpLt Op = "<"
	OpGe Op = ">="
	OpGt Op = ">"
	OpIn Op = "in" // Value is a comma-separated set; the field must be a member
)

// Condition is one comparison against an action field.
type Condition struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

// Rule fires when ALL of its conditions match (logical AND). Rules are evaluated
// top to bottom and the first match wins, so order deny/consequential rules by
// priority.
type Rule struct {
	Name          string      `json:"name"`
	When          []Condition `json:"when"`
	Deny          bool        `json:"deny,omitempty"`
	Consequential bool        `json:"consequential,omitempty"`
	Reason        string      `json:"reason"`
}

// Default is the outcome when no rule matches. It is the whole of a deployment's
// POSTURE: deny-list is {Allowed: true, Consequential: false} (routine unless a
// rule says otherwise), allow-list is {Allowed: true, Consequential: true}
// (approval-gated unless a rule says routine). See the package README.
type Default struct {
	Allowed       bool   `json:"allowed"`
	Consequential bool   `json:"consequential"`
	Reason        string `json:"reason"`
}

// Policy is a versioned, ordered set of rules for one environment. It implements
// Evaluator. (The version field is named Ver so the Version() method, required
// by Evaluator, can coexist with it.)
type Policy struct {
	Ver     string  `json:"version"`
	Rules   []Rule  `json:"rules"`
	Default Default `json:"default"`

	// defaultPresent records whether the decoded JSON actually carried a "default"
	// block. Without it an omitted default is indistinguishable from an explicit
	// zero value, and an omitted one means deny-everything-with-no-reason, which
	// is a silent footgun rather than a stated posture. Validate requires it.
	//
	// It is deliberately UNEXPORTED: encoding/json ignores it in both directions,
	// so a policy's serialized bytes, and therefore its content address
	// (export.PolicyID) and every envelope signature over it, are unchanged.
	defaultPresent bool
}

// UnmarshalJSON decodes a policy and records whether a "default" block was
// present, which the plain struct decoding cannot express.
//
// Keep the field list below in sync with Policy above; it is spelled out rather
// than derived via a type alias so the "default"-presence handling stays obvious.
func (p *Policy) UnmarshalJSON(data []byte) error {
	var raw struct {
		Ver     string   `json:"version"`
		Rules   []Rule   `json:"rules"`
		Default *Default `json:"default"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Ver = raw.Ver
	p.Rules = raw.Rules
	p.Default = Default{}
	p.defaultPresent = raw.Default != nil
	if raw.Default != nil {
		p.Default = *raw.Default
	}
	return nil
}

var _ Evaluator = (*Policy)(nil)

// Load reads and validates a policy from a JSON file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: load %q: %w", path, err)
	}
	return Parse(data)
}

// Parse reads and validates a policy from JSON.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate reports whether the policy is well-formed.
//
// It is EXPORTED because two independent paths need exactly these rules: Parse,
// when a proxy loads a policy file at startup, and export.Parse, when the
// verifier reads the policy carried inside a signed export. Sharing one function
// is what stops a policy the proxy would have rejected from being silently
// accepted at verification time, the two must never disagree about whether a
// policy is meaningful.
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.Ver) == "" {
		return fmt.Errorf("policy: missing version")
	}
	// An absent default is not a neutral omission: Evaluate would fall through to
	// the zero value and deny every unmatched action with an empty reason. A
	// deployment's posture must be stated, not inferred.
	if !p.defaultPresent {
		return fmt.Errorf("policy %s: missing required \"default\" block", p.Ver)
	}
	if strings.TrimSpace(p.Default.Reason) == "" {
		return fmt.Errorf("policy %s: default.reason must not be empty", p.Ver)
	}
	for i, r := range p.Rules {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("policy %s: rule %d has no name", p.Ver, i)
		}
		if len(r.When) == 0 {
			return fmt.Errorf("policy %s: rule %q has no conditions", p.Ver, r.Name)
		}
		for _, c := range r.When {
			if err := c.validate(); err != nil {
				return fmt.Errorf("policy %s: rule %q: %w", p.Ver, r.Name, err)
			}
		}
		// A rule's reason is required for the same reason the default's is, one
		// level down. When a rule fires, Evaluate copies r.Reason straight into
		// the Decision, and that Decision is written verbatim into a signed,
		// hash-chained audit entry. Without this, a policy can be accepted that
		// records an ALLOW on a consequential action whose stated cause is the
		// empty string: an entry that verifies perfectly and explains nothing.
		//
		// Checked AFTER the conditions so a rule that is wrong in both ways is
		// reported by the more specific complaint (a typo'd operator) rather than
		// by this one.
		//
		// Found by this package's FuzzParse, which asserts that Evaluate always
		// returns a stated reason. The default block's version of this rule was
		// already here; nobody had applied the same argument to rules.
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("policy %s: rule %q has no reason", p.Ver, r.Name)
		}
	}
	return nil
}

func (c Condition) validate() error {
	if strings.TrimSpace(c.Field) == "" {
		return fmt.Errorf("condition has empty field")
	}
	switch c.Op {
	case OpEq, OpNe, OpIn:
		if c.Value == "" {
			return fmt.Errorf("condition %q %q has empty value", c.Field, c.Op)
		}
	case OpLe, OpLt, OpGe, OpGt:
		if _, ok := scalar.Parse(c.Value); !ok {
			return fmt.Errorf("condition %q %q value %q is not a scalar", c.Field, c.Op, c.Value)
		}
	default:
		return fmt.Errorf("condition %q has unknown operator %q", c.Field, c.Op)
	}
	return nil
}

// Version returns the policy version, recorded in every audit entry.
func (p *Policy) Version() string { return p.Ver }

// Evaluate applies the rules top to bottom; the first matching rule decides.
//
// NOTE: Evaluate is a CLASSIFIER, not an authorization decision. It sets Allowed
// from policy rules alone (including a default-allow branch) and knows nothing
// of macaroon caveats, revocation status, or proof-of-possession. The enforcement
// proxy must compose this with those checks before writing Decision.Allowed into
// an audit entry, the independent verifier re-checks all three for every
// allowed entry and will fail any entry where they do not hold.
func (p *Policy) Evaluate(a types.Action) (types.Decision, error) {
	ctx := a.Context()
	for _, r := range p.Rules {
		matched, indeterminate := r.eval(ctx)
		// A rule that could not be evaluated DENIES, and it does so before any later
		// rule or the default gets a chance to answer. An action carrying a value
		// this rule cannot compare has not been classified, and the two ways of
		// pretending otherwise are both wrong: treating it as a match invents an
		// answer, and treating it as a non-match hands it to whatever comes next,
		// which under a routine default is the permissive outcome.
		//
		// Denying is the only answer that is right whichever way the policy is
		// written, which is what makes it safe to give here, where the posture is
		// not in view. It is also the answer the independent verifier re-derives,
		// since it runs this same function over the recorded action.
		if indeterminate {
			return types.Decision{
				Allowed:       false,
				Consequential: true,
				RuleFired:     r.Name,
				PolicyVersion: p.Ver,
				Reason: fmt.Sprintf("rule %q could not be evaluated: %s is not comparable",
					r.Name, indeterminateFields(r, ctx)),
			}, nil
		}
		if matched {
			return types.Decision{
				Allowed:       !r.Deny,
				Consequential: r.Consequential,
				RuleFired:     r.Name,
				PolicyVersion: p.Ver,
				Reason:        r.Reason,
			}, nil
		}
	}
	return types.Decision{
		Allowed:       p.Default.Allowed,
		Consequential: p.Default.Consequential,
		RuleFired:     DefaultRule,
		PolicyVersion: p.Ver,
		Reason:        p.Default.Reason,
	}, nil
}

// eval reports whether every condition holds, and whether any of them could not
// be evaluated at all.
//
// It does NOT stop at the first false condition. A rule that contains both a
// condition that does not hold and a condition that cannot be evaluated is
// indeterminate, and short-circuiting would make which of those two answers comes
// back depend on the order the conditions happen to be written in.
func (r Rule) eval(ctx map[string]string) (matched, indeterminate bool) {
	matched = true
	for _, c := range r.When {
		ok, ind := c.eval(ctx)
		if ind {
			indeterminate = true
		}
		if !ok {
			matched = false
		}
	}
	return matched && !indeterminate, indeterminate
}

// indeterminateFields names the fields of r that could not be evaluated against
// ctx, in the order the rule declares them.
//
// It names the FIELD and never the value. The value is attacker-supplied and this
// string is written into a signed, hash-chained audit entry that the verifier
// re-derives byte for byte; the action itself is already recorded alongside, so
// quoting it here would duplicate attacker-controlled text into a second place
// without adding anything a reader cannot already see. Rule-declaration order
// keeps the result deterministic, which re-derivation requires.
func indeterminateFields(r Rule, ctx map[string]string) string {
	var names []string
	for _, c := range r.When {
		if _, ind := c.eval(ctx); ind {
			names = append(names, c.Field)
		}
	}
	return strings.Join(names, ", ")
}

// eval reports whether the condition holds, and whether it could not be evaluated.
//
// THREE SITUATIONS, NOT TWO. A field the action does not carry, a field that is
// present and compares false, and a field that is present but cannot be compared
// at all are three different claims, and the last one needs its own answer.
//
// Collapsing the third into "does not hold" is only safe if a rule that does not
// fire is the cautious outcome, and whether that is true depends on what the
// surrounding policy uses its rules to say. A policy whose default is routine uses
// rules to mark things consequential, so a rule that does not fire is the
// PERMISSIVE outcome there, and an operand nobody can compare would quietly take
// it. Reporting indeterminate separately lets Evaluate answer that case the same
// way whichever way the policy is written, instead of inheriting the answer from
// the posture it happens to be run under.
//
// An ABSENT field stays a plain non-match, deliberately. "This rule does not apply
// to an action that carries no such field" is the whole truth about that case, and
// policies rely on it: a rule about `amount` should simply not apply to an action
// that has no amount.
func (c Condition) eval(ctx map[string]string) (ok, indeterminate bool) {
	got, present := ctx[c.Field]
	if !present {
		return false, false // absent field never matches (fail closed)
	}
	switch c.Op {
	case OpEq:
		return got == c.Value, false
	case OpNe:
		return got != c.Value, false
	case OpLe, OpLt, OpGe, OpGt:
		gs, ok1 := scalar.Parse(got)
		// c.Value is already known to parse: Condition.validate refuses an ordering
		// operator whose own bound is not a scalar, and Parse always calls Validate,
		// so a policy carrying one never reaches here. Checked anyway rather than
		// assumed, because the cost is one comparison and the alternative is a
		// panic-free silent wrong answer if that ever stops being true.
		vs, ok2 := scalar.Parse(c.Value)
		if !ok1 || !ok2 {
			return false, true
		}
		return gs.Satisfies(scalar.Op(c.Op), vs), false
	case OpIn:
		for _, m := range strings.Split(c.Value, ",") {
			// A member that trims to nothing is not a member. Dropping it matches
			// internal/macaroon.splitSet, which has always done so, and closes the
			// gap where "in" was not the same operator on the two sides of the same
			// field vocabulary.
			//
			// The reachable case is a trailing comma, which is an ordinary typo
			// rather than an exotic policy: "us,eu," used to put "" in the approved
			// set, so an action carrying region="" matched. Under allow-list posture
			// a rule declares something ROUTINE, so that match was the permissive
			// outcome and the action skipped the approval gate that region="cn"
			// correctly triggers.
			//
			// Consistent with a rule the schema already states, rather than a new
			// one: Condition.validate refuses "in" with an empty value outright, so
			// an empty member list is already meaningless. Honouring an empty member
			// INSIDE a list was the same concept accepted piecemeal.
			if m = strings.TrimSpace(m); m != "" && got == m {
				return true, false
			}
		}
	}
	return false, false
}
