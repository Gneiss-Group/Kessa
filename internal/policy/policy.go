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
	"strconv"
	"strings"
	"time"

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
		if _, ok := asScalar(c.Value); !ok {
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
		if r.matches(ctx) {
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

// matches reports whether every condition holds.
func (r Rule) matches(ctx map[string]string) bool {
	for _, c := range r.When {
		if !c.matches(ctx) {
			return false
		}
	}
	return true
}

func (c Condition) matches(ctx map[string]string) bool {
	got, ok := ctx[c.Field]
	if !ok {
		return false // absent field never matches (fail closed)
	}
	switch c.Op {
	case OpEq:
		return got == c.Value
	case OpNe:
		return got != c.Value
	case OpLe, OpLt, OpGe, OpGt:
		gs, ok1 := asScalar(got)
		vs, ok2 := asScalar(c.Value)
		if !ok1 || !ok2 {
			return false
		}
		switch c.Op {
		case OpLe:
			return gs <= vs
		case OpLt:
			return gs < vs
		case OpGe:
			return gs >= vs
		case OpGt:
			return gs > vs
		}
	case OpIn:
		for _, m := range strings.Split(c.Value, ",") {
			if got == strings.TrimSpace(m) {
				return true
			}
		}
	}
	return false
}

// asScalar parses s as an RFC3339 time (as Unix nanoseconds) or a float, so the
// ordering operators work on both amounts and timestamps.
func asScalar(s string) (float64, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return float64(t.UnixNano()), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	return 0, false
}
