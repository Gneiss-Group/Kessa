// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package opaeval

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/policy"
)

// regoPackage is the package the generated module declares, and therefore the
// prefix of the query the evaluator asks for.
const regoPackage = "kessa.policy"

// decisionQuery is the single value the generated module exists to produce.
const decisionQuery = "data." + regoPackage + ".decision"

// compileModule translates a validated Kessa policy into a Rego module.
//
// The translation is the whole experiment. Kessa's classifier is an ORDERED,
// first-match-wins list, and Rego is a declarative language where rules are
// unordered by construction: nothing in "these three rules hold" says which one
// was written first. So order cannot be carried implicitly, it has to be
// reconstructed. Each policy rule becomes a member of a `matches` set keyed by
// its position, and the decision is the entry at min(matches). That is the
// crossing point where an ordered semantics survives into an unordered engine,
// and it is exactly the sort of assumption the Evaluator interface was silently
// resting on until a second implementation had to state it out loud.
//
// Everything the classifier decides is decided here by Rego: field lookup,
// every operator, scalar coercion, conjunction across a rule's conditions, the
// ordering between rules, and the fallback to the default block. Go's remaining
// jobs are generating this source and unmarshalling the object Rego returns. In
// particular the decision is NOT assembled on the Go side from a returned index,
// which would have quietly moved the interesting half of the semantics back
// across the boundary and proved much less.
func compileModule(p *policy.Policy) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "package %s\n\n", regoPackage)

	// scalar mirrors internal/scalar.Parse, including its ORDER: RFC3339
	// first, then a plain number. The order is load-bearing rather than
	// stylistic, since a string that parses as neither must end up undefined
	// rather than defaulting to zero.
	//
	// The mirror is now exact on infinities, and it was not always. to_number has
	// always refused "Inf", while scalar.Parse took it from strconv.ParseFloat
	// and let it order below every finite bound. The differential test is what
	// surfaced that; scalar.Parse refuses infinities now, and the conformance
	// suite states the rule for both.
	//
	// KNOW WHAT THAT AGREEMENT IS WORTH. This helper is a transcription of
	// internal/scalar.Parse, so the two agreeing about it is a fact about one
	// author writing the same thing twice, not evidence from two implementations.
	// Where a divergence did surface it came from to_number, a builtin written by
	// someone else against a different specification, and that is the only part of
	// this row that was ever independent. The same caution applies to the `in`
	// branch further down, which says so itself.
	//
	// Undefined is how Rego spells "not comparable", and it used to be the whole
	// story here: a builtin that errors (parsing "lots" as a number) leaves the
	// expression undefined, the enclosing rule body fails, and the rule does not
	// match.
	//
	// That is no longer sufficient, because Rego spells TWO different situations
	// the same way. A rule that does not apply and a rule that cannot be evaluated
	// both arrive as undefined, and they are not the same claim: the first is an
	// answer, the second is the absence of one. `comparable` and `uncomparable`
	// below exist to separate them, and everything they add was written from the
	// stated semantics rather than transcribed from the Go, which is the point of
	// having a second implementation at all.
	b.WriteString("scalar(s) := v if {\n\tv := time.parse_rfc3339_ns(s)\n} else := v if {\n\tv := to_number(s)\n}\n\n")

	// The default block. Written as Rego's `default` rule, which fires precisely
	// when the rule below it is undefined, i.e. when no policy rule matched. The
	// correspondence is exact and worth keeping that way: posture is stated in one
	// place in the policy file and in one place here.
	def, err := decisionLiteral(p.Default.Allowed, p.Default.Consequential, policy.DefaultRule, p.Ver, p.Default.Reason)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "default decision := %s\n\n", def)

	// A policy with no rules is all default, and emitting the machinery below for
	// it would reference an undefined `matches`. Stopping here is not a special
	// case so much as the honest translation of "there is nothing to order".
	if len(p.Rules) == 0 {
		return b.String(), nil
	}

	// comparable answers the question the ordering operators actually ask before
	// they compare: can this string be read as a value at all?
	//
	// It exists because "the rule does not apply" and "the rule cannot be
	// evaluated" are different answers and Rego spells both of them `undefined`.
	// An ordering comparison against an uncoercible operand is undefined, and so is
	// a comparison against a field the action never carried, so the two arrive at
	// the rule body looking identical. Asking about coercibility separately is what
	// tells them apart.
	//
	// is_number rather than a bare call, so that a builtin returning a falsy value
	// cannot be mistaken for a builtin that failed.
	b.WriteString("comparable(s) if {\n\tis_number(time.parse_rfc3339_ns(s))\n}\n\n")
	b.WriteString("comparable(s) if {\n\tis_number(to_number(s))\n}\n\n")

	// ordering_fields records, per rule, the fields that rule compares with an
	// ordering operator, in the order the rule declares them. Declaration order is
	// load-bearing: the reason string names the offending fields and an audit entry
	// carrying it is re-derived byte for byte, so the order cannot come from
	// iterating a set.
	b.WriteString(orderingFields(p.Rules))

	// uncomparable maps a rule index to the fields that stopped it being evaluable:
	// present in the action, and not coercible. A rule with no such field is absent
	// from the object entirely, which is how "this rule is evaluable" is spelled.
	b.WriteString("uncomparable[i] := fs if {\n" +
		"\tsome i, flds in ordering_fields\n" +
		"\tfs := [f | some f in flds; input.ctx[f]; not comparable(input.ctx[f])]\n" +
		"\tcount(fs) > 0\n}\n\n")

	// A rule is CONSIDERED if it matched or if it could not be evaluated, and the
	// lowest such index decides. That is what carries first-match-wins across both
	// outcomes with one expression: an unevaluable rule earlier in the policy is
	// answered before a matching rule later in it, exactly as an ordered classifier
	// reading top to bottom would.
	//
	// The two sets are disjoint by construction, since a rule cannot match while
	// one of its comparisons is undefined, but the branches below are written to be
	// exclusive anyway rather than relying on that.
	b.WriteString("considered := matches | {i | some i, _ in uncomparable}\n\n")

	// min over an empty set is undefined, which is what hands control to the
	// `default` rule above when nothing matched. So the no-match path is the same
	// expression as the match path rather than a separate branch that could
	// disagree with it.
	b.WriteString("decision := d if {\n\ti := min(considered)\n\tnot uncomparable[i]\n\td := decisions[i]\n}\n\n")

	// An unevaluable rule denies. It reuses that rule's own entry in `decisions`
	// for the name and version rather than a second table keyed the same way, so
	// there is nowhere for the two to drift apart.
	b.WriteString("decision := d if {\n" +
		"\ti := min(considered)\n" +
		"\tfs := uncomparable[i]\n" +
		"\td := object.union(decisions[i], {\n" +
		"\t\t\"allowed\": false,\n" +
		"\t\t\"consequential\": true,\n" +
		"\t\t\"reason\": sprintf(\"rule %q could not be evaluated: %s is not comparable\", [decisions[i].ruleFired, concat(\", \", fs)]),\n" +
		"\t})\n}\n\n")

	for i, r := range p.Rules {
		conds, err := conditions(r.When)
		if err != nil {
			return "", fmt.Errorf("rule %q: %w", r.Name, err)
		}
		fmt.Fprintf(&b, "# %s\nmatches contains %d if {\n%s\n}\n\n", regoComment(r.Name), i, conds)
	}

	b.WriteString("decisions := {\n")
	for i, r := range p.Rules {
		lit, err := decisionLiteral(!r.Deny, r.Consequential, r.Name, p.Ver, r.Reason)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\t%d: %s,\n", i, lit)
	}
	b.WriteString("}\n")

	return b.String(), nil
}

// orderingFields renders the ordering_fields object: rule index to the fields
// that rule compares with an ordering operator, in declaration order.
//
// Only ordering operators appear. Equality, inequality and membership compare
// strings, and every string compares, so there is no such thing as an operand
// they cannot evaluate. Enumerating the ordering operators here rather than
// excluding the others means an operator added later is absent until someone
// decides what it does with an uncoercible operand, which is the direction that
// fails safe.
func orderingFields(rules []policy.Rule) string {
	var b strings.Builder
	b.WriteString("ordering_fields := {\n")
	for i, r := range rules {
		var fields []string
		for _, c := range r.When {
			switch c.Op {
			case policy.OpLe, policy.OpLt, policy.OpGe, policy.OpGt:
				q, err := regoString(c.Field)
				if err != nil {
					continue
				}
				fields = append(fields, q)
			}
		}
		if len(fields) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\t%d: [%s],\n", i, strings.Join(fields, ", "))
	}
	b.WriteString("}\n\n")
	return b.String()
}

// decisionLiteral renders a Rego object whose keys are types.Decision's JSON
// tags, so the result unmarshals straight into a Decision. Reusing the frozen
// export contract's tags rather than inventing a parallel set of names means a
// rename in types.Decision cannot leave this backend quietly populating fields
// that no longer exist.
//
// StatusCheckedHops is deliberately not among them: it is the enforcement
// point's to set, and Evaluator's contract says so.
func decisionLiteral(allowed, consequential bool, ruleFired, version, reason string) (string, error) {
	rf, err := regoString(ruleFired)
	if err != nil {
		return "", err
	}
	pv, err := regoString(version)
	if err != nil {
		return "", err
	}
	rs, err := regoString(reason)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`{"allowed": %t, "consequential": %t, "ruleFired": %s, "policyVersion": %s, "reason": %s}`,
		allowed, consequential, rf, pv, rs), nil
}

// conditions renders a rule's conditions as the lines of a Rego rule body.
// Successive expressions in a body are conjunctive, which is already the
// classifier's meaning for `when`, so the AND needs no encoding of its own.
func conditions(cs []policy.Condition) (string, error) {
	lines := make([]string, 0, len(cs))
	for i, c := range cs {
		line, err := condition(i, c)
		if err != nil {
			return "", err
		}
		lines = append(lines, "\t"+line)
	}
	return strings.Join(lines, "\n"), nil
}

// condition renders one comparison.
//
// Every operator reads the field as `input.ctx[...]`, and that single choice is
// what reproduces the classifier's fail-closed treatment of an absent field: a
// missing key is undefined in Rego, an undefined term makes its expression
// undefined, and an undefined expression fails the body. It falls out for "!="
// as well, which is the case worth being explicit about, because "audience is
// not internal" reads as TRUE for an action with no audience at all. The
// classifier returns false there (it checks presence before it looks at the
// operator) and so does this, but only because the lookup is what fails, not
// because anything here special-cases it.
func condition(idx int, c policy.Condition) (string, error) {
	field, err := regoString(c.Field)
	if err != nil {
		return "", err
	}
	value, err := regoString(c.Value)
	if err != nil {
		return "", err
	}
	got := fmt.Sprintf("input.ctx[%s]", field)

	switch c.Op {
	case policy.OpEq:
		return fmt.Sprintf("%s == %s", got, value), nil
	case policy.OpNe:
		return fmt.Sprintf("%s != %s", got, value), nil
	case policy.OpLe, policy.OpLt, policy.OpGe, policy.OpGt:
		return fmt.Sprintf("scalar(%s) %s scalar(%s)", got, c.Op, value), nil
	case policy.OpIn:
		// The classifier trims each member of the comma-separated set but not the
		// action's own value, so " eu" does not match "us,eu". Reproduced exactly:
		// trim_space is applied to the member, never to the field.
		//
		// The `!= ""` guard drops a member that trims to nothing, which the
		// classifier also does. Worth knowing why it is spelled out here rather
		// than inherited: this branch was written to mirror the classifier, and it
		// mirrored it faithfully while the classifier was WRONG, letting a trailing
		// comma put "" in the set so an action carrying an empty attribute matched.
		// Both backends agreed, so the conformance suite stayed green throughout.
		// That is the honest limit of a differential: it catches a divergence, and
		// a bug reproduced on purpose is not one.
		//
		// `some m in ...` is existential, which is the right reading of membership:
		// the body holds if ANY member matches.
		return fmt.Sprintf("some m%d in split(%s, \",\"); trim_space(m%d) != \"\"; trim_space(m%d) == %s",
			idx, value, idx, idx, got), nil
	}
	// Unreachable for any policy that came through policy.Parse, which rejects
	// unknown operators. Returning an error rather than skipping the condition is
	// the point: a condition this backend cannot express must stop the policy from
	// loading, never silently evaluate as though it were absent, which would turn
	// an unsupported operator into a rule that matches everything.
	return "", fmt.Errorf("unsupported operator %q on field %q", c.Op, c.Field)
}

// regoString renders a Go string as a Rego string literal. Rego's string syntax
// is JSON's, so the JSON encoder is the correct quoter rather than an
// approximation of one; hand-rolling the escaping here is how a policy field
// containing a quote would become a module that either fails to parse or, worse,
// parses into something else.
func regoString(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("cannot render %q as a Rego string: %w", s, err)
	}
	return string(b), nil
}

// regoComment flattens a rule name onto one line so it cannot escape the comment
// it labels. Cosmetic, but a newline in a rule name would otherwise emit source
// that does not compile.
func regoComment(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
