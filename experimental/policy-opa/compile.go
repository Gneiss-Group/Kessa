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
	// and let it order below every finite bound, so this backend failed closed on
	// an input the classifier let through a routine rule. The differential test
	// is what surfaced that; scalar.Parse refuses infinities now, and the
	// conformance suite states the rule for both. Worth recording because the
	// agreement here is by construction on both sides rather than the coincidence
	// it briefly was.
	//
	// Undefined is how "not comparable" is spelled in Rego, and it is the right
	// spelling here: a builtin that errors (parsing "lots" as a number) leaves the
	// expression undefined under OPA's default error handling, the enclosing rule
	// body fails, and the rule does not match. That lands on the classifier's
	// fail-closed behavior without needing to special-case it.
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

	// min over an empty set is undefined, which is what hands control to the
	// `default` rule above when nothing matched. So the no-match path is the same
	// expression as the match path rather than a separate branch that could
	// disagree with it.
	b.WriteString("decision := d if {\n\td := decisions[min(matches)]\n}\n\n")

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
