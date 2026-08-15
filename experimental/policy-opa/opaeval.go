// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package opaeval implements policy.Evaluator on top of Open Policy Agent,
// as the second implementation that tests whether that interface is a real
// boundary.
//
// # Why this is a separate module
//
// Kessa's core is stdlib-only Go, with no third-party runtime dependency, and
// that is a property the project makes claims about rather than an accident of
// how it grew. OPA brings roughly a hundred transitive modules with it. Putting
// this package in its own module, with its own go.mod, is what keeps those two
// facts compatible: `go list ./...` from the repository root does not see this
// directory, so `go build ./...` and the test suite cannot pull OPA in even by
// mistake. The dependency arrow points one way only, from here into the core,
// via the replace directive in go.mod.
//
// # What this is not
//
// This is not shipped OPA support and does not commit the project to any. It is
// a proof that a real third-party policy engine can sit behind
// policy.Evaluator and mean the same thing by it, which a second hand-rolled
// evaluator could not have proved: it would have inherited the same author's
// assumptions about what the interface needs to express. Nothing in the shipped
// product imports this package. See the module README for what the exercise
// actually turned up, including the places where the two implementations do not
// agree.
package opaeval

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/pkg/types"
	"github.com/open-policy-agent/opa/v1/rego"
)

// evalTimeout bounds one evaluation. See Evaluate for why the bound belongs to
// Kessa even though the work happens inside a dependency.
//
// It is WALL CLOCK, which is what makes the value larger than an evaluation's
// cost would suggest. The deadline counts time the goroutine spends not running
// as well as time it spends working, so under contention it measures scheduling
// delay too. 250ms looked generous against the cost of one evaluation and was
// not: TestConcurrentEvaluation runs 64 goroutines of 16 evaluations under the
// race detector, and on a shared CI runner that fired the deadline on requests
// that were merely waiting their turn.
//
// That is the symptom this comment used to say would mean something was broken,
// so the number is now set well above any legitimate evaluation INCLUDING the
// wait to be scheduled. Its job is to cap a hang, not to express a latency
// target: an evaluation taking seconds is already pathological, and one taking
// forever is the case that must not exist.
//
// A benchmark would replace the guess with a measurement, and until there is one
// the value errs high, because a bound that fires on healthy traffic converts a
// liveness property into an outage.
//
// A var rather than a const so a test can shorten it. Nothing else may: this is
// not a tuning knob, and a deployment that needed it larger would be telling us
// something about its policies rather than about this number.
var evalTimeout = 5 * time.Second

// NO SEPARATE INPUT-SIZE CAP, and that is a decision rather than an omission.
//
// Both listeners already cap the request body at 1 MiB with http.MaxBytesReader
// (internal/enforce/http.go, mcp.go), so the action reaching any evaluator is
// bounded in transport before it gets here. What that does not bound is the COST
// of evaluating a large-but-legal input, and evalTimeout bounds exactly that, in
// the unit that actually matters.
//
// A third limit would add a number nobody can choose well: this module has no
// operator to tune it, no evidence about what a reasonable attribute count is,
// and two bounds that disagree would produce a refusal whose reason depends on
// which one happened to be tighter. Recorded here so the next reader does not
// reopen it as an oversight.

// Evaluator evaluates Kessa policies with OPA. It satisfies policy.Evaluator.
type Evaluator struct {
	version string
	source  string
	query   rego.PreparedEvalQuery
}

// Assert the whole point of the package at compile time.
var _ policy.Evaluator = (*Evaluator)(nil)

// New compiles a policy into a Rego module and prepares it for evaluation.
//
// The policy is parsed by policy.Parse, the same function the proxy uses, rather
// than by anything here. That is deliberate and is where the boundary sits: a
// backend that did its own parsing could accept a policy the proxy would have
// rejected, which is the divergence policy.Validate is exported to prevent. What
// this package reimplements is EVALUATION, which is what Evaluator is an
// interface for.
//
// Compilation happens once, here, rather than per evaluation. Beyond the obvious
// cost argument, it means a policy that cannot be translated fails at load time,
// where a startup failure is a legible operational event, instead of at decision
// time, where it would be an error on a single request.
func New(policyJSON []byte) (*Evaluator, error) {
	p, err := policy.Parse(policyJSON)
	if err != nil {
		return nil, err
	}
	return NewFromPolicy(p)
}

// NewFromPolicy builds an evaluator from an already-parsed policy.
func NewFromPolicy(p *policy.Policy) (*Evaluator, error) {
	src, err := compileModule(p)
	if err != nil {
		return nil, fmt.Errorf("opaeval: compile policy %s: %w", p.Version(), err)
	}

	// context.Context is not part of the Evaluator signature, which is fine for
	// preparation (a caller controls when it loads a policy) and is noted in the
	// spec as an additive change to make if a network-backed evaluator ever needs
	// cancellation. Worth recording what this experiment found about that: an
	// in-process Rego evaluation never needs it, so the missing parameter is not a
	// gap the interface has to close speculatively. It would become one for
	// OPA-over-HTTP, and only then.
	q, err := rego.New(
		rego.Query(decisionQuery),
		rego.Module("kessa_policy.rego", src),
		// Errors from builtins stay non-fatal, which is load-bearing rather than
		// lax: it is what makes an uncoercible comparison undefined, so the rule
		// simply does not match. Turning this on would convert the classifier's
		// fail-closed no-match into an evaluation error.
		rego.StrictBuiltinErrors(false),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("opaeval: prepare policy %s: %w\n%s", p.Version(), err, src)
	}

	return &Evaluator{version: p.Version(), source: src, query: q}, nil
}

// Version returns the policy version, which is recorded in every audit entry.
func (e *Evaluator) Version() string { return e.version }

// Source returns the generated Rego module. Exported because the translation is
// the interesting artifact of this experiment: being able to read what a Kessa
// policy becomes is most of the value of having built it.
func (e *Evaluator) Source() string { return e.source }

// Evaluate classifies an action by evaluating the compiled Rego module.
//
// The action is flattened by types.Action.Context, the same canonical mapping
// the classifier and macaroon caveat satisfaction both use. Reusing it is not a
// shortcut: the verifier re-derives decisions from recorded actions through that
// function, so a backend that flattened actions its own way could produce
// decisions the verifier would refuse to reproduce.
func (e *Evaluator) Evaluate(a types.Action) (types.Decision, error) {
	// BOUNDED, because an unbounded one is a cost the caller controls. The action
	// arrives on a proxied request, the agent is the untrusted party, and this
	// evaluation runs on a path already serialized behind one mutex, so an
	// evaluation that does not finish holds up every other request behind it.
	//
	// Whether OPA is fast is not the question and is not Kessa's to answer. The
	// BOUND is Kessa's responsibility even when the unbounded work happens inside
	// a dependency, which is why it is applied here rather than assumed away.
	//
	// The interface takes no context.Context and does not need to: this is the
	// evaluator's own bound, not the caller's cancellation. Cancellation only
	// becomes an interface question for an evaluator that leaves the process.
	//
	// Deliberately generous, and see evalTimeout for how generous it has to be:
	// the deadline is wall clock, so it has to clear scheduling delay under
	// contention as well as the evaluation itself.
	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()

	// A deadline that fires surfaces as an error, and internal/enforce turns any
	// policy error into a denial, so exceeding the bound fails closed with no
	// further plumbing.
	rs, err := e.query.Eval(ctx, rego.EvalInput(map[string]any{"ctx": a.Context()}))
	if err != nil {
		return types.Decision{}, fmt.Errorf("opaeval: evaluate: %w", err)
	}

	// A policy always has a default block (policy.Validate requires one), so a
	// well-formed module always produces exactly one result. No result means the
	// generated module is wrong, and that has to surface as an error: returning a
	// zero Decision instead would be a silent DENY with no stated reason, which is
	// the precise footgun the mandatory default block exists to prevent.
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return types.Decision{}, fmt.Errorf("opaeval: policy %s produced %d results, want exactly 1", e.version, len(rs))
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return types.Decision{}, fmt.Errorf("opaeval: encode decision: %w", err)
	}
	var d types.Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return types.Decision{}, fmt.Errorf("opaeval: decode decision: %w", err)
	}

	// The generated module never emits a rule with an empty reason, and Validate
	// rejects a policy that could supply one, so this holds twice over. It is
	// checked anyway because the consequence is specific: a Decision reaches a
	// signed, hash-chained audit entry, and an entry that verifies perfectly while
	// explaining nothing is worse than a loud failure here.
	if d.Reason == "" || d.RuleFired == "" {
		return types.Decision{}, fmt.Errorf("opaeval: policy %s produced a decision with no stated rule or reason", e.version)
	}
	return d, nil
}
