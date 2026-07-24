// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package types holds the shared, exported vocabulary of Kessa: the actors in a
// delegation chain, the actions they attempt, and the decisions an enforcement
// point renders about those actions.
//
// It deliberately depends on nothing else in the module (only the standard
// library) so that every other package, including the standalone verifier in
// cmd/verify, can import it without dragging in server concerns. Keep it that
// way: this is a leaf package.
package types

import "time"

// DID is a decentralized identifier, e.g. "did:web:kessa.gneiss-group.com:orgs:acme".
type DID string

// PrincipalKind distinguishes the actors in a delegation chain.
type PrincipalKind int

const (
	KindHuman PrincipalKind = iota
	KindOrg
	KindAgent
	KindSubAgent
)

func (k PrincipalKind) String() string {
	switch k {
	case KindHuman:
		return "human"
	case KindOrg:
		return "org"
	case KindAgent:
		return "agent"
	case KindSubAgent:
		return "sub-agent"
	default:
		return "unknown"
	}
}

// Principal is one actor in a delegation chain. Public key material is resolved
// via the DID document (see internal/did), not carried here.
type Principal struct {
	DID  DID
	Kind PrincipalKind
}

// Action is a request an agent attempts. Fields are intentionally generic; the
// policy engine interprets them per-environment.
//
// The JSON tags are part of the frozen audit export contract (see
// internal/audit): do not rename them without versioning the export format.
type Action struct {
	Type       string            `json:"type"`                 // e.g. "post.publish", "payment.transfer", "code.merge"
	Target     string            `json:"target"`               // resource identifier
	Attributes map[string]string `json:"attributes,omitempty"` // e.g. {"amount":"500","currency":"USD","audience":"external"}
	Timestamp  time.Time         `json:"timestamp"`
}

// Reserved field names in the flattened action context. Any other name resolves
// against Action.Attributes. These are the shared vocabulary that macaroon
// caveats and policy conditions are both written against.
const (
	FieldActionType = "action.type"
	FieldTarget     = "target"
	FieldExpiry     = "expiry"
)

// Context flattens an Action into the canonical field map that macaroon caveat
// satisfaction and policy rule evaluation are both run against.
//
// This function is the single source of truth for that mapping, and it must
// stay that way: the enforcement proxy uses it to decide, and the independent
// verifier uses it to re-derive that decision from the recorded action. If the
// two ever flattened actions differently, the verifier could PASS an action the
// proxy denied, or, worse, PASS one it should have caught.
//
// Reserved names are written last, so an attacker-supplied attribute cannot
// shadow action.type, target, or expiry.
func (a Action) Context() map[string]string {
	ctx := make(map[string]string, len(a.Attributes)+3)
	for k, v := range a.Attributes {
		ctx[k] = v
	}
	ctx[FieldActionType] = a.Type
	ctx[FieldTarget] = a.Target
	ctx[FieldExpiry] = a.Timestamp.UTC().Format(time.RFC3339Nano)
	return ctx
}

// Decision is the enforcement outcome for an Action. Its JSON tags are likewise
// part of the frozen audit export contract.
//
// StatusCheckedHops replaced a `statusChecked bool` in the v2 evidence format,
// as part of security review round 2 (R2-01).
// The boolean was an assertion the enforcement point made about itself and the
// verifier accepted at face value: it was set unconditionally after the
// revocation sweep returned, including when the sweep examined zero hops, so
// "a status check was recorded" was satisfiable with no status check at all. A
// count is not merely a better assertion, it is re-derivable. The verifier knows
// from the export's own evidence how many hops publish a status list, so it
// computes the number it expects and fails on any mismatch, exactly as it already
// re-derives consequentiality instead of trusting the bit.
type Decision struct {
	Allowed       bool   `json:"allowed"`
	Consequential bool   `json:"consequential"` // did policy classify this as consequential?
	RuleFired     string `json:"ruleFired"`     // which policy rule produced the decision
	PolicyVersion string `json:"policyVersion"`
	// StatusCheckedHops is how many chain hops were actually resolved against a
	// signed status list. The verifier re-derives this number from the credential
	// evidence rather than trusting it; see internal/export.verifyEntry step 6.
	StatusCheckedHops int    `json:"statusCheckedHops"`
	Reason            string `json:"reason"`
}
