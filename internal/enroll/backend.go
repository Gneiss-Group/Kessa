// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// ConfirmRequest is what a Backend is asked to authorize: a device key has just
// been generated for an employee identity, and the question is whether to trust
// it and register it. No private key is ever passed: only the identity, the DID
// being registered, and the public key's fingerprint/algorithm.
type ConfirmRequest struct {
	Identity    string
	DID         types.DID
	Fingerprint string
	Algorithm   string
}

// Backend authenticates an enrollment before any key is registered or credential
// minted. It is the extension point the deployment model calls for: a
// zero-dependency default that always works, with room for a stronger check in
// real deployments.
//
// It is an INTERNAL extension point, not a designated plugin interface, and the
// difference is not cosmetic. A designated plug point carries the
// //kessa:plugin-interface marker, is licensed permissively, and reaches nothing
// but the standard library, so a third party can implement it and license their
// implementation on their own terms (see LICENSING.md; auditsink is the only one).
// Backend has none of those properties: this package is AGPL-3.0-only, and it
// lives under internal/, so the Go toolchain refuses the import outright to
// anyone outside this module. The seam exists so WE can add a stronger backend
// without disturbing Enroll's orchestration, which is a different thing from a
// seam a stranger can build against. An earlier version of this comment grouped
// it with AuditSink, which invited exactly the wrong inference.
//
// The default (LocalTOFU) is self-administered trust-on-first-use: it shows the
// operator the new key's fingerprint and asks for interactive confirmation, the
// same ceremony ssh uses for a new host key. No secret crosses between two
// parties, so there is nothing to intercept: honest and sufficient wherever
// there is no organizational gap between "admin" and "employee" (solo, home lab,
// small team).
//
// A stronger backend: binding enrollment to a live corporate IdP session
// (Okta/Azure AD) so the human is authenticated, not just the key confirmed:
// satisfies this same interface and drops in without touching Enroll's
// orchestration. It is deliberately NOT built here; the seam exists so it can be,
// and whether it ships open or paid is a separate, deferred decision. Rejected
// alternatives (admin-issued bearer tokens, SSH-key derivation) are recorded in
// the deployment doc, not offered here.
type Backend interface {
	// Confirm returns nil to authorize registration; any error aborts enrollment
	// before anything is written or minted.
	Confirm(req ConfirmRequest) error
	// Name identifies the backend, for the enrollment summary and logs.
	Name() string
}

// LocalTOFU is the default self-administered trust-on-first-use backend.
type LocalTOFU struct {
	In  io.Reader // prompt input (defaults to failing closed if nil and !AssumeYes)
	Out io.Writer // where the fingerprint prompt is written

	// AssumeYes skips the interactive prompt and confirms automatically. It is for
	// non-interactive enrollment (scripts, fixtures, tests) where a human cannot
	// answer; a real interactive enrollment leaves it false so the operator
	// actually eyeballs the fingerprint.
	AssumeYes bool
}

// Name identifies this backend.
func (b LocalTOFU) Name() string {
	if b.AssumeYes {
		return "local-tofu (assume-yes)"
	}
	return "local-tofu"
}

// Confirm shows the fingerprint and, unless AssumeYes is set, requires the
// operator to type "yes". Anything else (including EOF or a nil reader) fails
// closed, so an enrollment is never silently accepted for want of an answer.
func (b LocalTOFU) Confirm(req ConfirmRequest) error {
	out := b.Out
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, "\nEnrolling a new device key:\n")
	fmt.Fprintf(out, "  identity     %s\n", req.Identity)
	fmt.Fprintf(out, "  DID          %s\n", req.DID)
	fmt.Fprintf(out, "  algorithm    %s\n", req.Algorithm)
	fmt.Fprintf(out, "  fingerprint  %s\n", req.Fingerprint)

	if b.AssumeYes {
		fmt.Fprintf(out, "auto-confirmed (assume-yes)\n")
		return nil
	}
	if b.In == nil {
		return fmt.Errorf("enroll: no input to confirm fingerprint on (run interactively or pass --yes)")
	}
	fmt.Fprintf(out, "Confirm this fingerprint is correct out-of-band, then type 'yes' to register: ")
	line, err := bufio.NewReader(b.In).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("enroll: enrollment not confirmed (no input read): %w", err)
	}
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		return fmt.Errorf("enroll: enrollment declined at fingerprint confirmation")
	}
	return nil
}

// compile-time assertion that LocalTOFU satisfies Backend.
var _ Backend = LocalTOFU{}
