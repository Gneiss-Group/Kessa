// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/status"
)

// TestP256_CompiledVerifyBinary_EndToEnd closes R3-04's last-mile gap: not the
// verification LOGIC (that is covered by TestP256EmployeeAndApprover_EndToEnd via
// export.Verify), but the actual compiled `cmd/verify` BINARY re-deriving a P-256
// export it reads off disk, with did:web documents resolved from a --dids
// directory and a signed status list read from a file: exactly what an external
// evaluator runs.
//
// The chain is the B4 reframe made concrete: org(Ed25519, root) -> employee(P-256
// device key) -> agent(Ed25519). The employee's P-256 key does two things a human
// key does in this model and that the binary must re-derive: it ISSUES the agent
// credential (the on-device issuance act: a P-256 issuance signature at the
// employee->agent hop) and it APPROVES the consequential action (a P-256
// approval). The agent does Ed25519 PoP; the proxy envelope and status list stay
// Ed25519. One run therefore proves the compiled offline verifier handles a mixed
// Ed25519/P-256 chain including a P-256 ISSUER, which the older Ed25519-only
// goldens never exercised.
//
// It is generate-fresh-then-verify, not a committed golden: ECDSA/P-256
// signatures are non-deterministic (fresh nonce per signature) and each run also
// re-signs the envelope, so there is no byte-stable artifact to check in: the
// same reason the P-256 fixtures verify rather than byte-compare.
func TestP256_CompiledVerifyBinary_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	didsDir := filepath.Join(dir, "dids")

	r := memResolver{}
	// reg registers a principal both in the in-process resolver the proxy uses AND
	// as an on-disk did:web document the compiled binary resolves from --dids.
	reg := func(s signer.Signer) {
		doc := did.NewDocument(s.DID(), s.Public())
		r[s.DID()] = doc
		if _, err := did.WriteDocument(didsDir, doc); err != nil {
			t.Fatalf("write DID doc for %s: %v", s.DID(), err)
		}
	}

	org, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:orgs:acme", seed32(0x11)) // org + status issuer: Ed25519
	if err != nil {
		t.Fatal(err)
	}
	employee, err := signer.NewECDSASigner("did:web:localhost:employees:alice-laptop") // device key: P-256
	if err != nil {
		t.Fatal(err)
	}
	agent, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:agents:worker", seed32(0x22)) // agent PoP key: Ed25519
	if err != nil {
		t.Fatal(err)
	}
	proxyEP, err := signer.NewSoftwareSignerFromSeed("did:web:localhost:proxies:gatekeeper", seed32(0x55)) // EP: Ed25519
	if err != nil {
		t.Fatal(err)
	}
	reg(org)
	reg(employee)
	reg(agent)
	reg(proxyEP)

	// org -> employee -> agent, authority narrowing at each hop.
	base := macaroon.Mint(seed32(0x01), "cred-p256-binary", string(org.DID()))
	mEmployee := att(t, base, "action.type", "==", "payment.transfer")
	mAgent := att(t, mEmployee, "amount", "<=", "100")

	mk := func(subject, issuer signer.Signer, m macaroon.Macaroon, ref status.Reference) chain.Link {
		c, err := credential.New(credential.Options{
			Subject: subject.DID(), Issuer: issuer.DID(), Macaroon: m, StatusRef: ref, HolderKey: subject.Public(),
		})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := chain.SignIssuance(issuer, c)
		if err != nil {
			t.Fatal(err)
		}
		return chain.Link{Credential: *c, IssuerProof: proof}
	}
	// The employee->agent hop is the cross-issuer status case, and it is the
	// realistic one: the EMPLOYEE issues the hop (on-device issuance) while the ORG
	// publishes the revocation list covering its whole subtree. The credential
	// therefore names the org as its revocation authority (R6-01); without that it
	// would default to its own issuer, the employee, who signs no list. That
	// declaration is inside the issuance signature, so the employee is choosing it
	// at mint time and cannot be talked out of it afterwards.
	ch := &chain.Chain{Links: []chain.Link{
		mk(employee, org, mEmployee, status.Reference{}), // org signs (Ed25519)
		mk(agent, employee, mAgent, status.Reference{ // EMPLOYEE signs (P-256): on-device issuance
			ListURL: acmeListURL, Index: 42, Issuer: org.DID(),
		}),
	}}

	// Org publishes an all-clear status list and it is written to a file the binary
	// reads via --status.
	list := status.New(status.MinBits)
	if err := list.Sign(org); err != nil {
		t.Fatal(err)
	}
	statusFile := filepath.Join(dir, "status.json")
	if err := status.Save(list, statusFile); err != nil {
		t.Fatal(err)
	}
	statuses := export.MapStatusResolver{acmeListURL: list}

	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{EnforcementPoint: proxyEP, Policy: pol, DIDs: r, Status: statuses})
	if err != nil {
		t.Fatal(err)
	}

	a := action("100") // consequential: needs status sweep + human approval
	terminal := &ch.Links[len(ch.Links)-1].Credential
	tip := px.Tip()
	pop, err := terminal.ProvePossession(agent, []byte("nonce-bin"), a, tip.Seq, tip.PrevHash) // Ed25519 PoP
	if err != nil {
		t.Fatal(err)
	}
	appr, err := audit.SignApproval(employee, terminal.Subject, a, tip.Seq, tip.PrevHash) // P-256 approval (employee is the human)
	if err != nil {
		t.Fatal(err)
	}
	res, err := px.Handle(Request{Chain: ch, Action: a, PoP: pop, Approver: employee.DID(), Approval: appr})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allowed || !res.Decision.Consequential {
		t.Fatalf("expected consequential allow, got %+v", res.Decision)
	}

	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	data, err := exp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	exportFile := filepath.Join(dir, "export.json")
	if err := os.WriteFile(exportFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Run the ACTUAL compiled verifier binary, resolving DIDs from the directory
	// and the status list from the file. A zero exit is a PASS verdict.
	cmd := exec.Command("go", "run", "github.com/Gneiss-Group/Kessa/cmd/verify",
		"verify",
		"--export", exportFile,
		"--dids", didsDir,
		"--status", acmeListURL+"="+statusFile,
		"--color", "never",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compiled cmd/verify rejected a valid P-256 export (exit %v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("cmd/verify output did not report PASS:\n%s", out)
	}
}
