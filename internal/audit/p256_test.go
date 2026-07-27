// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// A human approver's key is exactly the kind that may be a hardware-minted P-256
// key, so the approval verification path must be algorithm-agile too. (This path
// was Ed25519-only before the scoped-P-256 change; the omission would have made a
// P-256 approver's approval silently unverifiable.)
func TestVerifyApproval_P256Approver(t *testing.T) {
	human, err := signer.NewECDSASigner("did:web:localhost:people:alice")
	if err != nil {
		t.Fatalf("approver signer: %v", err)
	}
	actor := types.DID("did:web:localhost:agents:worker")
	action := types.Action{Type: "payment.transfer", Target: "acct/1", Timestamp: time.Unix(0, 0).UTC()}
	prevHash := make([]byte, 32)

	sig, err := SignApproval(human, actor, action, 7, prevHash)
	if err != nil {
		t.Fatalf("SignApproval (P-256): %v", err)
	}
	if err := VerifyApproval(human.Public(), actor, action, 7, prevHash, sig); err != nil {
		t.Fatalf("a P-256 approval must verify: %v", err)
	}

	// Bound to position: the same approval must not verify at a different slot.
	if err := VerifyApproval(human.Public(), actor, action, 8, prevHash, sig); err == nil {
		t.Fatal("a P-256 approval must not verify at a different seq")
	}

	// Bound to key: another P-256 key must not accept it.
	other, err := signer.NewECDSASigner("did:web:localhost:people:mallory")
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	if err := VerifyApproval(other.Public(), actor, action, 7, prevHash, sig); err == nil {
		t.Fatal("a P-256 approval must not verify under a different key")
	}
}
