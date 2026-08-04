// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// The export is a bearer artifact (R5-06).
//
// This test pins a DELIBERATE design property together with the security
// consequence that follows from it, because the two are usually stated apart and
// the second one is the surprising half.
//
// The property: a v2 export carries each credential AND its issuer proof, so the
// delegation chain can be re-derived from the export alone. That is not a leak —
// it is the point. It is what lets the independent verifier re-check a chain
// offline against public DID documents with no shared secret and nothing of ours
// running. Take it away and the central claim of the product goes with it.
//
// The consequence: chain verification is the only gate before an audit entry is
// written (Gate 0, enforce.go). A chain proves ISSUANCE, which is public; it does
// not prove POSSESSION, which is what a private key is for. So anyone holding an
// export holds enough to make a reachable enforcement endpoint write entries —
// no key, no browser, no insider access. The entries are denials, and they are
// genuine: correctly signed, correctly chained, and the verifier re-derives them
// as PASS, because it is faithfully re-deriving what the enforcement point saw.
//
// The fix is NOT to stop carrying credentials, and NOT to stop logging denials (a
// denial is a real decision — R2, and scenario 5 of the demo turns on exactly
// that). The fix is that the enforcement endpoint needs CALLER AUTHENTICATION,
// which it does not have; see the README's Known limits and UPCOMING.md. Until it
// does, an export must be treated as a write credential for the proxy that
// produced it.
//
// If this test ever fails, one of two things changed: the export stopped being
// self-contained (a verifier regression), or the write gate moved (in which case
// the Known limits entry needs revisiting). Either is worth a human reading.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/export"
)

func TestExportIsSufficientToReDeriveTheChain(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)

	a := action("10")
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, "legit")}); err != nil {
		t.Fatalf("honest request: %v", err)
	}
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	handedOut, err := exp.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// A recipient with only the export bytes.
	var received export.Export
	if err := json.Unmarshal(handedOut, &received); err != nil {
		t.Fatal(err)
	}
	rebuilt := rebuildChain(t, received, 0)

	// Self-containment: this is the property the verifier depends on.
	if err := rebuilt.Verify(h.resolver); err != nil {
		t.Fatalf("export is not self-contained — the verifier's offline guarantee is broken: %v", err)
	}
}

// TestBearerChainCanWriteToTheLog states the consequence as an executable fact:
// the re-derived chain, with a signature the holder never produced, still causes
// an entry — and advances the tip out from under an honest caller.
func TestBearerChainCanWriteToTheLog(t *testing.T) {
	h := newHarness(t)
	px := h.proxy(t)
	srv := httptest.NewServer(Handler(px))
	t.Cleanup(srv.Close)

	a := action("10")
	if _, err := px.Handle(Request{Chain: h.chain, Action: a, PoP: h.pop(t, px.Tip(), a, "legit")}); err != nil {
		t.Fatal(err)
	}
	exp, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := rebuildChain(t, *exp, 0)
	before := len(exp.Entries)

	// An honest caller reads the tip and binds its proof to that position.
	honestTip := px.Tip()
	honestAction := action("10")
	honestPoP := h.pop(t, honestTip, honestAction, "honest-inflight")

	// The bearer submits over plain HTTP. No browser, so no Origin — which the
	// ingress guard correctly treats as a non-browser client. The PoP is worthless.
	bad := h.pop(t, honestTip, a, "bearer")
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0xff

	body, err := json.Marshal(Request{Chain: rebuilt, Action: a, PoP: bad})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/enforce", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	after, err := px.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Entries) == before {
		t.Fatalf("expected the bearer write to be recorded (status %d)", resp.StatusCode)
	}

	// The honest caller's proof is now bound to a position that has moved. This is
	// the availability half: it needs no key at all.
	res, err := px.Handle(Request{Chain: h.chain, Action: honestAction, PoP: honestPoP})
	if err == nil && res.Decision.Allowed {
		t.Fatal("expected the honest caller's tip-bound proof to be invalidated by the interleaved write")
	}
}

// rebuildChain reconstructs a delegation chain from an export's own evidence.
// CredentialRecord is {CredentialID, Credential, IssuerProof} and chain.Link is
// {Credential, IssuerProof}, so this is a field copy in the order the entry
// records.
func rebuildChain(t *testing.T, e export.Export, entry int) *chain.Chain {
	t.Helper()
	ids := e.Entries[entry].ChainCredentialIDs
	if len(ids) == 0 {
		t.Fatal("entry carries no chain credential IDs")
	}
	links := make([]chain.Link, 0, len(ids))
	for _, id := range ids {
		rec, ok := e.Credentials[id]
		if !ok {
			t.Fatalf("credential %s not carried in the export", id)
		}
		links = append(links, chain.Link{Credential: rec.Credential, IssuerProof: rec.IssuerProof})
	}
	return &chain.Chain{Links: links}
}

// TestBearerChainIsConfinedByTheDIDTrustRoot bounds R5-06's blast radius, which
// is the difference between "your auditor can pollute your log" and "anyone can".
//
// A proxy resolves DIDs with did.FileResolver over its --dids directory and has
// NO network resolution — there is no --fetch-dids on the proxy, unlike the
// verifier. So a chain is only usable against a proxy whose trust root can
// resolve EVERY hop of it. That confines an export to:
//
//  1. the deployment that issued it (which necessarily resolves its own DIDs), and
//  2. any proxy deliberately configured to trust that org — which is the cross-org
//     feature working as designed (demo scenario 6), not a leak.
//
// It does NOT reach an arbitrary third party. If the proxy ever gains network DID
// resolution, that premise dies and this test should fail loudly.
func TestBearerChainIsConfinedByTheDIDTrustRoot(t *testing.T) {
	h := newHarness(t)

	copyInto := func(t *testing.T, rel ...string) string {
		t.Helper()
		root := t.TempDir()
		for _, r := range rel {
			b, err := os.ReadFile(filepath.Join(didsRoot, r))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, r)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, r), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}

	chainDIDs := []string{
		"localhost/people/alice/did.json",
		"localhost/orgs/acme/did.json",
		"localhost/agents/worker/did.json",
		"localhost/agents/helper/did.json",
	}

	t.Run("unrelated org rejects it", func(t *testing.T) {
		root := copyInto(t, "localhost/orgs/bravo/did.json")
		if err := h.chain.Verify(did.FileResolver{Root: root}); err == nil {
			t.Fatal("a foreign chain must not verify against a trust root that never heard of it")
		}
	})

	t.Run("partial root rejects it", func(t *testing.T) {
		root := copyInto(t, "localhost/people/alice/did.json", "localhost/orgs/acme/did.json")
		if err := h.chain.Verify(did.FileResolver{Root: root}); err == nil {
			t.Fatal("every hop must resolve; a partially-trusting root must still reject")
		}
	})

	t.Run("cross-org-configured root accepts it, by design", func(t *testing.T) {
		root := copyInto(t, chainDIDs...)
		if err := h.chain.Verify(did.FileResolver{Root: root}); err != nil {
			t.Fatalf("cross-org trust is a feature; this configuration must accept: %v", err)
		}
	})
}
