// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/audit"
	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/enroll"
	"github.com/Gneiss-Group/Kessa/internal/export"
	"github.com/Gneiss-Group/Kessa/internal/policy"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/internal/status"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	specPath = "../../examples/issuer/spec.json"
	ksPath   = "../../examples/issuer/keystore.json"

	didAlice  = "did:web:localhost:people:alice"
	didAcme   = "did:web:localhost:orgs:acme"
	didWorker = "did:web:localhost:agents:worker"
	didHelper = "did:web:localhost:agents:helper"
	didProxy  = "did:web:localhost:proxies:gatekeeper"
)

func loadExample(t *testing.T) (*Spec, Keystore) {
	t.Helper()
	spec, err := loadJSON[Spec](specPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	ks, err := loadJSON[Keystore](ksPath)
	if err != nil {
		t.Fatalf("load keystore: %v", err)
	}
	return &spec, ks
}

// publishTo publishes the example spec into a fresh temp root.
func publishTo(t *testing.T) (root string, res *Result, spec *Spec, ks Keystore) {
	t.Helper()
	spec, ks = loadExample(t)
	root = t.TempDir()
	chainOut := filepath.Join(t.TempDir(), "chain.json")
	res, err := publish(spec, ks, root, chainOut)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	return root, res, spec, ks
}

// ---- step-11 acceptance: issued credentials verify end to end --------------

func TestIssuedChainVerifiesAgainstPublishedDIDDocs(t *testing.T) {
	root, res, _, ks := publishTo(t)

	// The chain the issuer minted verifies using ONLY the DID documents it
	// published, no issuer process, no network.
	if err := res.Chain.Verify(did.FileResolver{Root: root}); err != nil {
		t.Fatalf("issued chain should verify against the published root: %v", err)
	}

	want := []types.DID{didAlice, didAcme, didWorker, didHelper}
	got := res.Chain.Principals()
	if len(got) != len(want) {
		t.Fatalf("principals = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("principals[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Every published DID doc resolves to the keystore's key for that principal.
	for _, d := range []string{didAlice, didAcme, didWorker, didHelper, didProxy} {
		s, err := ks.Signer(types.DID(d))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := did.ResolveKey(did.FileResolver{Root: root}, types.DID(d))
		if err != nil {
			t.Fatalf("resolve %s: %v", d, err)
		}
		if !signer.KeysEqual(pub, s.Public()) {
			t.Fatalf("published DID doc for %s carries the wrong key", d)
		}
	}
}

func TestPublishedStatusListIsSignedByItsIssuer(t *testing.T) {
	root, res, spec, _ := publishTo(t)

	list, err := status.Load(res.StatusPath)
	if err != nil {
		t.Fatalf("load published status list: %v", err)
	}
	if list.Issuer != spec.Status.Issuer {
		t.Fatalf("status list issuer = %q", list.Issuer)
	}
	pub, err := did.ResolveKey(did.FileResolver{Root: root}, spec.Status.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Verify(spec.Status.Issuer, pub); err != nil {
		t.Fatalf("published status list must verify against its issuer's published DID doc: %v", err)
	}
	// Freshly published: nothing revoked.
	for _, idx := range []int{42, 44} {
		if revoked, _ := list.Lookup(idx); revoked {
			t.Fatalf("index %d should start un-revoked", idx)
		}
	}
}

// ---- the self-hostable-first constraint ------------------------------------

// TestPublicationRootIsStaticallyHostable is the heart of step 11. The very same
// directory must work as (a) a local directory for an offline verifier, and
// (b) a static website answering did:web over HTTP. No application server, no
// Kessa service.
func TestPublicationRootIsStaticallyHostable(t *testing.T) {
	root, res, spec, _ := publishTo(t)

	// (b) Serve the host's document root with a plain static file server. The
	// publication root is host-partitioned, so a web server for `localhost`
	// serves <root>/localhost, exactly what any static host would be configured
	// to do.
	site, err := SiteRoot(root, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(site)))
	defer srv.Close()

	// Every principal's DID document is fetchable at the exact path did:web
	// resolution derives, and is byte-identical to the file on disk.
	for _, d := range []string{didAlice, didAcme, didWorker, didHelper, didProxy} {
		urlPath := didWebURLPath(t, types.DID(d))
		body := httpGet(t, srv.URL+urlPath)

		diskPath, err := did.DocumentPath(root, types.DID(d))
		if err != nil {
			t.Fatal(err)
		}
		onDisk, err := os.ReadFile(diskPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, onDisk) {
			t.Fatalf("%s: bytes served over HTTP differ from the published file", d)
		}
	}

	// The status list is likewise reachable at the URL the credentials reference.
	statusPath := strings.TrimPrefix(spec.Status.URL, "https://localhost")
	body := httpGet(t, srv.URL+statusPath)
	onDisk, err := os.ReadFile(res.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, onDisk) {
		t.Fatal("status list served over HTTP differs from the published file")
	}

	// (a) And the same directory resolves offline.
	if err := res.Chain.Verify(did.FileResolver{Root: root}); err != nil {
		t.Fatalf("published root must also work as a local directory: %v", err)
	}
}

// TestPublishedRootResolvesOverDIDWebHTTPS proves the layout satisfies the real
// did:web resolver (not just raw byte fetches): we publish DIDs whose host IS the
// static server's address, then resolve them with did.HTTPResolver.
func TestPublishedRootResolvesOverDIDWebHTTPS(t *testing.T) {
	root := t.TempDir()
	// The DID host is the server's host:port, which we only learn after the
	// listener binds, so resolve the document root lazily, per request.
	var site string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(site)).ServeHTTP(w, r)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()         // 127.0.0.1:PORT
	site = filepath.Join(root, addr)             // the host-partitioned document root
	host := strings.ReplaceAll(addr, ":", "%3A") // did:web percent-encodes the port
	org := types.DID("did:web:" + host + ":orgs:acme")
	agent := types.DID("did:web:" + host + ":agents:worker")

	_, ks := loadExample(t)
	ks[org] = ks[didAcme]
	ks[agent] = ks[didWorker]

	spec := &Spec{
		RootKeyHex: "0011223344556677",
		Identifier: "cred-http-1",
		Location:   string(org),
		Status:     StatusSpec{URL: "http://" + srv.Listener.Addr().String() + "/orgs/acme/status.json", Issuer: org, Bits: status.MinBits},
		Hops:       []HopSpec{{Issuer: org, Subject: agent, Caveats: []CaveatSpec{{Field: "amount", Op: "<=", Value: "100"}}}},
	}
	if _, err := publish(spec, ks, root, filepath.Join(t.TempDir(), "chain.json")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	r := did.HTTPResolver{Scheme: "http", AllowedHosts: []string{addr}}
	for _, d := range []types.DID{org, agent} {
		doc, err := r.Resolve(d)
		if err != nil {
			t.Fatalf("did:web HTTPS resolution of %s against a static host failed: %v", d, err)
		}
		if doc.ID != d {
			t.Fatalf("resolved doc id = %q", doc.ID)
		}
	}
}

// TestAirGappedHostIsAccepted: the hostname is the operator's, and may resolve
// nowhere at all. Publishing and offline verification must not care.
func TestAirGappedHostIsAccepted(t *testing.T) {
	_, ks := loadExample(t)
	org := types.DID("did:web:vault.corp.internal:orgs:acme")
	agent := types.DID("did:web:vault.corp.internal:agents:worker")
	ks[org] = ks[didAcme]
	ks[agent] = ks[didWorker]

	root := t.TempDir()
	spec := &Spec{
		RootKeyHex: "00ff",
		Identifier: "airgap-1",
		Location:   string(org),
		Status:     StatusSpec{URL: "https://vault.corp.internal/orgs/acme/status.json", Issuer: org, Bits: status.MinBits},
		Hops:       []HopSpec{{Issuer: org, Subject: agent, StatusIndex: ptr(7)}},
	}
	res, err := publish(spec, ks, root, filepath.Join(t.TempDir(), "chain.json"))
	if err != nil {
		t.Fatalf("an unroutable, internal-only host must publish fine: %v", err)
	}
	if err := res.Chain.Verify(did.FileResolver{Root: root}); err != nil {
		t.Fatalf("air-gapped chain must verify offline: %v", err)
	}
	if !strings.Contains(res.StatusPath, filepath.Join("vault.corp.internal", "orgs", "acme")) {
		t.Fatalf("status list published to an unexpected path: %s", res.StatusPath)
	}
}

// TestNoSecretsInPublicationRoot: the root is public. It must contain only DID
// documents and the status list, never credentials, never key material.
func TestNoSecretsInPublicationRoot(t *testing.T) {
	root, res, _, ks := publishTo(t)

	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range files {
		base := filepath.Base(p)
		if base != "did.json" && base != "status.json" {
			t.Fatalf("unexpected file in the public root: %s", p)
		}
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// No private seed may appear anywhere in the public artifacts.
		for d, seed := range ks {
			if d == "_comment" {
				continue
			}
			if bytes.Contains(body, []byte(seed)) {
				t.Fatalf("%s leaks the private seed for %s", p, d)
			}
		}
		// Nor the macaroon root key.
		if bytes.Contains(body, []byte("00112233445566778899aabbccddeeff")) {
			t.Fatalf("%s leaks the macaroon root key", p)
		}
	}

	// The credentials live outside the root.
	if strings.HasPrefix(res.ChainPath, root) {
		t.Fatalf("credentials were written inside the public root: %s", res.ChainPath)
	}
}

func TestPublishIsDeterministic(t *testing.T) {
	spec, ks := loadExample(t)
	hash := func() []byte {
		root := t.TempDir()
		res, err := publish(spec, ks, root, filepath.Join(t.TempDir(), "chain.json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := res.Chain.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		doc, err := os.ReadFile(filepath.Join(root, "localhost", "orgs", "acme", "did.json"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := os.ReadFile(res.StatusPath)
		if err != nil {
			t.Fatal(err)
		}
		return append(append(b, doc...), st...)
	}
	if !bytes.Equal(hash(), hash()) {
		t.Fatal("two publishes of the same spec produced different artifacts")
	}
}

// ---- the issuer cannot mint a widening delegation --------------------------

func TestIssuerRefusesBroadeningDelegation(t *testing.T) {
	spec, ks := loadExample(t)
	// Hop 2 tries to raise the ceiling its parent set at 100.
	spec.Hops[2].Caveats = []CaveatSpec{{Field: "amount", Op: "<=", Value: "500"}}

	_, err := publish(spec, ks, t.TempDir(), filepath.Join(t.TempDir(), "chain.json"))
	if err == nil {
		t.Fatal("the issuer must not be able to mint a broadening delegation")
	}
	if !strings.Contains(err.Error(), "does not narrow") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestIssuerRefusesChainDeeperThanMaxDepth is the issuance half of the delegation
// depth cap: minting a chain one hop past chain.MaxDepth is rejected. Only
// validate() is reached (it rejects on depth before any key is touched) so the
// synthetic hops need continuity but no keystore entries. The verification half
// lives in internal/chain (TestVerify_OverMaxDepthFails).
func TestIssuerRefusesChainDeeperThanMaxDepth(t *testing.T) {
	spec, ks := loadExample(t)
	hops := make([]HopSpec, chain.MaxDepth+1)
	prev := types.DID(didAlice)
	for i := range hops {
		subject := types.DID(fmt.Sprintf("did:web:localhost:agents:p%d", i))
		hops[i] = HopSpec{Issuer: prev, Subject: subject}
		prev = subject
	}
	spec.Hops = hops

	_, err := publish(spec, ks, t.TempDir(), filepath.Join(t.TempDir(), "chain.json"))
	if err == nil {
		t.Fatalf("issuer must refuse a chain of %d hops (cap is %d)", chain.MaxDepth+1, chain.MaxDepth)
	}
	if !strings.Contains(err.Error(), "max delegation depth") {
		t.Fatalf("rejection should name the depth cap, got: %v", err)
	}
}

func TestSpecValidation(t *testing.T) {
	base, ks := loadExample(t)
	cases := []struct {
		name   string
		break_ func(s *Spec)
	}{
		{"broken continuity", func(s *Spec) { s.Hops[1].Issuer = didAlice }},
		{"self delegation", func(s *Spec) { s.Hops[0].Subject = s.Hops[0].Issuer }},
		{"no hops", func(s *Spec) { s.Hops = nil }},
		{"no status issuer", func(s *Spec) { s.Status.Issuer = "" }},
		{"no root key", func(s *Spec) { s.RootKeyHex = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *base
			s.Hops = append([]HopSpec(nil), base.Hops...)
			tc.break_(&s)
			if _, err := publish(&s, ks, t.TempDir(), filepath.Join(t.TempDir(), "chain.json")); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

// A DID with a traversal segment must never become a write outside the root.
func TestPathTraversalRefused(t *testing.T) {
	_, ks := loadExample(t)
	evil := types.DID("did:web:localhost:..:..:etc:pwned")
	ks[evil] = ks[didAcme]
	s, err := ks.Signer(didAcme)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := did.WriteDocument(t.TempDir(), did.NewDocument(evil, s.Public())); err == nil {
		t.Fatal("a did:web with a '..' segment must be refused, not written")
	}
	if _, err := status.PublishPath(t.TempDir(), "https://localhost/../../etc/pwned.json"); err == nil {
		t.Fatal("a status URL with a '..' segment must be refused")
	}
}

// ---- steps 11 -> 10 compose, with no hosted assumption ---------------------

// TestIssuerOutputVerifiesWithTheVerifier is the composition proof: the issuer
// publishes, an enforcement point logs an action against the issued chain, and
// the independent verifier re-derives the verdict using ONLY the issuer's static
// files. Then the issuer revokes a mid-chain credential and the very same export
// starts failing, the whole revocation story, end to end, with no service.
func TestIssuerOutputVerifiesWithTheVerifier(t *testing.T) {
	root, res, spec, ks := publishTo(t)

	// An enforcement point records one allowed, consequential action.
	gatekeeper, err := ks.Signer(didProxy)
	if err != nil {
		t.Fatal(err)
	}
	set := export.NewCredentialSet()
	var ids []string
	for _, l := range res.Chain.Links {
		id, err := set.Add(l.Credential, l.IssuerProof)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	terminal := res.Chain.Links[len(res.Chain.Links)-1].Credential
	helper, err := ks.Signer(didHelper)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	// Amount 100 is at the commerce policy's consequentiality threshold, so the
	// verifier's F1 re-derivation agrees the action is consequential.
	act := types.Action{Type: "payment.transfer", Target: "acct/999",
		Attributes: map[string]string{"amount": "100"}, Timestamp: ts}
	pop, err := terminal.ProvePossession(helper, []byte("nonce-issuer-e2e"), act, 0, audit.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}

	// A consequential allow requires a human approval: alice approves the actor.
	alice, err := ks.Signer(didAlice)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := audit.SignApproval(alice, terminal.Subject, act, 0, audit.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	// The verifier re-derives consequentiality from the carried policy (F1), so
	// carry the commerce policy and pin it in the entry.
	pol, err := policy.Load("../../examples/policies/commerce-security.json")
	if err != nil {
		t.Fatal(err)
	}
	polID, err := export.PolicyID(pol)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.NewLog(gatekeeper)
	if _, err := log.Append(audit.EntryDraft{
		Action:             act,
		ResolvedChain:      res.Chain.Principals(),
		ChainCredentialIDs: ids,
		PolicyID:           polID,
		// Both hops in the issuer's example spec carry a statusIndex, so the
		// verifier re-derives 2 status-checked hops from the credential evidence
		// and this entry must record 2 (R2-01).
		Decision: types.Decision{Allowed: true, Consequential: true, StatusCheckedHops: 2,
			RuleFired: "high-value-transfer", PolicyVersion: "commerce-security-v1", Reason: "within scope"},
		PoPNonce: pop.Nonce, PoPSignature: pop.Signature,
		ApprovedBy: didAlice, Approval: approval,
		Timestamp: ts,
	}); err != nil {
		t.Fatal(err)
	}
	exp, err := export.Build(gatekeeper, log.Entries(), set, pol)
	if err != nil {
		t.Fatal(err)
	}

	verifyNow := func() *export.Result {
		t.Helper()
		list, err := status.Load(res.StatusPath) // re-read: revocation rewrites it
		if err != nil {
			t.Fatal(err)
		}
		out, err := export.Verify(exp, export.Inputs{
			DIDs:   did.FileResolver{Root: root},
			Status: export.MapStatusResolver{spec.Status.URL: list},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Before revocation: the verifier re-derives the allow from the issuer's
	// static artifacts alone.
	if out := verifyNow(); !out.Pass() {
		t.Fatalf("issued chain should verify end to end: %s", out.Entries[0].Reason)
	}

	// The issuer revokes the MID-CHAIN acme -> worker credential (index 42) by
	// rewriting one static file. Nothing is notified; nothing calls home.
	if _, err := revoke(spec, ks, root, 42, false); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	out := verifyNow()
	if out.Pass() {
		t.Fatal("after mid-chain revocation the same export must stop verifying")
	}
	if r := out.Entries[0].Reason; !strings.Contains(r, "revoked") || !strings.Contains(r, didWorker) {
		t.Fatalf("failure should name the revoked mid-chain hop: %q", r)
	}

	// And un-revoking restores it, the status list is the only moving part.
	if _, err := revoke(spec, ks, root, 42, true); err != nil {
		t.Fatal(err)
	}
	if out := verifyNow(); !out.Pass() {
		t.Fatalf("un-revoking should restore the verdict: %s", out.Entries[0].Reason)
	}
}

// ---- CLI -------------------------------------------------------------------

func TestCLI_PublishAndRevoke(t *testing.T) {
	root := t.TempDir()
	chainOut := filepath.Join(t.TempDir(), "chain.json")

	code, out, errb := invoke(t, "publish", "--spec", specPath, "--keystore", ksPath, "--root", root, "--out", chainOut)
	if code != exitOK {
		t.Fatalf("publish exit=%d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "kept OUT of the public root") {
		t.Fatalf("publish should say where credentials went:\n%s", out)
	}
	if _, err := os.Stat(chainOut); err != nil {
		t.Fatalf("chain not written: %v", err)
	}

	code, out, errb = invoke(t, "revoke", "--spec", specPath, "--keystore", ksPath, "--root", root, "--index", "42")
	if code != exitOK {
		t.Fatalf("revoke exit=%d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "nothing calls home") {
		t.Fatalf("revoke should state the propagation model:\n%s", out)
	}
}

// TestCLI_Enroll drives the enroll subcommand end to end against a published
// root: it mints a software P-256 device key, writes the org->employee credential
// and mapping, and the credential verifies as a one-hop chain using only the
// published DID documents.
func TestCLI_Enroll(t *testing.T) {
	root, _, spec, _ := publishTo(t)
	mapPath := filepath.Join(t.TempDir(), "map.json")
	credOut := filepath.Join(t.TempDir(), "cred.json")
	deviceDID := "did:web:localhost:employees:alice-laptop"

	code, out, errb := invoke(t, "enroll",
		"--identity", "alice@acme.example",
		"--did", deviceDID,
		"--org-did", didAcme,
		"--keystore", ksPath,
		"--root-key-hex", spec.RootKeyHex,
		"--identifier", "acme-alice-laptop",
		"--status-url", spec.Status.URL,
		"--status-index", "9",
		"--root", root,
		"--mapping", mapPath,
		"--out", credOut,
		"--software-key",
		"--yes",
	)
	if code != exitOK {
		t.Fatalf("enroll exit=%d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "SHA256:") {
		t.Fatalf("enroll should print a fingerprint:\n%s", out)
	}
	if !strings.Contains(out, "NON-PRODUCTION software key") {
		t.Fatalf("a --software-key enroll must warn it is not hardware-backed:\n%s", out)
	}

	data, err := os.ReadFile(credOut)
	if err != nil {
		t.Fatalf("credential not written: %v", err)
	}
	ch, err := chain.Parse(data)
	if err != nil {
		t.Fatalf("parse minted credential: %v", err)
	}
	if err := ch.Verify(did.FileResolver{Root: root}); err != nil {
		t.Fatalf("enrolled credential must verify against the published root: %v", err)
	}
	if ch.Root() != didAcme || string(ch.Actor()) != deviceDID {
		t.Fatalf("minted hop is not org->employee: root=%q actor=%q", ch.Root(), ch.Actor())
	}
}

// TestDaemon_RefusesSoftwareEnrolledApprovalKey is the daemon-wiring half of
// R4-02: an enrolled key recorded as software-backed is approval-capable, so the
// daemon must refuse to broker it (it cannot back the human-approval control).
// Exercises loadEnrolledKeys directly, which is where the refusal lives.
func TestDaemon_RefusesSoftwareEnrolledApprovalKey(t *testing.T) {
	mapPath := filepath.Join(t.TempDir(), "map.json")
	m := enroll.NewMapping()
	if err := m.AddCredential("alice@acme.example", enroll.Credential{
		DID:        "did:web:localhost:employees:alice-laptop",
		KeyBackend: enroll.BackendSoftware,
		KeyTag:     "kessa-issuer:alice",
		Algorithm:  "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(mapPath); err != nil {
		t.Fatal(err)
	}
	_, err := loadEnrolledKeys(mapPath)
	if err == nil || !strings.Contains(err.Error(), "SOFTWARE") {
		t.Fatalf("a software-enrolled approval key must be refused, got %v", err)
	}
}

func TestCLI_UsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"publish"}, // no --spec/--keystore
		{"revoke", "--spec", specPath, "--keystore", ksPath}, // no --index
		{"enroll"}, // no required flags
	} {
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Fatalf("args %v: exit=%d, want %d", args, code, exitUsage)
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	return run(args, &out, &errb), out.String(), errb.String()
}

func ptr[T any](v T) *T { return &v }

// didWebURLPath derives the HTTP path a did:web document is served at.
func didWebURLPath(t *testing.T, d types.DID) string {
	t.Helper()
	rest := strings.TrimPrefix(string(d), "did:web:")
	fields := strings.Split(rest, ":")
	if len(fields) == 1 {
		return "/.well-known/did.json"
	}
	return "/" + strings.Join(fields[1:], "/") + "/did.json"
}

func httpGet(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDaemon_AttestationKeyClassification: --attestation-key reclassifies exactly
// the named keystore DIDs and leaves every other key ROUTINE. The negative half
// matters as much as the positive one: a flag that promoted everything, or
// nothing, would still produce a daemon that starts and brokers keys.
func TestDaemon_AttestationKeyClassification(t *testing.T) {
	ks, err := loadJSON[Keystore](ksPath)
	if err != nil {
		t.Fatal(err)
	}
	principals := ks.Principals()
	if len(principals) < 2 {
		t.Fatalf("this test needs a keystore with at least two principals, got %d", len(principals))
	}
	chosen := principals[0]

	keys, err := keystoreKeys(ks, didList{chosen})
	if err != nil {
		t.Fatalf("keystoreKeys: %v", err)
	}
	if len(keys) != len(principals) {
		t.Fatalf("brokered %d keys from a keystore of %d principals", len(keys), len(principals))
	}

	var attested int
	for _, k := range keys {
		want := signerd.Routine
		if k.Signer.DID() == chosen {
			want = signerd.Attestation
			attested++
		}
		if k.Policy != want {
			t.Errorf("key %s classified %s, want %s", k.Signer.DID(), k.Policy, want)
		}
	}
	if attested != 1 {
		t.Fatalf("%d keys were promoted to attestation, want exactly 1", attested)
	}

	// With no flag at all, nothing is promoted.
	plain, err := keystoreKeys(ks, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plain {
		if k.Policy != signerd.Routine {
			t.Errorf("without --attestation-key, %s was classified %s", k.Signer.DID(), k.Policy)
		}
	}
}

// TestDaemon_AttestationKeyMustBeHeld: naming a DID the keystore does not hold is
// refused rather than ignored. Ignoring it would broker the operator's intended
// enforcement-point key as ROUTINE and report success, so the mistake would only
// show up as a mislabelled key table nobody reads.
func TestDaemon_AttestationKeyMustBeHeld(t *testing.T) {
	ks, err := loadJSON[Keystore](ksPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = keystoreKeys(ks, didList{"did:web:localhost:proxies:not-in-this-keystore"})
	if err == nil || !strings.Contains(err.Error(), "not in the keystore") {
		t.Fatalf("an unheld --attestation-key must be refused, got %v", err)
	}

	// Same refusal through the CLI, and --attestation-key without --keystore has
	// nothing to name at all.
	code, _, errOut := invoke(t, "daemon", "--keystore", ksPath,
		"--attestation-key", "did:web:localhost:proxies:not-in-this-keystore")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "not in the keystore") {
		t.Fatalf("stderr %q does not name the problem", errOut)
	}

	code, _, errOut = invoke(t, "daemon", "--mapping", filepath.Join(t.TempDir(), "absent.json"),
		"--attestation-key", "did:web:localhost:proxies:gatekeeper")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "--keystore") {
		t.Fatalf("stderr %q does not say the flag needs a keystore", errOut)
	}
}
