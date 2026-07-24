// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package perf

import (
	"fmt"
	"testing"

	"github.com/Gneiss-Group/Kessa/internal/chain"
	"github.com/Gneiss-Group/Kessa/internal/credential"
	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/internal/signer"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// Task C, chain-depth cost (optional add-on).
//
// chain.Verify walks every hop, and each hop is two DID resolutions (issuer key +
// subject key) plus one Ed25519 issuance verify plus a structural attenuation
// check. MaxDepth caps a chain at 8 hops. This sweeps depths 1..8 to report
// whether verification cost scales linearly, worse, or negligibly across the
// allowed range. Depth is the variable; nothing else changes.
//
// Deeper-than-demo chains need published DID documents for each principal, so the
// harness generates a fresh did:web tree in a temp dir (via did.WriteDocument) and
// resolves the synthetic chain against it, exactly the offline, public-document
// resolution the real verifier uses, just with more principals.

func BenchmarkChainVerify_Depth(b *testing.B) {
	for depth := 1; depth <= chain.MaxDepth; depth++ {
		ch, resolver := deepChain(b, depth)
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			// Sanity: the chain must actually verify, or we'd be timing an error path.
			if err := ch.Verify(resolver); err != nil {
				b.Fatalf("depth %d chain does not verify: %v", depth, err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ch.Verify(resolver); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

// deepChain mints a strictly-attenuating delegation chain of `depth` hops
// (p0 -> p1 -> ... -> pDepth), publishes a did:web document for every principal
// into a temp directory, and returns the chain plus a file resolver over that
// directory. Each hop adds a caveat on a unique field, so every child strictly
// narrows its parent and chain.Verify's attenuation check passes.
func deepChain(b *testing.B, depth int) (*chain.Chain, did.Resolver) {
	b.Helper()
	root := b.TempDir()

	principal := func(i int) types.DID { return types.DID(fmt.Sprintf("did:web:localhost:perf:p%d", i)) }
	signerFor := func(i int) signer.Signer {
		s, err := signer.NewSoftwareSignerFromSeed(principal(i), seed32(byte(0x80+i)))
		if err != nil {
			b.Fatalf("signer p%d: %v", i, err)
		}
		return s
	}

	// Publish a DID document for each of the depth+1 principals.
	signers := make([]signer.Signer, depth+1)
	for i := 0; i <= depth; i++ {
		signers[i] = signerFor(i)
		doc := did.NewDocument(principal(i), signers[i].Public())
		if _, err := did.WriteDocument(root, doc); err != nil {
			b.Fatalf("write did p%d: %v", i, err)
		}
	}

	// Build the chain, adding one narrowing caveat per hop.
	m := macaroon.Mint(seed32(0x01), "perf-deep", string(principal(0)))
	links := make([]chain.Link, 0, depth)
	for i := 0; i < depth; i++ {
		var err error
		m, err = macaroon.Attenuate(m, macaroon.Caveat{
			Field: fmt.Sprintf("f%d", i), Op: macaroon.OpEq, Value: "v",
		})
		if err != nil {
			b.Fatalf("attenuate hop %d: %v", i, err)
		}
		issuer, subject := principal(i), principal(i+1)
		c, err := credential.New(credential.Options{
			Subject: subject, Issuer: issuer, Macaroon: m, HolderKey: signers[i+1].Public(),
		})
		if err != nil {
			b.Fatalf("credential hop %d: %v", i, err)
		}
		proof, err := chain.SignIssuance(signers[i], c)
		if err != nil {
			b.Fatalf("sign issuance hop %d: %v", i, err)
		}
		links = append(links, chain.Link{Credential: *c, IssuerProof: proof})
	}
	return &chain.Chain{Links: links}, did.FileResolver{Root: root}
}
