// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/enroll"
	"github.com/Gneiss-Group/Kessa/internal/macaroon"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// caveatList collects repeated -caveat "field:op:value" flags.
type caveatList []macaroon.Caveat

func (c *caveatList) String() string { return fmt.Sprintf("%d caveat(s)", len(*c)) }

func (c *caveatList) Set(s string) error {
	// SplitN on the first two colons only, so an RFC3339 value ("...T00:00:00Z")
	// keeps its own colons intact.
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("caveat %q must be field:op:value", s)
	}
	*c = append(*c, macaroon.Caveat{
		Field: parts[0],
		Op:    macaroon.Op(parts[1]),
		Value: parts[2],
	})
	return nil
}

// cmdEnroll runs the on-device enrollment ceremony: generate the employee/device
// key, confirm it trust-on-first-use, publish its DID document, mint the
// org->employee credential, and record it in the employee->credential mapping.
func cmdEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)

	identity := fs.String("identity", "", "durable employee label the credential is grouped under, e.g. an email (required)")
	deviceDID := fs.String("did", "", "this device's employee DID (credential subject) (required)")
	orgDID := fs.String("org-did", "", "issuing organization DID (credential issuer) (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON: DID -> hex seed, holding the org signing key (required)")
	rootKeyHex := fs.String("root-key-hex", "", "org macaroon root key (hex); prefer --root-key-file to keep it out of argv")
	rootKeyFile := fs.String("root-key-file", "", "file containing the org macaroon root key (hex); preferred over --root-key-hex")
	fetchOrgDID := fs.Bool("fetch-org-did", false, "preflight the org DID over HTTPS (did:web) instead of the local publication root")
	identifier := fs.String("identifier", "", "macaroon identifier for this credential (required)")
	location := fs.String("location", "", "macaroon location (informational)")
	statusURL := fs.String("status-url", "", "status list URL this credential's revocation bit lives in (required)")
	statusIndex := fs.Int("status-index", -1, "status list bit for this credential (required, >= 0)")
	root := fs.String("root", "public", "publication root: where the device DID document is written and the org DID is resolved")
	mappingPath := fs.String("mapping", "enrollment-map.json", "employee->credential mapping file (created if absent)")
	out := fs.String("out", "credential.json", "where to write the minted org->employee credential (kept OUT of --root)")
	softwareKey := fs.Bool("software-key", false, "mint a NON-PRODUCTION software P-256 device key instead of using the secure element")
	seedHex := fs.String("seed-hex", "", "deterministic 32-byte seed (hex) for the software device key; fixtures/tests only")
	tag := fs.String("tag", "", "keychain tag to persist the secure-element key under (default derived from the DID)")
	yes := fs.Bool("yes", false, "skip the interactive fingerprint confirmation (non-interactive enrollment)")

	var caveats caveatList
	fs.Var(&caveats, "caveat", "grant-scoping caveat 'field:op:value' (repeatable)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// Resolve the org macaroon root key, preferring a file (keeps the secret out of
	// argv / shell history, R4-04) over the inline hex flag.
	rootHex := *rootKeyHex
	if *rootKeyFile != "" {
		b, err := os.ReadFile(*rootKeyFile)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: read --root-key-file: %v\n", err)
			return exitUsage
		}
		rootHex = strings.TrimSpace(string(b))
	}
	if *identity == "" || *deviceDID == "" || *orgDID == "" || *ksPath == "" ||
		rootHex == "" || *identifier == "" || *statusURL == "" || *statusIndex < 0 {
		fmt.Fprintln(stderr, "kessa-issuer: --identity, --did, --org-did, --keystore, one of --root-key-file/--root-key-hex, --identifier, --status-url, and --status-index are required")
		return exitUsage
	}

	ks, err := loadJSON[Keystore](*ksPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	orgSigner, err := ks.Signer(types.DID(*orgDID))
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	rootKey, err := hex.DecodeString(rootHex)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: org macaroon root key is not hex: %v\n", err)
		return exitUsage
	}

	dev := enroll.DeviceKeyOptions{ForceSoftware: *softwareKey}
	if *seedHex != "" {
		seed, err := hex.DecodeString(*seedHex)
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: --seed-hex is not hex: %v\n", err)
			return exitUsage
		}
		dev.Seed = seed
	}
	if *tag != "" {
		dev.Tag = []byte(*tag)
	} else {
		dev.Tag = []byte("kessa-issuer:" + *deviceDID)
	}

	cfg := enroll.Config{
		Identity:        *identity,
		DeviceDID:       types.DID(*deviceDID),
		OrgDID:          types.DID(*orgDID),
		OrgSigner:       orgSigner,
		MacaroonRootKey: rootKey,
		Identifier:      *identifier,
		Location:        *location,
		Caveats:         caveats,
		StatusURL:       *statusURL,
		StatusIndex:     *statusIndex,
		Root:            *root,
		MappingPath:     *mappingPath,
		CredentialOut:   *out,
		Device:          dev,
		Backend:         enroll.LocalTOFU{In: os.Stdin, Out: stderr, AssumeYes: *yes},
	}
	// SO-1: preflight the org DID over the network (real did:web reachability)
	// instead of the local publication root, when asked.
	if *fetchOrgDID {
		// The permitted host is DERIVED from the org DID rather than configured,
		// and that is the whole difference between this call site and the
		// verifier's. Here the only DID resolved is the one the operator just
		// named on the command line, so the host it implies is already an operator
		// decision and asking for it twice would be ceremony. In the verifier the
		// DIDs come from the export under audit, so the hosts have to be named
		// separately or the artifact would choose its own trust root.
		host, _, err := did.ParseWebHost(types.DID(*orgDID))
		if err != nil {
			fmt.Fprintf(stderr, "kessa-issuer: --fetch-org-did: %v\n", err)
			return exitUsage
		}
		cfg.Resolver = did.HTTPResolver{AllowedHosts: []string{host}}
	}
	res, err := enroll.Enroll(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}

	fmt.Fprintf(stdout, "enrolled %s\n", res.Identity)
	fmt.Fprintf(stdout, "  device DID    %s\n", res.DeviceDID)
	fmt.Fprintf(stdout, "  key          %s (%s)\n", res.Key.Backend, res.Key.Algorithm)
	fmt.Fprintf(stdout, "  fingerprint  %s\n", res.Key.Fingerprint)
	fmt.Fprintf(stdout, "  backend      %s\n", res.BackendName)
	fmt.Fprintf(stdout, "  DID document %s\n", res.DIDDocPath)
	fmt.Fprintf(stdout, "  credential   %s  (%s)\n", res.CredentialOut, res.CredentialID)
	fmt.Fprintf(stdout, "  mapping      %s  (status[%d] revokes this device)\n", res.MappingPath, *statusIndex)
	if res.Key.Backend == "software" {
		fmt.Fprintf(stdout, "\nNOTE: this is a NON-PRODUCTION software key; it is not hardware-backed.\n")
	}
	return exitOK
}
