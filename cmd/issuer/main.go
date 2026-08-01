// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

// Command kessa-issuer mints delegation credentials and publishes the public
// artifacts a verifier needs: did:web documents and a signed bitstring status
// list.
//
// Self-hostable first. The issuer's entire public output is a directory of plain
// JSON files laid out at exactly the paths did:web resolution and the status URL
// imply. That directory is simultaneously:
//
//   - a static website (drop it on Cloudflare Pages, nginx, S3, anything), and
//   - a local directory an offline verifier reads with `kessa verify --dids <dir>`.
//
// There is no Kessa service in that loop, and the hostname in the DIDs and the
// status URL is the operator's, not ours, it may be an internal-only or
// air-gapped name that resolves nowhere on the public internet. `serve` exists
// only so the demo can exercise did:web over HTTP; it is a plain static file
// server with no application logic, and deleting it would change nothing.
//
// Secrets never enter the publication root: the minted credentials are written
// to a separate path, and private keys are never written at all.
//
// Exit codes: 0 = ok, 2 = usage or I/O error.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Gneiss-Group/Kessa/internal/version"
)

const (
	exitOK    = 0
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: kessa-issuer <command> [flags]

  publish  mint the delegation chain; write did:web docs + signed status list
  revoke   flip a credential's bit in the published status list and re-sign
  serve    serve the publication root over HTTP (static files; demo only)
  daemon   run the on-device signing daemon (brokers keys over a local socket)

  --version  print the build version and exit
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if version.Requested(args) {
		fmt.Fprintln(stdout, version.Current().String("kessa-issuer"))
		return exitOK
	}
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "publish":
		return cmdPublish(args[1:], stdout, stderr)
	case "revoke":
		return cmdRevoke(args[1:], stdout, stderr)
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "daemon":
		return cmdDaemon(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return exitUsage
	}
}

// loadInputs reads the spec and keystore shared by publish and revoke.
func loadInputs(specPath, ksPath string, stderr io.Writer) (*Spec, Keystore, bool) {
	if specPath == "" || ksPath == "" {
		fmt.Fprintln(stderr, "kessa-issuer: --spec and --keystore are required")
		return nil, nil, false
	}
	spec, err := loadJSON[Spec](specPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return nil, nil, false
	}
	ks, err := loadJSON[Keystore](ksPath)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return nil, nil, false
	}
	return &spec, ks, true
}

func cmdPublish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "delegation spec JSON (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON: DID -> hex seed (required)")
	root := fs.String("root", "public", "publication root: the static, public artifact directory")
	chainOut := fs.String("out", "chain.json", "where to write the minted credentials (NOT inside --root)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	spec, ks, ok := loadInputs(*specPath, *ksPath, stderr)
	if !ok {
		return exitUsage
	}

	res, err := publish(spec, ks, *root, *chainOut)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}

	fmt.Fprintf(stdout, "published %d DID documents under %s/\n", len(res.DIDDocs), res.Root)
	for _, p := range res.DIDDocs {
		fmt.Fprintf(stdout, "  %s\n", p)
	}
	fmt.Fprintf(stdout, "status list  %s  (%s)\n", res.StatusPath, spec.Status.URL)
	fmt.Fprintf(stdout, "credentials  %s  (kept OUT of the public root)\n", res.ChainPath)
	for i, id := range res.CredentialIDs {
		h := spec.Hops[i]
		idx := "-"
		if h.StatusIndex != nil {
			idx = fmt.Sprintf("%d", *h.StatusIndex)
		}
		fmt.Fprintf(stdout, "  hop %d  %s -> %s  status[%s]  %s\n", i, h.Issuer, h.Subject, idx, id)
	}
	fmt.Fprintf(stdout, "\nverify offline with:\n  kessa verify --export <export.json> --dids %s --status \"%s=%s\"\n",
		res.Root, spec.Status.URL, res.StatusPath)
	if site, err := SiteRoot(res.Root, ""); err == nil {
		fmt.Fprintf(stdout, "\nor host it statically (the root is host-partitioned; serve one host's dir):\n  %s\n", site)
	}
	return exitOK
}

func cmdRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "delegation spec JSON (required)")
	ksPath := fs.String("keystore", "", "MOCK keystore JSON (required)")
	root := fs.String("root", "public", "publication root")
	index := fs.Int("index", -1, "status list bit to flip (required)")
	clear := fs.Bool("clear", false, "clear the bit (un-revoke) instead of setting it")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *index < 0 {
		fmt.Fprintln(stderr, "kessa-issuer: --index is required and must be >= 0")
		return exitUsage
	}
	spec, ks, ok := loadInputs(*specPath, *ksPath, stderr)
	if !ok {
		return exitUsage
	}

	path, err := revoke(spec, ks, *root, *index, *clear)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	verb := "revoked"
	if *clear {
		verb = "un-revoked"
	}
	fmt.Fprintf(stdout, "%s index %d; re-signed and republished %s\n", verb, *index, path)
	fmt.Fprintf(stdout, "propagation is your static host's cache policy — nothing calls home\n")
	return exitOK
}

// SiteRoot returns the document root to serve for a given host.
//
// The publication root is HOST-PARTITIONED: artifacts live at
// <root>/<host>/<path>, because one issuer may publish DIDs under several
// hostnames. A web server for `example.com` therefore serves <root>/example.com
// as its document root, not <root> itself. (did.FileResolver reads the same
// layout from the other side, which is why one directory satisfies both.)
//
// If host is empty and the root holds exactly one host, that one is used.
func SiteRoot(root, host string) (string, error) {
	if host != "" {
		return filepath.Join(root, host), nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read publication root %q: %w", root, err)
	}
	var hosts []string
	for _, e := range entries {
		if e.IsDir() {
			hosts = append(hosts, e.Name())
		}
	}
	if len(hosts) == 1 {
		return filepath.Join(root, hosts[0]), nil
	}
	return "", fmt.Errorf("publication root %q holds %d hosts %v; pass --host to choose one", root, len(hosts), hosts)
}

// cmdServe is a plain static file server over one host's document root. It
// exists only so the demo can resolve did:web over HTTP; any static host
// (Cloudflare Pages, nginx, S3) substitutes for it, and deleting it would change
// nothing about the artifacts.
func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "public", "publication root")
	host := fs.String("host", "", "which host's document root to serve (default: the only one)")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	site, err := SiteRoot(*root, *host)
	if err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	if _, err := os.Stat(site); err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "serving %s at http://%s (static files only)\n", site, *addr)
	if err := http.ListenAndServe(*addr, http.FileServer(http.Dir(site))); err != nil {
		fmt.Fprintf(stderr, "kessa-issuer: %v\n", err)
		return exitUsage
	}
	return exitOK
}
