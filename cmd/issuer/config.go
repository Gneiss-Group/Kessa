// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/config"
	"github.com/Gneiss-Group/Kessa/internal/signerd"
	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// DaemonConfig is the on-disk configuration for `kessa-issuer daemon`.
//
// The `flag` struct tag names the CLI flag each field replaces, and the set of
// flags refused alongside --config is derived from these tags rather than kept in
// a list beside them (internal/config.FlagNames). A field added here extends that
// set by itself.
type DaemonConfig struct {
	// Comment is accepted and ignored: a declared field, not a tolerated unknown
	// key. See docs/configuration.md.
	Comment string `json:"comment,omitempty"`

	// Sock is REQUIRED and has no absent state, which is a different reason from
	// every other required field here.
	//
	// The flag's default is derived from the ENVIRONMENT ($XDG_RUNTIME_DIR, else
	// $HOME), so an omitted sock would mean the socket lands wherever the invoking
	// shell happens to point. A config file exists to describe a deployment
	// completely, and a path that changes with the caller's environment is the
	// implicitness it is meant to remove.
	//
	// It also has to agree with the proxy's `enforcement_point.key.broker_socket`,
	// which is always a literal path. Letting one side be environment-derived and
	// the other literal is a silent mismatch: the daemon comes up on a path the
	// proxy is not looking at, and the proxy fails at startup pointing at a socket
	// that does not exist.
	Sock string `json:"sock" flag:"sock"`

	// Keystore holds software keys brokered as ROUTINE (proof-of-possession).
	// Absent means the daemon brokers none.
	Keystore string `json:"keystore,omitempty" flag:"keystore"`

	// Mapping loads enrolled Secure Enclave keys as APPROVAL-capable keys. Absent
	// means the daemon brokers none.
	Mapping string `json:"mapping,omitempty" flag:"mapping"`

	// AttestationKeys names keystore DIDs to broker as ATTESTATION keys, an
	// enforcement point's own audit-signing key, rather than routine PoP keys.
	// Absent means none are promoted.
	AttestationKeys []types.DID `json:"attestation_keys,omitempty" flag:"attestation-key"`
}

func daemonSchemaFlags() map[string]bool { return config.FlagNames(DaemonConfig{}) }

func daemonConflictingFlags(fs *flag.FlagSet) []string {
	return config.Conflicting(fs, daemonSchemaFlags())
}

// loadDaemonConfig reads and validates a daemon config. It performs no side
// effects: no socket is created, no key is materialized.
func loadDaemonConfig(path string) (*DaemonConfig, error) {
	var cfg DaemonConfig
	if err := config.Load(path, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *DaemonConfig) validate() error {
	if strings.TrimSpace(c.Sock) == "" {
		return errors.New("sock is required: name the Unix socket this daemon listens on. " +
			"It has no default here because the flag's default is derived from the environment, " +
			"and a proxy's broker_socket names a literal path that has to match it")
	}
	if strings.TrimSpace(c.Keystore) == "" && strings.TrimSpace(c.Mapping) == "" {
		return errors.New("one of keystore or mapping is required: a daemon with no key source has nothing to broker")
	}
	if len(c.AttestationKeys) > 0 && strings.TrimSpace(c.Keystore) == "" {
		return errors.New("attestation_keys names DIDs from keystore, which is not set")
	}
	for _, d := range c.AttestationKeys {
		if strings.TrimSpace(string(d)) == "" {
			return errors.New("attestation_keys contains an empty DID")
		}
	}
	return nil
}

// reportDaemonCheck prints what --check-config verified and how deep it reached.
//
// The daemon tops out at depth 2 and says so. It dials nothing: its equivalent of
// the proxy's live check is BINDING its socket, which is a side effect the check
// must not perform. Claiming a depth 3 here would be inventing one, so the last
// line states the limit rather than implying the check proved more than it did.
func reportDaemonCheck(w io.Writer, cfgPath, dirState string, keys []signerd.HeldKey) {
	fmt.Fprintf(w, "kessa-issuer: checked %s\n", cfgPath)
	fmt.Fprintln(w, "  schema           OK  parsed, no unknown fields, required fields present")
	// The socket DIRECTORY is checkable without binding, and it is where the
	// daemon's only side effect outside its own files used to land unannounced.
	// Saying whether it will be created or was found already correct is the
	// difference between a check that predicts the start and one that omits the
	// part an operator cannot see coming.
	fmt.Fprintf(w, "  socket dir       OK  %s\n", dirState)
	fmt.Fprintf(w, "  keys             OK  %d brokerable, hardware policy satisfied\n", len(keys))
	for _, k := range heldKeysSorted(keys) {
		fmt.Fprintf(w, "    %-11s %s\n", k.Policy, k.Signer.DID())
	}
	fmt.Fprintln(w, "\nChecked to depth 2 (referential). The socket was NOT bound, since binding it")
	fmt.Fprintln(w, "is the side effect this check exists to avoid; a daemon already holding that")
	fmt.Fprintln(w, "path would still refuse the real start.")
}
