// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Gneiss-Group/Kessa/internal/config"
)

// Config is the on-disk configuration for `kessa-proxy serve`.
//
// WHY THIS EXISTS. Configuration and invocation used to be the same channel, and
// they collided. A container image's CMD carries the bind flags the image needs,
// and supplying `--policy`, `--dids` and the rest means overriding the command,
// which REPLACES the CMD rather than adding to it. So every real invocation had
// to restate a bind posture it never intended to change, and forgetting to was a
// refused start. The CMD in this repository shipped unstartable for months for
// exactly that reason.
//
// THE `flag` STRUCT TAG IS LOAD-BEARING, not documentation. It names the CLI flag
// each field replaces, and schemaFlags walks these tags to build the set of flags
// that may not be combined with --config. That is what makes the rule "a flag is
// refused alongside --config if and only if the schema covers it" derived rather
// than maintained: a field added here extends the refused set by itself. A
// hand-kept list would be enumerated-inclusion, and it would fail permissively,
// letting a newly added field be silently overridden by a stale launcher script.
//
// A field with NO `flag` tag is deliberately outside the schema and stays usable
// alongside --config. `comment` is one (it has no flag). So is `--now`, which is
// a determinism fixture for reproducible runs and must never become
// operator-facing surface; it appears nowhere in this struct, which is what keeps
// it available on the command line.
type Config struct {
	// Comment is accepted and ignored. JSON has no comments, and a config file is
	// exactly where someone wants to record why a field is set.
	//
	// It is a DECLARED field rather than a tolerated unknown key. Tolerating
	// unknown keys is what loadConfig refuses, and carving out a prefix like "_"
	// would reintroduce that under another name. It would also recreate the defect
	// the keystore fixtures caused: `kessa-issuer daemon` could not load either
	// keystore in this repository because a "_comment" entry was iterated as data.
	Comment string `json:"comment,omitempty"`

	Policy string `json:"policy" flag:"policy"`
	DIDs   string `json:"dids"   flag:"dids"`

	EnforcementPoint enforcementPointConfig `json:"enforcement_point"`

	HTTPAddr string `json:"http_addr,omitempty" flag:"http-addr"`
	MCPAddr  string `json:"mcp_addr,omitempty"  flag:"mcp-addr"`

	AllowUnauthenticatedRemote bool `json:"allow_unauthenticated_remote,omitempty" flag:"allow-unauthenticated-remote"`

	Export   string `json:"export,omitempty"    flag:"export"`
	AuditLog string `json:"audit_log,omitempty" flag:"audit-log"`

	// AuditWAL is REQUIRED and has no absent state: a path enables durability,
	// JSON null disables it.
	//
	// Raw, rather than *string, because *string cannot tell "absent" from "null":
	// both decode to nil, so a required check built on one would accept an omitted
	// key as a deliberate "off". That is a check that passes without testing
	// anything, on the one field where the difference matters most.
	//
	// It is required rather than defaulted because this is the only field where
	// "off" means the process promises LESS ABOUT WHAT IT RECORDED rather than
	// merely doing less: with durability off, an allowed action can be returned
	// and then lost in a crash. Whether durability should default ON is a separate,
	// tracked question (UPCOMING.md); it needs a WAL benchmark first and has to
	// change the flag path at the same time. Requiring the field gets the
	// fail-closed posture's benefit without answering that first.
	AuditWAL json.RawMessage `json:"audit_wal" flag:"audit-wal"`

	// Status maps a published status-list URL to the local file serving it, the
	// object form of the repeatable `--status url=file`.
	Status map[string]string `json:"status,omitempty" flag:"status"`
}

type enforcementPointConfig struct {
	DID string          `json:"did" flag:"enforcement-point"`
	Key keySourceConfig `json:"key"`
}

// keySourceConfig is tagged rather than two optional sibling fields, so the
// exclusivity is structural: "both set" and "neither set" are malformed shapes
// rather than well-formed shapes rejected afterwards. The runtime check below is
// still required, because JSON does not enforce it, but the schema says it too.
type keySourceConfig struct {
	// BrokerSocket is a running `kessa-issuer daemon`'s Unix socket. The private
	// key stays in the daemon; the proxy holds no key material.
	BrokerSocket string `json:"broker_socket,omitempty" flag:"signer-sock"`
	// MockKeystore is a JSON file holding this enforcement point's seed in the
	// clear. Evaluation only.
	MockKeystore string `json:"mock_keystore,omitempty" flag:"keystore"`
}

// schemaFlags returns every CLI flag name this schema can express, derived from
// the `flag` struct tags above rather than from a list kept beside them. The
// mechanism is shared: see internal/config.FlagNames for why it is derived.
func schemaFlags() map[string]bool { return config.FlagNames(Config{}) }

// conflictingFlags returns the flags explicitly set on fs that this schema also
// covers, sorted. See internal/config.Conflicting for why "explicitly set" is
// fs.Visit and never a comparison against defaults.
func conflictingFlags(fs *flag.FlagSet) []string {
	return config.Conflicting(fs, schemaFlags())
}

// loadConfig reads and validates a config file. It performs NO side effects: no
// file is created, no address is bound, no socket is dialed. Everything it can
// reject, it rejects before the caller does anything irreversible.
func loadConfig(path string) (*Config, error) {
	var cfg Config
	if err := config.Load(path, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	for name, v := range map[string]string{
		"policy":                c.Policy,
		"dids":                  c.DIDs,
		"enforcement_point.did": c.EnforcementPoint.DID,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	broker := strings.TrimSpace(c.EnforcementPoint.Key.BrokerSocket) != ""
	mock := strings.TrimSpace(c.EnforcementPoint.Key.MockKeystore) != ""
	switch {
	case broker && mock:
		return errors.New("enforcement_point.key sets both broker_socket and mock_keystore; name exactly one")
	case !broker && !mock:
		return errors.New("enforcement_point.key must set exactly one of broker_socket or mock_keystore")
	}

	if _, _, err := c.auditWAL(); err != nil {
		return err
	}

	for url, file := range c.Status {
		if strings.TrimSpace(url) == "" {
			return errors.New("status has an empty URL key")
		}
		if strings.TrimSpace(file) == "" {
			return fmt.Errorf("status %q names an empty file", url)
		}
	}
	return nil
}

// auditWAL resolves the required audit_wal field: a path enables durability, JSON
// null disables it, and absence is an error rather than a synonym for either.
func (c *Config) auditWAL() (path string, enabled bool, err error) {
	raw := bytes.TrimSpace(c.AuditWAL)
	if len(raw) == 0 {
		return "", false, errors.New("audit_wal is required: give a path to enable the durable write-ahead log, " +
			"or null to run without durability. It has no default because turning it off means an allowed action " +
			"can be returned and then lost in a crash, which is a decision to take rather than inherit")
	}
	if bytes.Equal(raw, []byte("null")) {
		return "", false, nil
	}
	var p string
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", false, fmt.Errorf("audit_wal must be a path string or null: %w", err)
	}
	if strings.TrimSpace(p) == "" {
		return "", false, errors.New(`audit_wal is an empty string; use null to disable durability, so that "off" is stated rather than implied`)
	}
	return p, true, nil
}

// reportConfigCheck prints what --check-config actually verified, and how deep it
// got.
//
// It states the DEPTH rather than a bare "OK". A check that only proved the JSON
// parses, reported as "valid", is the same shape as a gate that passes by not
// running: most of what breaks a real start lives in the files the config names
// and in the daemon it points at, not in its syntax. An operator has to be able
// to tell "this will start" from "this is well-formed", so the last line says
// which claim was earned.
func reportConfigCheck(w io.Writer, cfgPath, sockPath string, listenAddrs []string, statuses statusFlag) {
	var enabled []string
	for _, a := range listenAddrs {
		if strings.TrimSpace(a) != "" {
			enabled = append(enabled, a)
		}
	}

	fmt.Fprintf(w, "kessa-proxy: checked %s\n", cfgPath)
	fmt.Fprintln(w, "  schema           OK  parsed, no unknown fields, required fields present")
	fmt.Fprintf(w, "  listeners        OK  %s\n", strings.Join(enabled, ", "))
	fmt.Fprintf(w, "  policy and DIDs  OK  loaded from the paths named\n")
	if len(statuses) == 0 {
		fmt.Fprintln(w, "  status lists     none configured")
	} else {
		fmt.Fprintf(w, "  status lists     OK  %d loaded and signature-checked\n", len(statuses))
	}

	if sockPath != "" {
		fmt.Fprintf(w, "  signing daemon   OK  answered on %s and holds this enforcement point's key\n", sockPath)
		fmt.Fprintln(w, "\nChecked to depth 3 (live). This configuration should start here.")
		return
	}
	fmt.Fprintln(w, "  key source       OK  mock keystore, read from disk")
	fmt.Fprintln(w, "\nChecked to depth 2 (referential). This configuration names no signing daemon,")
	fmt.Fprintln(w, "so there was nothing live to reach; the mock keystore is evaluation only.")
}

// statusPairs renders the status map into the repeatable flag's url=file form,
// sorted so a given config always produces the same ordering.
func (c *Config) statusPairs() []string {
	out := make([]string, 0, len(c.Status))
	for url, file := range c.Status {
		out = append(out, url+"="+file)
	}
	sort.Strings(out)
	return out
}
