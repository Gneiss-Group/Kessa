// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

// TestResolve_EmptyAllowlistResolvesNothing pins the polarity, which is the
// single most important property of this field.
//
// An empty AllowedHosts must mean NONE, never ALL. The opposite polarity is the
// shape this project keeps finding: an omitted value that quietly widens a check,
// so a caller who forgets to configure it gets no protection and no error. Here a
// forgetful caller resolves nothing and is told why.
func TestResolve_EmptyAllowlistResolvesNothing(t *testing.T) {
	var did types.DID
	srv := serveDoc(t, &did)
	host := mustHost(t, srv.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))

	r := HTTPResolver{Scheme: "http"} // no AllowedHosts
	_, err := r.Resolve(did)
	if err == nil {
		t.Fatal("an empty allowlist resolved a host; empty must mean none, not all")
	}
	if !strings.Contains(err.Error(), "no did:web hosts are permitted") {
		t.Errorf("error %q should say that no hosts are permitted", err)
	}
}

// TestResolve_UnlistedHostIsRefused is the finding itself: the export chooses the
// DID, so an attacker naming a host the deployment never approved must get
// nothing. The permitted host here is real and reachable, which is what makes the
// refusal about the LIST rather than about the request failing anyway.
func TestResolve_UnlistedHostIsRefused(t *testing.T) {
	var did types.DID
	srv := serveDoc(t, &did)
	host := mustHost(t, srv.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))

	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{"acme.example"}}
	_, err := r.Resolve(did)
	if err == nil {
		t.Fatal("resolved a host that was not on the allowlist")
	}
	if !strings.Contains(err.Error(), "not a permitted did:web host") {
		t.Errorf("error %q should name the refusal", err)
	}
	// The operator needs to see what WAS permitted to fix a stale list, which is
	// the failure mode a host rename produces.
	if !strings.Contains(err.Error(), "acme.example") {
		t.Errorf("error %q should list the permitted hosts", err)
	}
}

// TestResolve_ListedHostSucceeds is the other direction. A tightened check is
// only correct if the permitted case still works, and without this the two tests
// above would pass against a resolver that refused everything.
func TestResolve_ListedHostSucceeds(t *testing.T) {
	var did types.DID
	srv := serveDoc(t, &did)
	host := mustHost(t, srv.URL)
	did = types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))

	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{host}}
	if _, err := r.Resolve(did); err != nil {
		t.Fatalf("a permitted host should resolve: %v", err)
	}
}

// TestResolve_AllowlistMatchesExactly covers the matching rule. Case is
// insensitive because hostnames are; the port is significant because a different
// port is a different endpoint, and guessing which one an operator meant is not
// this package's business.
func TestResolve_AllowlistMatchesExactly(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		ok      bool
	}{
		{"exact", []string{"acme.example:8443"}, true},
		{"case insensitive", []string{"ACME.Example:8443"}, true},
		{"surrounding space tolerated", []string{"  acme.example:8443  "}, true},
		{"one of several", []string{"other.example", "acme.example:8443"}, true},
		{"port omitted does not match", []string{"acme.example"}, false},
		{"different port", []string{"acme.example:9443"}, false},
		{"suffix is not a match", []string{"example"}, false},
		{"parent domain is not a match", []string{"acme.example:8443.evil.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := HTTPResolver{AllowedHosts: tc.allowed}
			err := r.hostAllowed("acme.example:8443")
			if tc.ok && err != nil {
				t.Errorf("host should have been permitted: %v", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("host should have been refused by %v", tc.allowed)
			}
		})
	}
}

// TestResolve_AllowlistCheckedBeforeAnyRequest confirms the refusal happens
// before a request is made, not after one is abandoned. Validate before the side
// effect: a refused host should produce no traffic at all, which is also what
// stops the resolver being usable as a port prober against unlisted hosts.
func TestResolve_AllowlistCheckedBeforeAnyRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	did := types.DID("did:web:" + strings.ReplaceAll(host, ":", "%3A"))

	r := HTTPResolver{Scheme: "http", AllowedHosts: []string{"acme.example"}}
	if _, err := r.Resolve(did); err == nil {
		t.Fatal("expected a refusal")
	}
	if hits != 0 {
		t.Errorf("refused host still received %d request(s); the check must precede the fetch", hits)
	}
}
