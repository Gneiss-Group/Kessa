// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Gneiss-Group/Kessa/internal/did"
	"github.com/Gneiss-Group/Kessa/internal/policy"
)

// TestEnforceBodyLimit is the F6 guard: an oversized /enforce body is rejected
// with 413 rather than streamed unbounded into the JSON decoder.
func TestEnforceBodyLimit(t *testing.T) {
	h := newHarness(t)
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{
		EnforcementPoint: sign(t, didProxy),
		Policy:           pol,
		DIDs:             did.FileResolver{Root: didsRoot},
		Status:           h.statuses,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(px))
	defer srv.Close()

	// A body well over the 1 MiB cap.
	huge := strings.NewReader(`{"junk":"` + strings.Repeat("A", (1<<20)+1024) + `"}`)
	resp, err := http.Post(srv.URL+"/enforce", "application/json", huge)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body should get 413, got %d", resp.StatusCode)
	}
}

// TestTipEndpoint confirms GET /tip reports the next entry's Seq, so a caller can
// bind its PoP/approval to that slot (F4).
func TestTipEndpoint(t *testing.T) {
	h := newHarness(t)
	pol, err := policy.Load(commercePol)
	if err != nil {
		t.Fatal(err)
	}
	px, err := NewProxy(Config{
		EnforcementPoint: sign(t, didProxy),
		Policy:           pol,
		DIDs:             did.FileResolver{Root: didsRoot},
		Status:           h.statuses,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(px))
	defer srv.Close()

	tip, err := FetchTip(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tip.Seq != 0 {
		t.Fatalf("empty log's next Seq should be 0, got %d", tip.Seq)
	}
}
