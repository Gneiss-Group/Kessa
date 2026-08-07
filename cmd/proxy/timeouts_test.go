// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R6-02. A zero-value http.Server applies no timeout of any kind, so a request
// whose headers never end holds a goroutine and a connection for as long as the
// client likes, at a cost of one TCP connection each. Two hundred half-open
// requests survived three seconds against the enforcement handler with no
// server-side close.
//
// There are two things to pin, and they need different kinds of test. The first
// is that a server built here carries the bounds. The second, which is the one
// that actually keeps this closed, is that NO listener can be added that skips
// them: a helper is only a defence if every path goes through it.

func TestR6_02_ListenersCarryEveryTimeout(t *testing.T) {
	srv := newServer("127.0.0.1:0", http.NotFoundHandler())

	// Named individually rather than looped, so a zero value reports which bound
	// is missing instead of "a timeout is unset".
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset: this is the one that closes the half-open request")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout is unset: a body can be trickled indefinitely")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout is unset: a response can be consumed indefinitely slowly")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset: a kept-alive connection can be held between requests")
	}
	if srv.MaxHeaderBytes == 0 || srv.MaxHeaderBytes >= http.DefaultMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want a value below net/http's %d default: header size is per-connection memory the attacker chooses",
			srv.MaxHeaderBytes, http.DefaultMaxHeaderBytes)
	}

	// ReadHeaderTimeout must not exceed ReadTimeout, or it never fires and the
	// bound that matters most is decorative.
	if srv.ReadHeaderTimeout > srv.ReadTimeout {
		t.Errorf("ReadHeaderTimeout (%v) exceeds ReadTimeout (%v), so it can never fire",
			srv.ReadHeaderTimeout, srv.ReadTimeout)
	}
}

// The guard that survives a future contributor. newServer is only worth anything
// if it is the ONLY way this package starts a listener; http.ListenAndServe
// builds the zero-value server that R6-02 is about, so its presence anywhere in
// this package silently reintroduces the finding for whichever listener uses it.
//
// This is a source-level assertion for the same reason the licence boundary is
// one: a rule that lives only in a comment is a rule that gets forgotten, and a
// green build is exactly what would report nothing.
//
// It walks the AST rather than grepping the text, and that is not fastidiousness.
// The first version was a substring search and it failed on this file's own
// prose: the doc comments here have to NAME http.ListenAndServe to explain what
// is wrong with it. A check that cannot tell a call from a mention would force
// the explanation out of the code, which is the wrong trade. Same problem, and
// the same answer, as the licence guardrail's quoted-marker case.
func TestR6_02_NoListenerBypassesTheTimeoutHelper(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go")
	}, 0) // 0: no ParseComments, so a comment cannot trip the check
	if err != nil {
		t.Fatal(err)
	}

	// Enumerate what is forbidden, not what is allowed: every net/http entry point
	// that constructs a server implicitly, and therefore with no timeouts.
	banned := map[string]bool{"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true}

	found := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "http" || !banned[sel.Sel.Name] {
					return true
				}
				found++
				t.Errorf("%s:%d calls http.%s, which serves on a server with NO timeouts (R6-02); "+
					"build it with newServer instead", filepath.Base(name), fset.Position(call.Pos()).Line, sel.Sel.Name)
				return true
			})
		}
	}
	t.Logf("scanned %d files in package main; %d bypassing call(s)", len(pkgs["main"].Files), found)
}
