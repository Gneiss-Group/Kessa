// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package release exists so the release shell scripts in this directory can have
// Go tests beside them.
//
// It holds no code. scripts/release/*.sh is the implementation; notes_test.go
// drives notes.sh against throwaway git repositories, the same way
// scripts/reusecheck pairs a program with a test that shells out to it. Keeping
// the test here rather than under internal/ means the test and the script it
// covers move together, and `go test ./...` picks it up with no wiring, so the
// merge gate runs it without knowing it exists.
package release
