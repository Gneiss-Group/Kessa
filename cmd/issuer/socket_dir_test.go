// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The socket's parent directory is the filesystem half of the daemon's access
// control, and settling it used to reach outside the daemon's own footprint: an
// unconditional chmod tightened whatever directory --sock happened to name, so
// `--sock /tmp/kessa.sock` chmod'd /tmp.
//
// The property these pin is narrow and absolute: a directory this process
// created is its to set, and one it merely found is left exactly as found,
// whether that means accepting it or refusing to start.

func TestSocketDirCreatedIsTightened(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kessa")
	if err := prepareSocketDir(dir); err != nil {
		t.Fatalf("refused to create a directory of its own: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("created the socket dir %#o, want 0700", perm)
	}
}

// The finding. A directory the daemon did not create is not its to modify, so a
// loose one is refused rather than silently corrected, and its mode is untouched
// on the way out.
func TestSocketDirFoundLooseIsRefusedAndUnchanged(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o755, 0o750, 0o770} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "shared")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			err := prepareSocketDir(dir)
			if err == nil {
				t.Fatal("accepted a directory it did not create and could not vouch for")
			}
			if !strings.Contains(err.Error(), "did not create") {
				t.Errorf("refused, but not for the stated reason: %v", err)
			}
			// The whole point: refusing must not be a euphemism for changing it.
			fi, serr := os.Stat(dir)
			if serr != nil {
				t.Fatal(serr)
			}
			if got := fi.Mode().Perm(); got != mode.Perm() {
				t.Fatalf("the directory was modified on the way out: mode %#o, was %#o", got, mode.Perm())
			}
		})
	}
}

// A directory that is already exactly right is accepted, and still not written
// to. Without this the case above would pass if the daemon simply refused every
// pre-existing directory, which would break every restart.
func TestSocketDirFoundCorrectIsAcceptedAndUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kessa")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDir(dir); err != nil {
		t.Fatalf("refused a directory that was already correct, so a restart would fail: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("mode changed from %v to %v on a directory that needed nothing", before.Mode(), after.Mode())
	}
}

// A missing parent is reported rather than filled in. Creating a tree implicitly
// is how a typo'd path became a new directory somewhere unintended.
func TestSocketDirMissingParentIsReportedNotCreated(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "absent", "kessa")
	if err := prepareSocketDir(deep); err == nil {
		t.Fatal("created a directory tree for a path whose parent does not exist")
	}
	if _, err := os.Stat(filepath.Join(root, "absent")); !os.IsNotExist(err) {
		t.Fatal("the missing parent was created anyway")
	}
}

func TestSocketDirRejectsAFileWhereADirectoryBelongs(t *testing.T) {
	f := filepath.Join(t.TempDir(), "kessa")
	if err := os.WriteFile(f, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := prepareSocketDir(f)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("accepted a plain file as the socket directory: %v", err)
	}
}

// socketDirState is what --check-config calls, and it has to answer the same
// question prepareSocketDir will, without performing it. A check that came to a
// different answer from the thing it predicts is worse than no check.
func TestSocketDirStatePredictsWithoutActing(t *testing.T) {
	t.Run("absent, and it says so without creating it", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "kessa")
		state, err := socketDirState(dir)
		if err != nil {
			t.Fatalf("a creatable path was reported as a failure: %v", err)
		}
		if !strings.Contains(state, "will be created") {
			t.Errorf("state does not say what will happen: %q", state)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("the check created the directory, which is the side effect it exists to avoid")
		}
	})
	t.Run("loose, and it refuses exactly as the start would", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, checkErr := socketDirState(dir)
		startErr := prepareSocketDir(dir)
		if checkErr == nil || startErr == nil {
			t.Fatalf("check and start disagree: check=%v start=%v", checkErr, startErr)
		}
		if checkErr.Error() != startErr.Error() {
			t.Fatalf("the check refuses for a different reason than the start:\n  check: %v\n  start: %v", checkErr, startErr)
		}
	})
	t.Run("already correct", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "kessa")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		state, err := socketDirState(dir)
		if err != nil {
			t.Fatalf("refused a correct directory: %v", err)
		}
		if !strings.Contains(state, "left as found") {
			t.Errorf("state does not say the directory is untouched: %q", state)
		}
	})
}
