//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: a symlink in an input ancestor must not be followed, even if
// Lstat and the subsequently opened leaf descriptor refer to the same inode.
func TestReadSafeRejectsInputAncestorSymlinkAndDotDot(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(root, "external")
	trusted := filepath.Join(root, "trusted")
	inside := filepath.Join(trusted, "inside")
	for _, dir := range []string{external, trusted, inside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	externalInput := filepath.Join(external, "data.json")
	if err := os.WriteFile(externalInput, []byte(`{"synthetic":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	safeInput := filepath.Join(inside, "safe.json")
	if err := os.WriteFile(safeInput, []byte(`{"synthetic":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSafe(safeInput, 4096); err != nil {
		t.Fatalf("valid nested input rejected: %v", err)
	}
	if err := os.Symlink(external, filepath.Join(trusted, "link")); err != nil {
		t.Fatal(err)
	}
	symlinked := filepath.Join(trusted, "link", "data.json")
	if _, err := readSafe(symlinked, 4096); err == nil {
		t.Fatal("symlink in input ancestor accepted")
	}
	traversing := trusted + "/../external/data.json" // preserve lexical ..
	if _, err := readSafe(traversing, 4096); err == nil {
		t.Fatal("lexical .. in input path accepted")
	}
}
