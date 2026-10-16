//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOutputLinuxSecurity(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "report.json")
	if err := writeSafe(output, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "{\"ok\":true}\n" {
		t.Fatalf("wrong output %q %v", got, err)
	}
	stat, err := os.Stat(output)
	if err != nil || stat.Mode().Perm()&0077 != 0 {
		t.Fatalf("unsafe mode %v %v", stat, err)
	}
	if err := writeSafe(output, []byte(`{}`)); err == nil {
		t.Fatal("overwrite accepted")
	}
	existing, err := os.ReadFile(output)
	if err != nil || string(existing) != string(got) {
		t.Fatal("overwrite modified result")
	}

	link := filepath.Join(root, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := writeSafe(filepath.Join(link, "leaked.json"), []byte(`{}`)); err == nil {
		t.Fatal("symlink output parent accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "leaked.json")); !os.IsNotExist(err) {
		t.Fatalf("wrote outside %v", err)
	}

	// Existing final-component symlink must not be followed or overwritten.
	leaf := filepath.Join(parent, "final.json")
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, leaf); err != nil {
		t.Fatal(err)
	}
	if err := writeSafe(leaf, []byte(`{}`)); err == nil {
		t.Fatal("symlink leaf accepted")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "keep" {
		t.Fatalf("symlink target changed %q %v", b, err)
	}
}

// A legitimate directory inside a symlinked ancestor must not be used for
// report output. The old final-parent-only check accepted this path.
func TestWriteOutputLinuxAncestorSymlink(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "trusted")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "reports"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, trusted); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(trusted, "reports", "report.json")
	if err := writeSafe(bad, []byte(`{"ok":true}`)); err == nil {
		t.Fatal("symlink in output ancestor accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "reports", "report.json")); !os.IsNotExist(err) {
		t.Fatalf("escaped ancestor output: %v", err)
	}
	if err := writeSafe(filepath.Join(root, "outside", "reports")+"/../bad.json", []byte(`{}`)); err == nil {
		t.Fatal("lexical parent traversal accepted")
	}
	if err := writeSafe(filepath.Join(outside, "reports", "okay.json"), []byte(`{}`)); err != nil {
		t.Fatalf("normal nested path rejected: %v", err)
	}
}
