//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinInputAncestor(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "real", "nested"), 0700)
	os.WriteFile(filepath.Join(d, "real", "nested", "input.json"), []byte("synthetic"), 0600)
	os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "alias"))
	f, e := openInputFile(filepath.Join(d, "alias", "nested", "input.json"))
	if e == nil {
		f.Close()
		t.Fatal("accepted symlink ancestor")
	}
	f, e = openInputFile(filepath.Join(d, "real", "nested", "input.json"))
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
}
