package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSafe(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x.json")
	if e := os.WriteFile(p, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := readSafe(p, 10); e != nil {
		t.Fatal(e)
	}
	if _, e := readSafe(p, 1); e == nil {
		t.Fatal("size limit bypass")
	}
	s := filepath.Join(d, "link")
	if e := os.Symlink(p, s); e != nil {
		t.Skip(e)
	}
	if _, e := readSafe(s, 10); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := readSafe(d, 10); e == nil {
		t.Fatal("directory accepted")
	}
}
func TestWriteSafe(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "r.json")
	if e := writeSafe(p, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode: %o", st.Mode().Perm())
	}
	if e = writeSafe(p, []byte("another")); e == nil {
		t.Fatal("overwrote existing")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if strings.TrimSpace(string(b)) != "{}" {
		t.Fatal("existing file modified")
	}
	s := filepath.Join(d, "link")
	if e := os.Symlink(p, s); e != nil {
		t.Skip(e)
	}
	if e = writeSafe(s, []byte("{}")); e == nil {
		t.Fatal("symlink write accepted")
	}
}
func TestArgumentRejection(t *testing.T) {
	for _, arg := range [][]string{nil, {}, {"unknown"}, {"analyze"}, {"analyze", "--fake\nInjected"}, {"verify"}, {"replay"}} {
		if run(arg) == 0 {
			t.Fatalf("accepted bad args %q", arg)
		}
	}
}
