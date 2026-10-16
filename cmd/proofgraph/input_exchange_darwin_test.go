//go:build darwin

package main

import (
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestDarwinInputConcurrentAncestor(t *testing.T) {
	d := t.TempDir()
	parent := filepath.Join(d, "parent")
	other := filepath.Join(d, "other")
	link := filepath.Join(d, "exchange")
	for _, p := range []string{parent, other} {
		if e := os.MkdirAll(filepath.Join(p, "nested"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(parent, "nested", "source"), []byte("original"), 0600)
	os.WriteFile(filepath.Join(other, "nested", "source"), []byte("foreign"), 0600)
	if e := os.Symlink(other, link); e != nil {
		t.Fatal(e)
	}

	var stop atomic.Bool
	var swaps atomic.Int64
	done := make(chan error, 1)
	go func() {
		for !stop.Load() {
			if e := unix.RenamexNp(parent, link, unix.RENAME_SWAP); e != nil {
				done <- e
				return
			}
			swaps.Add(1)
		}
		done <- nil
	}()
	accepted, bad := 0, 0
	for i := 0; i < 200; i++ {
		f, e := openInputFile(filepath.Join(parent, "nested", "source"))
		if e != nil {
			continue
		}
		b, e := io.ReadAll(f)
		f.Close()
		if e != nil || string(b) != "original" {
			bad++
		}
		accepted++
	}
	stop.Store(true)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if swaps.Load() == 0 {
		t.Fatal("exchange did not run")
	}
	if bad != 0 {
		t.Fatalf("foreign reads %d", bad)
	}
	t.Logf("attempts=200 exchanges=%d accepted=%d foreign=%d", swaps.Load(), accepted, bad)
}
