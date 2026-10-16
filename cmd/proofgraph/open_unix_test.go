//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNonblockingOpenAndDescriptorControls(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		f, err := openInputFile(pipe)
		if f != nil {
			f.Close()
		}
		completed <- err
	}()
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO waited for writer")
	}
	target := filepath.Join(dir, "regular.json")
	if err := os.WriteFile(target, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openInputFile(target)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := f.Stat()
	f.Close()
	if err != nil || !stat.Mode().IsRegular() {
		t.Fatalf("regular descriptor not accepted: %v", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(pipe, alias); err != nil {
		t.Fatal(err)
	}
	if f, err := openInputFile(alias); err == nil {
		f.Close()
		t.Fatal("symlink opened")
	}
	if _, err := readSafe(target, 1024); err != nil {
		t.Fatalf("regular input rejected: %v", err)
	}
	if _, err := readSafe(pipe, 1024); err == nil {
		t.Fatal("FIFO unexpectedly accepted")
	}
	if _, err := readSafe(dir, 1024); err == nil {
		t.Fatal("directory unexpectedly accepted")
	}
}
