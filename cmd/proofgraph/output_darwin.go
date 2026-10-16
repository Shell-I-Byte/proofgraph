//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const outputDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// openSafeParent traverses every component from a pinned root ("/" for
// absolute paths, "." for relative paths). Never re-resolve an ancestor by
// pathname after obtaining its descriptor. Reject lexical traversal and
// symlinks at every directory component, not only at the final parent.
// Shared by Darwin input and output opens. Privileged mount operations and
// directory renames remain outside this confinement guarantee.
func openSafeParent(path string) (*os.File, error) {
	for _, name := range strings.Split(path, "/") {
		if name == ".." {
			return nil, errors.New("path traversal forbidden")
		}
	}
	start := "."
	if filepath.IsAbs(path) {
		start = "/"
	}
	fd, err := unix.Open(start, outputDirFlags, 0)
	if err != nil {
		return nil, errors.New("cannot safely open path root")
	}
	for _, name := range strings.Split(filepath.Dir(path), "/") {
		if name == "" || name == "." {
			continue
		}
		next, err := unix.Openat(fd, name, outputDirFlags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, errors.New("unsafe path ancestor")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "pinned-parent"), nil
}

// writeOutputFile creates a new report exclusively beneath an already opened
// Darwin directory chain. No intermediate or leaf symlink is followed.
func writeOutputFile(path string, payload []byte) error {
	base := filepath.Base(path)
	if base == "" || base == "." || base == ".." {
		return errors.New("invalid output filename")
	}
	parent, err := openSafeParent(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd := int(parent.Fd())
	outFD, err := unix.Openat(fd, base,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("cannot create output")
	}
	f := os.NewFile(uintptr(outFD), base)
	n, writeErr := f.Write(payload)
	syncErr := error(nil)
	if writeErr == nil && n == len(payload) {
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || n != len(payload) || syncErr != nil || closeErr != nil {
		_ = unix.Unlinkat(fd, base, 0)
		return errors.New("cannot complete output write")
	}
	return nil
}
