//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openInputFile opens the leaf relative to a pinned directory-descriptor
// chain. A symlink anywhere in the input pathname is refused; lexical .. is
// refused before filepath normalization. O_NONBLOCK also prevents FIFO hangs.
// This does not pin a pathname against a privileged mount or directory rename.
func openInputFile(path string) (*os.File, error) {
	base := filepath.Base(path)
	if base == "" || base == "." || base == ".." {
		return nil, errors.New("invalid input filename")
	}
	parent, err := openSafeParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), base,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("unsafe input leaf")
	}
	return os.NewFile(uintptr(fd), "pinned-input-leaf"), nil
}
