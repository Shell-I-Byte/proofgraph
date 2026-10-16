//go:build !linux && !darwin

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Non-Linux fallback: exclusive creation and safe permissions, but parent
// directory race confinement remains UNTESTED. Native validation is required.
func writeOutputFile(p string, payload []byte) error {
	if st, err := os.Lstat(p); err == nil {
		if !st.Mode().IsRegular() {
			return errors.New("output must be regular file")
		}
		return errors.New("refusing overwrite")
	} else if !os.IsNotExist(err) {
		return errors.New("invalid output")
	}
	dir := filepath.Dir(p)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return errors.New("invalid destination directory")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create output")
	}
	n, writeErr := f.Write(payload)
	syncErr := error(nil)
	if writeErr == nil && n == len(payload) {
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || n != len(payload) {
		_ = os.Remove(p)
		return io.ErrShortWrite
	}
	return nil
}
