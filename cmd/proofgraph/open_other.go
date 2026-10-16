//go:build !linux && !darwin

package main

import "os"

// Other platforms retain descriptor verification, but the Unix nonblocking
// FIFO-opening guarantee does not apply. Native Windows validation is open.
func openInputFile(path string) (*os.File, error) { return os.Open(path) }
