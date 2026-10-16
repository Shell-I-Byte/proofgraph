package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Shell-I-Byte/proofgraph/internal/graph"
)

func readSafe(p string, limit int64) ([]byte, error) {
	if p == "" || p == "-" {
		return nil, errors.New("file path required")
	}
	st, e := os.Lstat(p)
	if e != nil {
		return nil, errors.New("cannot read input")
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("regular file required")
	}
	if st.Size() < 0 || st.Size() > limit {
		return nil, errors.New("file size limit")
	}
	f, e := openInputFile(p)
	if e != nil {
		return nil, errors.New("cannot read input")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
		return nil, errors.New("input file changed during open")
	}
	again, e := os.Lstat(p)
	if e != nil || !again.Mode().IsRegular() || !os.SameFile(st, again) {
		return nil, errors.New("input path changed during open")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || len(b) > int(limit) {
		return nil, errors.New("file size limit")
	}
	return b, nil
}

// writeSafe writes JSON to stdout or delegates file creation to a
// platform-specific implementation. On Linux, output parent identity is
// pinned before exclusive creation to prevent a last-component symlink race.
func writeSafe(p string, b []byte) error {
	payload := append(append([]byte(nil), b...), '\n')
	if p == "" {
		n, e := os.Stdout.Write(payload)
		if e != nil {
			return e
		}
		if n != len(payload) {
			return io.ErrShortWrite
		}
		return nil
	}
	if p == "-" {
		return errors.New("invalid output path")
	}
	return writeOutputFile(p, payload)
}
func parse(name string, args []string) (*flag.FlagSet, *string, *string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	in := fs.String("input", "", "input JSON file")
	out := fs.String("output", "", "output JSON file; stdout if omitted")
	if e := fs.Parse(args); e != nil || fs.NArg() != 0 {
		return nil, nil, nil, errors.New("invalid flags")
	}
	return fs, in, out, nil
}
func run(args []string) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(graph.Describe())
		return 0
	}
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: use analyze, verify, replay, or version")
		return 2
	}
	switch args[0] {
	case "analyze":
		_, in, out, e := parse("analyze", args[1:])
		if e != nil || *in == "" {
			fmt.Fprintln(os.Stderr, "error: invalid analyze arguments")
			return 2
		}
		raw, e := readSafe(*in, graph.MaxInput)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: input unavailable or unsafe")
			return 4
		}
		r, e := graph.Analyze(raw)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: invalid input: "+safeErr(e))
			return 2
		}
		b, _ := graph.Encode(r)
		if e = writeSafe(*out, b); e != nil {
			fmt.Fprintln(os.Stderr, "error: output unavailable or unsafe")
			return 4
		}
		return 0
	case "verify":
		_, in, out, e := parse("verify", args[1:])
		if e != nil || *in == "" || *out != "" {
			fmt.Fprintln(os.Stderr, "error: invalid verify arguments")
			return 2
		}
		b, e := readSafe(*in, graph.MaxInput)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: report unavailable or unsafe")
			return 4
		}
		if e = graph.VerifyReport(b); e != nil {
			fmt.Fprintln(os.Stderr, "error: report integrity check failed")
			return 3
		}
		fmt.Println("PASS report digest (not source attestation)")
		return 0
	case "replay":
		fs := flag.NewFlagSet("replay", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		input := fs.String("input", "", "")
		report := fs.String("report", "", "")
		if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 || *input == "" || *report == "" {
			fmt.Fprintln(os.Stderr, "error: invalid replay arguments")
			return 2
		}
		a, e := readSafe(*input, graph.MaxInput)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: source unavailable")
			return 4
		}
		b, e := readSafe(*report, graph.MaxInput)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: report unavailable")
			return 4
		}
		if e = graph.Replay(a, b); e != nil {
			fmt.Fprintln(os.Stderr, "error: replay mismatch")
			return 3
		}
		fmt.Println("PASS deterministic replay")
		return 0
	default:
		fmt.Fprintln(os.Stderr, "error: unknown command")
		return 2
	}
}
func safeErr(e error) string {
	s := e.Error()
	if len(s) > 100 || strings.ContainsAny(s, "\n\x1b\r") {
		return "validation failed"
	}
	return s
}
func main() { os.Exit(run(os.Args[1:])) }
