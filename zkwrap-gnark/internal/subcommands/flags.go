package subcommands

import (
	"flag"
	"fmt"
	"io"
)

// subcmdFlags wraps flag.FlagSet with conventions shared across subcommands:
// stderr-only output, no positional args, every registered flag is required.
// A false return from parse means the caller should return ExitMisuse.
type subcmdFlags struct {
	fs   *flag.FlagSet
	subc string
	err  io.Writer
}

func newSubcmdFlags(subc string, stderr io.Writer) *subcmdFlags {
	fs := flag.NewFlagSet(subc, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: zkwrap-gnark %s [flags]\n", subc)
		fs.PrintDefaults()
	}
	return &subcmdFlags{fs: fs, subc: subc, err: stderr}
}

// parse runs flag.Parse, rejects positional args, and requires every
// registered flag to have been set. All missing flags are reported in one pass.
func (s *subcmdFlags) parse(args []string) bool {
	if err := s.fs.Parse(args); err != nil {
		return false
	}
	if s.fs.NArg() > 0 {
		fmt.Fprintf(s.err, "zkwrap-gnark %s: positional arguments not accepted; got %v\n", s.subc, s.fs.Args())
		return false
	}
	seen := map[string]bool{}
	s.fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	ok := true
	s.fs.VisitAll(func(f *flag.Flag) {
		if !seen[f.Name] {
			fmt.Fprintf(s.err, "zkwrap-gnark %s: missing required flag --%s\n", s.subc, f.Name)
			ok = false
		}
	})
	return ok
}
