// Package subcommands implements the zkwrap-gnark CLI:
// three subcommands (unsafe-setup, prove, verify), named flags only,
// stderr for human output, stdout silent, exit codes 0/1/2.
package cli

import (
	"fmt"
	"io"
)

// Exit codes:
//
//	0 — success
//	1 — operational failure (file missing, verification failed, etc.)
//	2 — CLI misuse (unknown subcommand, missing flag, conflicting flags)
const (
	ExitOK      = 0
	ExitOpError = 1
	ExitMisuse  = 2
)

// Run executes the CLI with the given args (sans program name) and writes
// human output to stderr; stdout is reserved for future structured output
// and currently silent. It returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "zkwrap-gnark: missing subcommand (expected one of: unsafe-setup, prove, verify)")
		return ExitMisuse
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "unsafe-setup":
		return runUnsafeSetup(rest, stdout, stderr)
	case "prove":
		return runProve(rest, stdout, stderr)
	case "verify":
		return runVerify(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "zkwrap-gnark: unknown subcommand %q (expected one of: unsafe-setup, prove, verify)\n", sub)
		return ExitMisuse
	}
}

func runUnsafeSetup(args []string, stdout, stderr io.Writer) int {
	f := newSubcmdFlags("unsafe-setup", stderr)
	var (
		maxInputs int
		out       string
		backend   string
	)
	f.fs.IntVar(&maxInputs, "max-inputs", 0, "number of wrapper-circuit input slots (groth16: padded MAX_INPUTS; plonk: exact n_real)")
	f.fs.StringVar(&out, "out", "", "output directory for the setup bundle")
	f.fs.StringVar(&backend, "backend", "", "outer backend: groth16 | plonk")
	if !f.parse(args) {
		return ExitMisuse
	}
	return unsafeSetup(backend, maxInputs, out, stderr)
}

func runProve(args []string, stdout, stderr io.Writer) int {
	f := newSubcmdFlags("prove", stderr)
	var (
		innerDir string
		setupDir string
		out      string
	)
	f.fs.StringVar(&innerDir, "inner", "", "canonical inner proof directory")
	f.fs.StringVar(&setupDir, "setup", "", "setup directory (outer_pk.bin, outer_vk.json, circuit.r1cs)")
	f.fs.StringVar(&out, "out", "", "output outer_proof.json path")
	if !f.parse(args) {
		return ExitMisuse
	}
	return prove(innerDir, setupDir, out, stderr)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	f := newSubcmdFlags("verify", stderr)
	var (
		proofPath string
		setupDir  string
	)
	f.fs.StringVar(&proofPath, "proof", "", "outer_proof.json path")
	f.fs.StringVar(&setupDir, "setup", "", "setup directory")
	if !f.parse(args) {
		return ExitMisuse
	}
	return verify(proofPath, setupDir, stderr)
}
