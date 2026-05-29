// Command zkwrap-gnark wraps a BN254 Groth16 inner proof inside a
// BLS12-381 Groth16 outer proof. See docs/adr/0004-gnark-prover-cli.md.
package main

import (
	"os"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
