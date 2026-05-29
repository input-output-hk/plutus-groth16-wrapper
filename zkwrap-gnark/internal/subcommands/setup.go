package subcommands

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/artifacts"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
)

// unsafeSetup compiles the wrapper circuit for the given MAX_INPUTS, runs
// gnark's groth16.Setup (insecure local randomness — the "unsafe" prefix
// makes this visible at the CLI), and persists the three setup
// artifacts to outDir.
func unsafeSetup(maxInputs int, outDir string, stderr io.Writer) int {
	if maxInputs <= 0 {
		fmt.Fprintf(stderr, "unsafe-setup: --max-inputs must be positive, got %d\n", maxInputs)
		return ExitMisuse
	}

	fmt.Fprintf(stderr, "compiling wrapper circuit (MAX_INPUTS=%d)...\n", maxInputs)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit.Placeholder(maxInputs))
	if err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: compile: %v\n", err)
		return ExitOpError
	}
	fmt.Fprintf(stderr, "  %d constraints\n", ccs.GetNbConstraints())

	fmt.Fprintln(stderr, "running unsafe trusted setup (local randomness)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: setup: %v\n", err)
		return ExitOpError
	}

	bls12vk, ok := vk.(*bls12381groth16.VerifyingKey)
	if !ok {
		fmt.Fprintf(stderr, "unsafe-setup: setup returned VK of unexpected type %T\n", vk)
		return ExitOpError
	}

	fmt.Fprintf(stderr, "writing bundle to %s ...\n", outDir)
	if err := artifacts.WriteSetupBundle(outDir, pk, bls12vk, ccs, maxInputs); err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: %v\n", err)
		return ExitOpError
	}
	return ExitOK
}
