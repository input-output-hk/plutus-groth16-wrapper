package cli

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
	outergroth16 "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/groth16"
	outerplonk "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/plonk"
)

// unsafeSetup compiles the wrapper circuit for the given number of input slots
// and runs the chosen outer backend's setup with insecure local randomness (the
// "unsafe" prefix makes this visible at the CLI), persisting the setup bundle to
// outDir.
func unsafeSetup(backend string, maxInputs int, outDir string, stderr io.Writer) int {
	if maxInputs <= 0 {
		fmt.Fprintf(stderr, "unsafe-setup: --max-inputs must be positive, got %d\n", maxInputs)
		return ExitMisuse
	}

	switch backend {
	case "groth16":
		return unsafeSetupGroth16(maxInputs, outDir, stderr)
	case "plonk":
		return unsafeSetupPlonk(maxInputs, outDir, stderr)
	default:
		fmt.Fprintf(stderr, "unsafe-setup: unknown --backend %q (expected groth16 | plonk)\n", backend)
		return ExitMisuse
	}
}

func unsafeSetupGroth16(maxInputs int, outDir string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "compiling wrapper circuit (groth16, MAX_INPUTS=%d)...\n", maxInputs)
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
	if err := outergroth16.WriteSetupBundle(outDir, pk, bls12vk, ccs, maxInputs); err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: %v\n", err)
		return ExitOpError
	}
	return ExitOK
}

func unsafeSetupPlonk(numInputs int, outDir string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "compiling wrapper circuit (plonk/scs, num_inputs=%d)...\n", numInputs)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, circuit.Placeholder(numInputs))
	if err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: compile: %v\n", err)
		return ExitOpError
	}
	fmt.Fprintf(stderr, "  %d constraints\n", ccs.GetNbConstraints())

	fmt.Fprintln(stderr, "generating unsafe KZG SRS (local randomness)...")
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: srs: %v\n", err)
		return ExitOpError
	}

	fmt.Fprintln(stderr, "running plonk setup...")
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: setup: %v\n", err)
		return ExitOpError
	}
	bls12vk, ok := vk.(*bls12381plonk.VerifyingKey)
	if !ok {
		fmt.Fprintf(stderr, "unsafe-setup: setup returned VK of unexpected type %T\n", vk)
		return ExitOpError
	}

	fmt.Fprintf(stderr, "writing bundle to %s ...\n", outDir)
	if err := outerplonk.WriteSetupBundle(outDir, pk, bls12vk, ccs, numInputs); err != nil {
		fmt.Fprintf(stderr, "unsafe-setup: %v\n", err)
		return ExitOpError
	}
	return ExitOK
}
