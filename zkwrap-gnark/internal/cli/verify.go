package cli

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
)

// verify loads outer_proof.json and the setup-dir's outer_vk.json, then runs
// gnark's outer-Groth16 verification. No soundness checks beyond that — those
// are the Aiken validator's job.
func verify(proofPath, setupDir string, stderr io.Writer) int {
	vkFile, err := os.Open(filepath.Join(setupDir, outer.FileVK))
	if err != nil {
		fmt.Fprintf(stderr, "verify: open %s: %v\n", outer.FileVK, err)
		return ExitOpError
	}
	vk, vkMaxInputs, err := outer.ReadVK(vkFile)
	_ = vkFile.Close()
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return ExitOpError
	}

	pf, err := os.Open(proofPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify: open %s: %v\n", proofPath, err)
		return ExitOpError
	}
	proof, innerVKHash, inputs, proofMaxInputs, err := outer.ReadProof(pf)
	_ = pf.Close()
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return ExitOpError
	}
	if vkMaxInputs != proofMaxInputs {
		fmt.Fprintf(stderr, "verify: max_inputs mismatch: vk=%d, proof=%d\n", vkMaxInputs, proofMaxInputs)
		return ExitOpError
	}

	// Build the outer public-witness vector [InnerVKHash, inputs...]
	// by assigning to an OuterCircuit shape and extracting only the public
	// portion — same approach the in-circuit prover takes.
	pubAssignment := &circuit.OuterCircuit{
		InnerVKHash: frAsBigInt(innerVKHash),
		Inputs:      frsAsVariables(inputs),
	}
	w, err := frontend.NewWitness(pubAssignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Fprintf(stderr, "verify: build public witness: %v\n", err)
		return ExitOpError
	}

	if err := groth16.Verify(proof, vk, w); err != nil {
		fmt.Fprintf(stderr, "verify: gnark verify failed: %v\n", err)
		return ExitOpError
	}
	fmt.Fprintln(stderr, "verify: PASS")
	return ExitOK
}

func frAsBigInt(h fr.Element) *big.Int {
	var bi big.Int
	h.BigInt(&bi)
	return &bi
}

func frsAsVariables(inputs []fr.Element) []frontend.Variable {
	out := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		var bi big.Int
		inputs[i].BigInt(&bi)
		out[i] = bi
	}
	return out
}
