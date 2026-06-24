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
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
	outergroth16 "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/groth16"
	outerplonk "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/plonk"
)

// verify loads the setup-dir's outer_vk.json and outer_proof.json and runs the
// outer verification for the backend recorded in the bundle. No soundness checks
// beyond that — those are the Aiken validator's job.
func verify(proofPath, setupDir string, stderr io.Writer) int {
	backend, err := outer.PeekBackend(setupDir)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return ExitOpError
	}
	switch backend {
	case outer.BackendGroth16:
		return verifyGroth16(proofPath, setupDir, stderr)
	case outer.BackendPlonk:
		return verifyPlonk(proofPath, setupDir, stderr)
	default:
		fmt.Fprintf(stderr, "verify: unsupported backend %q in setup bundle\n", backend)
		return ExitOpError
	}
}

func verifyGroth16(proofPath, setupDir string, stderr io.Writer) int {
	vkFile, err := os.Open(filepath.Join(setupDir, outer.FileVK))
	if err != nil {
		fmt.Fprintf(stderr, "verify: open %s: %v\n", outer.FileVK, err)
		return ExitOpError
	}
	vk, vkMaxInputs, err := outergroth16.ReadVK(vkFile)
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
	proof, innerVKHash, inputs, proofMaxInputs, err := outergroth16.ReadProof(pf)
	_ = pf.Close()
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return ExitOpError
	}
	if vkMaxInputs != proofMaxInputs {
		fmt.Fprintf(stderr, "verify: max_inputs mismatch: vk=%d, proof=%d\n", vkMaxInputs, proofMaxInputs)
		return ExitOpError
	}

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

func verifyPlonk(proofPath, setupDir string, stderr io.Writer) int {
	vkFile, err := os.Open(filepath.Join(setupDir, outer.FileVK))
	if err != nil {
		fmt.Fprintf(stderr, "verify: open %s: %v\n", outer.FileVK, err)
		return ExitOpError
	}
	vk, vkNumInputs, err := outerplonk.ReadVK(vkFile)
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
	proof, innerVKHash, inputs, suppliedLinDigest, proofNumInputs, err := outerplonk.ReadProof(pf)
	_ = pf.Close()
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return ExitOpError
	}
	if vkNumInputs != proofNumInputs {
		fmt.Fprintf(stderr, "verify: num_inputs mismatch: vk=%d, proof=%d\n", vkNumInputs, proofNumInputs)
		return ExitOpError
	}

	// Canonical gnark verification.
	pubAssignment := &circuit.OuterCircuit{
		InnerVKHash: frAsBigInt(innerVKHash),
		Inputs:      frsAsVariables(inputs),
	}
	w, err := frontend.NewWitness(pubAssignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Fprintf(stderr, "verify: build public witness: %v\n", err)
		return ExitOpError
	}
	if err := plonk.Verify(proof, vk, w); err != nil {
		fmt.Fprintf(stderr, "verify: gnark verify failed: %v\n", err)
		return ExitOpError
	}

	// Deterministic (on-chain-equivalent) verification, and confirm the
	// supplied lin_digest matches the recomputed one (schema rule).
	publicWitness := append([]fr.Element{innerVKHash}, inputs...)
	recomputedLinDigest, err := outerplonk.VerifyDeterministic(vk, proof, publicWitness)
	if err != nil {
		fmt.Fprintf(stderr, "verify: deterministic verify failed: %v\n", err)
		return ExitOpError
	}
	if !recomputedLinDigest.Equal(&suppliedLinDigest) {
		fmt.Fprintln(stderr, "verify: lin_digest does not match the recomputed linearized-polynomial digest")
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
