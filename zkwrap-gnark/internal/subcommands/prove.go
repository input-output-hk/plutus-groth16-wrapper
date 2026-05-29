package subcommands

import (
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/artifacts"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/inner"
)

// prove loads the canonical inner proof from innerDir, loads the setup bundle
// from setupDir, runs the wrapper circuit to produce an outer proof, and
// writes outer_proof.json to outPath.
func prove(innerDir, setupDir, outPath string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "loading setup bundle...")
	pk, _, ccs, maxInputs, err := artifacts.ReadSetupBundle(setupDir)
	if err != nil {
		fmt.Fprintf(stderr, "prove: %v\n", err)
		return ExitOpError
	}

	fmt.Fprintln(stderr, "loading canonical inner proof...")
	ip, err := inner.Load(innerDir)
	if err != nil {
		fmt.Fprintf(stderr, "prove: %v\n", err)
		return ExitOpError
	}
	if ip.NReal() > maxInputs {
		fmt.Fprintf(stderr, "prove: n_real=%d exceeds max_inputs=%d\n", ip.NReal(), maxInputs)
		return ExitOpError
	}

	paddedVK, err := circuit.PadInnerVK(ip.VK, maxInputs)
	if err != nil {
		fmt.Fprintf(stderr, "prove: pad inner VK: %v\n", err)
		return ExitOpError
	}
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](paddedVK)
	if err != nil {
		fmt.Fprintf(stderr, "prove: vk to circuit form: %v\n", err)
		return ExitOpError
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](ip.Proof)
	if err != nil {
		fmt.Fprintf(stderr, "prove: proof to circuit form: %v\n", err)
		return ExitOpError
	}

	innerVKHash, err := circuit.ComputeInnerVKHash(ip.VK, maxInputs)
	if err != nil {
		fmt.Fprintf(stderr, "prove: compute InnerVKHash: %v\n", err)
		return ExitOpError
	}

	inputs := make([]frontend.Variable, maxInputs)
	paddedInputs := make([]fr.Element, maxInputs)
	for i := 0; i < maxInputs; i++ {
		if i < ip.NReal() {
			var bi big.Int
			ip.PublicInputs[i].BigInt(&bi)
			inputs[i] = bi
			// BLS12-381 Fr re-encoding of the BN254 input value as an
			// integer (canonical for inputs in [0, BN254_Fr_modulus) which
			// fit in BLS12-381 Fr without reduction).
			paddedInputs[i].SetBigInt(&bi)
		} else {
			inputs[i] = 0
			// paddedInputs[i] is already zero-valued
		}
	}

	var hashBi big.Int
	innerVKHash.BigInt(&hashBi)
	assignment := &circuit.OuterCircuit{
		InnerVKHash:  hashBi,
		Inputs:       inputs,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
	}
	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		fmt.Fprintf(stderr, "prove: build witness: %v\n", err)
		return ExitOpError
	}

	fmt.Fprintln(stderr, "running outer prover...")
	outerProof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Fprintf(stderr, "prove: gnark prove: %v\n", err)
		return ExitOpError
	}
	bls12proof, ok := outerProof.(*bls12381groth16.Proof)
	if !ok {
		fmt.Fprintf(stderr, "prove: outer proof of unexpected type %T\n", outerProof)
		return ExitOpError
	}

	fmt.Fprintf(stderr, "writing outer proof to %s\n", outPath)
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "prove: create %s: %v\n", outPath, err)
		return ExitOpError
	}
	if err := artifacts.WriteOuterProof(f, bls12proof, innerVKHash, paddedInputs, maxInputs); err != nil {
		_ = f.Close()
		fmt.Fprintf(stderr, "prove: write outer_proof.json: %v\n", err)
		return ExitOpError
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "prove: close %s: %v\n", outPath, err)
		return ExitOpError
	}
	return ExitOK
}
