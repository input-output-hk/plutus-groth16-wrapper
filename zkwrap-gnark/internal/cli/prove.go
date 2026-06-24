package cli

import (
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/circuit"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/inner"
	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
	outergroth16 "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/groth16"
	outerplonk "github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer/plonk"
)

// prove loads the canonical inner proof and the setup bundle, dispatches on the
// backend recorded in the bundle's outer_vk.json, runs the wrapper circuit to
// produce an outer proof, and writes outer_proof.json to outPath.
func prove(innerDir, setupDir, outPath string, stderr io.Writer) int {
	backend, err := outer.PeekBackend(setupDir)
	if err != nil {
		fmt.Fprintf(stderr, "prove: %v\n", err)
		return ExitOpError
	}
	switch backend {
	case outer.BackendGroth16:
		return proveGroth16(innerDir, setupDir, outPath, stderr)
	case outer.BackendPlonk:
		return provePlonk(innerDir, setupDir, outPath, stderr)
	default:
		fmt.Fprintf(stderr, "prove: unsupported backend %q in setup bundle\n", backend)
		return ExitOpError
	}
}

func proveGroth16(innerDir, setupDir, outPath string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "loading setup bundle...")
	pk, _, ccs, maxInputs, err := outergroth16.ReadSetupBundle(setupDir)
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
			paddedInputs[i].SetBigInt(&bi)
		} else {
			inputs[i] = 0
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
	if err := outergroth16.WriteProof(f, bls12proof, innerVKHash, paddedInputs, maxInputs); err != nil {
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

func provePlonk(innerDir, setupDir, outPath string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "loading setup bundle...")
	pk, vk, ccs, numInputs, err := outerplonk.ReadSetupBundle(setupDir)
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
	// PLONK compiles the circuit for exactly the inner system's n_real (no
	// padding), so the bundle's num_inputs must match exactly.
	if ip.NReal() != numInputs {
		fmt.Fprintf(stderr, "prove: n_real=%d != num_inputs=%d (plonk requires an exact-fit setup)\n", ip.NReal(), numInputs)
		return ExitOpError
	}

	innerVK, err := circuit.PadInnerVK(ip.VK, numInputs) // no-op copy when n_real == numInputs
	if err != nil {
		fmt.Fprintf(stderr, "prove: prepare inner VK: %v\n", err)
		return ExitOpError
	}
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		fmt.Fprintf(stderr, "prove: vk to circuit form: %v\n", err)
		return ExitOpError
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](ip.Proof)
	if err != nil {
		fmt.Fprintf(stderr, "prove: proof to circuit form: %v\n", err)
		return ExitOpError
	}

	innerVKHash, err := circuit.ComputeInnerVKHash(ip.VK, numInputs)
	if err != nil {
		fmt.Fprintf(stderr, "prove: compute InnerVKHash: %v\n", err)
		return ExitOpError
	}

	inputs := make([]frontend.Variable, numInputs)
	inputsFr := make([]fr.Element, numInputs)
	for i := 0; i < numInputs; i++ {
		var bi big.Int
		ip.PublicInputs[i].BigInt(&bi)
		inputs[i] = bi
		inputsFr[i].SetBigInt(&bi)
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

	fmt.Fprintln(stderr, "running outer prover (plonk)...")
	outerProof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Fprintf(stderr, "prove: gnark prove: %v\n", err)
		return ExitOpError
	}
	bls12proof, ok := outerProof.(*bls12381plonk.Proof)
	if !ok {
		fmt.Fprintf(stderr, "prove: outer proof of unexpected type %T\n", outerProof)
		return ExitOpError
	}

	// Canonical gnark self-check.
	pubWitness, err := witness.Public()
	if err != nil {
		fmt.Fprintf(stderr, "prove: extract public witness: %v\n", err)
		return ExitOpError
	}
	if err := plonk.Verify(outerProof, vk, pubWitness); err != nil {
		fmt.Fprintf(stderr, "prove: gnark self-verify failed: %v\n", err)
		return ExitOpError
	}

	// Deterministic (on-chain-equivalent) verify: confirms the proof is
	// verifiable by the Aiken validator's algorithm and yields the linearized-
	// polynomial digest the proof artifact must carry.
	publicWitness := append([]fr.Element{innerVKHash}, inputsFr...)
	linDigest, err := outerplonk.VerifyDeterministic(vk, bls12proof, publicWitness)
	if err != nil {
		fmt.Fprintf(stderr, "prove: deterministic verify failed (proof not on-chain-verifiable): %v\n", err)
		return ExitOpError
	}

	fmt.Fprintf(stderr, "writing outer proof to %s\n", outPath)
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "prove: create %s: %v\n", outPath, err)
		return ExitOpError
	}
	if err := outerplonk.WriteProof(f, bls12proof, innerVKHash, inputsFr, linDigest, numInputs); err != nil {
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
