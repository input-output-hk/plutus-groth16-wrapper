package main

import (
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"sp1-gnark-verifier/parse"
)

const fixturesDir = "../sp1-hello-world/fixtures"

// innerNPublic is the number of public inputs in the SP1 BN254 Groth16 proof.
// SP1 exposes exactly 2: vkey_hash and committed_values_digest.
const innerNPublic = 2

// OuterCircuit wraps a BN254 Groth16 inner proof inside a BLS12-381 Groth16 outer proof.
// The inner VK, proof, and public inputs are all private witnesses of the outer circuit.
type OuterCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func main() {
	vk, err := parse.LoadVK(fixturesDir + "/vk.bin")
	die("load vk", err)
	proof, err := parse.LoadSeal(fixturesDir + "/seal.bin")
	die("load seal", err)
	pubInputs, err := parse.LoadPublicInputs(fixturesDir + "/public_inputs.json")
	die("load public inputs", err)

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	die("vk to circuit", err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
	die("proof to circuit", err)

	// Build the inner witness from the fr.Vector.
	circuitWitness := stdgroth16.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], innerNPublic),
	}
	for i, e := range pubInputs {
		circuitWitness.Public[i] = sw_bn254.NewScalar(e)
	}

	// Placeholder circuit for compilation. SP1's Groth16 circuit has 2 public inputs (IC[0..2]).
	// G1.K length = nPublic + 1 = 3 (IC[0] is the constant term, IC[1..2] are per-input).
	outerCircuit := &OuterCircuit{
		VerifyingKey: stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			G1: struct{ K []sw_bn254.G1Affine }{
				K: make([]sw_bn254.G1Affine, innerNPublic+1),
			},
			PublicAndCommitmentCommitted: [][]int{},
		},
		InnerWitness: stdgroth16.Witness[sw_bn254.ScalarField]{
			Public: make([]emulated.Element[sw_bn254.ScalarField], innerNPublic),
		},
	}

	fmt.Print("Compiling outer circuit (BN254-in-BLS12-381)... ")
	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, outerCircuit)
	die("compile", err)
	fmt.Printf("%d constraints (%s)\n", ccs.GetNbConstraints(), time.Since(t))

	fmt.Print("Setup (unsafe random)... ")
	t = time.Now()
	pk, outerVK, err := groth16.Setup(ccs)
	die("setup", err)
	fmt.Printf("done (%s)\n", time.Since(t))

	outerAssignment := &OuterCircuit{
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		InnerWitness: circuitWitness,
	}
	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BLS12_381.ScalarField())
	die("outer witness", err)

	fmt.Print("Proving... ")
	t = time.Now()
	outerProof, err := groth16.Prove(ccs, pk, outerWitness)
	die("prove", err)
	fmt.Printf("done (%s)\n", time.Since(t))

	outerPubWitness, err := outerWitness.Public()
	die("public witness", err)
	if err := groth16.Verify(outerProof, outerVK, outerPubWitness); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: verify outer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
