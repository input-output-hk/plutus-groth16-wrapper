// Command export generates a real gnark PLONK/BLS12-381 proof whose shape
// matches the production wrapper outer proof — 9 public inputs
// ([InnerVKHash, input_0..input_7]) plus exactly one BSB22 commitment (forced
// by api.Commit, the same source as the Groth16 path's Pedersen commitment) —
// and serializes the VK + proof + public inputs to JSON for the Aiken PLONK
// verifier spike.
//
// This is a THROWAWAY de-risking spike (docs/tmp/plonk-integration-plan.md,
// Step 0). It deliberately uses a tiny circuit rather than the multi-minute
// recursive BN254-Groth16 verifier: the on-chain unknowns (SHA-256 Fiat-Shamir
// transcript, BSB22 commitment hash-to-field, single folded KZG pairing) depend
// only on the proof *shape*, not on what the circuit computes.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/plonk"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// maxInputs mirrors the production MAX_INPUTS; public signals are
// [InnerVKHash, input_0..input_{maxInputs-1}].
const maxInputs = 8

const backendID = "gnark-plonk-bls12381"

// SpikeCircuit reproduces the production outer-proof public-input layout and
// forces a single BSB22 commitment, without the cost of real recursion.
type SpikeCircuit struct {
	InnerVKHash frontend.Variable            `gnark:",public"`
	Inputs      [maxInputs]frontend.Variable `gnark:",public"`

	// X is a private witness tying the public inputs together so they are
	// genuinely constrained (not optimized away).
	X frontend.Variable
}

func (c *SpikeCircuit) Define(api frontend.API) error {
	// Sum of public inputs equals the private witness X.
	sum := c.InnerVKHash
	for i := range c.Inputs {
		sum = api.Add(sum, c.Inputs[i])
	}
	api.AssertIsEqual(sum, c.X)

	// Force exactly one BSB22 commitment over the public inputs — this is what
	// makes the PLONK proof carry Bsb22Commitments and the VK carry Qcp.
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("frontend.API is not a Committer")
	}
	toCommit := make([]frontend.Variable, 0, maxInputs+1)
	toCommit = append(toCommit, c.InnerVKHash)
	for i := range c.Inputs {
		toCommit = append(toCommit, c.Inputs[i])
	}
	cmt, err := committer.Commit(toCommit...)
	if err != nil {
		return err
	}
	// Use the commitment so gnark keeps it in the constraint system.
	api.AssertIsDifferent(cmt, 0)
	return nil
}

func main() {
	outDir := "../artifacts"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := run(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, "compiling (scs)... ")
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &SpikeCircuit{})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%d constraints\n", ccs.GetNbConstraints())

	fmt.Fprint(os.Stderr, "kzg srs (unsafe)... ")
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		return fmt.Errorf("srs: %w", err)
	}
	fmt.Fprintln(os.Stderr, "done")

	fmt.Fprint(os.Stderr, "plonk setup... ")
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	fmt.Fprintln(os.Stderr, "done")

	// Sample public-input values resembling production: 5 "real" inputs then
	// zero padding (n_real=5 like RISC Zero / SP1 v6).
	innerVKHash := frInt(0x1234567)
	var inputs [maxInputs]frontend.Variable
	reals := []int64{11, 22, 33, 44, 55}
	var sum int64
	for i := range inputs {
		if i < len(reals) {
			inputs[i] = reals[i]
			sum += reals[i]
		} else {
			inputs[i] = 0
		}
	}
	assignment := &SpikeCircuit{
		InnerVKHash: 0x1234567,
		Inputs:      inputs,
		X:           big.NewInt(0x1234567 + sum),
	}
	_ = innerVKHash

	fullWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}

	fmt.Fprint(os.Stderr, "plonk prove... ")
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	fmt.Fprintln(os.Stderr, "done")

	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}
	if err := plonk.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	fmt.Fprintln(os.Stderr, "self-verify: PASS")

	bvk, ok := vk.(*bls12381plonk.VerifyingKey)
	if !ok {
		return fmt.Errorf("vk type %T", vk)
	}
	bproof, ok := proof.(*bls12381plonk.Proof)
	if !ok {
		return fmt.Errorf("proof type %T", proof)
	}

	// public witness vector (Fr elements) in declaration order.
	pubVec := publicWitness.Vector().(fr.Vector)
	pubHex := make([]string, len(pubVec))
	for i := range pubVec {
		pubHex[i] = frHex(pubVec[i])
	}

	if err := writeJSON(outDir+"/outer_vk.json", vkJSON(bvk)); err != nil {
		return err
	}
	if err := writeJSON(outDir+"/outer_proof.json", proofJSON(bproof, pubHex)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote artifacts to %s\n", outDir)
	return nil
}

// ---- serialization helpers -------------------------------------------------

func g1c(p bls12381.G1Affine) string { b := p.Bytes(); return hex.EncodeToString(b[:]) }    // compressed 48B
func g1u(p bls12381.G1Affine) string { b := p.RawBytes(); return hex.EncodeToString(b[:]) } // uncompressed 96B
func g2c(p bls12381.G2Affine) string { b := p.Bytes(); return hex.EncodeToString(b[:]) }    // compressed 96B
func frHex(e fr.Element) string      { b := e.Bytes(); return hex.EncodeToString(b[:]) }    // 32B BE

func frInt(v int64) fr.Element {
	var e fr.Element
	e.SetInt64(v)
	return e
}

// g1Point carries both encodings: compressed for EC ops, uncompressed for the
// Fiat-Shamir transcript (deriveRandomness hashes RawBytes()).
func g1Point(p bls12381.G1Affine) map[string]string {
	return map[string]string{"c": g1c(p), "u": g1u(p)}
}

func vkJSON(vk *bls12381plonk.VerifyingKey) any {
	qcp := make([]string, len(vk.Qcp))
	for i := range vk.Qcp {
		qcp[i] = g1c(vk.Qcp[i])
	}
	cci := make([]uint64, len(vk.CommitmentConstraintIndexes))
	copy(cci, vk.CommitmentConstraintIndexes)
	return map[string]any{
		"backend":             backendID,
		"max_inputs":          maxInputs,
		"size":                vk.Size,
		"size_inv":            frHex(vk.SizeInv),
		"generator":           frHex(vk.Generator),
		"nb_public_variables": vk.NbPublicVariables,
		"coset_shift":         frHex(vk.CosetShift),
		"kzg": map[string]any{
			"g1":   g1c(vk.Kzg.G1),
			"g2_0": g2c(vk.Kzg.G2[0]),
			"g2_1": g2c(vk.Kzg.G2[1]),
		},
		"s":                             []string{g1c(vk.S[0]), g1c(vk.S[1]), g1c(vk.S[2])},
		"ql":                            g1c(vk.Ql),
		"qr":                            g1c(vk.Qr),
		"qm":                            g1c(vk.Qm),
		"qo":                            g1c(vk.Qo),
		"qk":                            g1c(vk.Qk),
		"qcp":                           qcp,
		"commitment_constraint_indexes": cci,
	}
}

func proofJSON(p *bls12381plonk.Proof, publicInputs []string) any {
	lro := []map[string]string{g1Point(p.LRO[0]), g1Point(p.LRO[1]), g1Point(p.LRO[2])}
	h := []map[string]string{g1Point(p.H[0]), g1Point(p.H[1]), g1Point(p.H[2])}
	bsb := make([]map[string]string, len(p.Bsb22Commitments))
	for i := range p.Bsb22Commitments {
		bsb[i] = g1Point(p.Bsb22Commitments[i])
	}
	claimed := make([]string, len(p.BatchedProof.ClaimedValues))
	for i := range p.BatchedProof.ClaimedValues {
		claimed[i] = frHex(p.BatchedProof.ClaimedValues[i])
	}
	return map[string]any{
		"backend":           backendID,
		"max_inputs":        maxInputs,
		"public_inputs":     publicInputs,
		"lro":               lro,
		"z":                 g1Point(p.Z),
		"h":                 h,
		"bsb22_commitments": bsb,
		"batched_proof": map[string]any{
			"h":              g1Point(p.BatchedProof.H),
			"claimed_values": claimed,
		},
		"z_shifted_opening": map[string]any{
			"h":             g1Point(p.ZShiftedOpening.H),
			"claimed_value": frHex(p.ZShiftedOpening.ClaimedValue),
		},
	}
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
