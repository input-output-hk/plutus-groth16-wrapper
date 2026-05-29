// Package circuit implements the universal wrapper circuit
// The circuit verifies a BN254 Groth16 inner proof inside
// a BLS12-381 outer proof and exposes outer public signals
// [InnerVKHash, input_0..input_{MAX_INPUTS-1}].
//
// The circuit is universal in `n_real`: it has no knowledge of how many of the
// MAX_INPUTS slots are "real" for a given inner system. The prover assigns the
// inner system's public inputs to the first n_real slots and zero to the rest;
// the Aiken validator enforces the excess-zero check on-chain.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Poseidon2 over BLS12-381 Fr, gnark-crypto default parameters.
// The in-circuit and off-circuit hashers must agree on these.
const (
	PoseidonWidth         = 2
	PoseidonFullRounds    = 6
	PoseidonPartialRounds = 50
)

// OuterCircuit wraps a BN254 Groth16 inner proof inside a BLS12-381 Groth16
// outer proof. Outer public signals: [InnerVKHash, input_0..input_{MAX-1}].
type OuterCircuit struct {
	InnerVKHash frontend.Variable   `gnark:",public"`
	Inputs      []frontend.Variable `gnark:",public"`

	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
}

// Placeholder returns an OuterCircuit shaped for the given MAX_INPUTS, suitable
// for passing to frontend.Compile. All values are zero-valued; only the array
// lengths matter.
func Placeholder(maxInputs int) *OuterCircuit {
	return &OuterCircuit{
		Inputs: make([]frontend.Variable, maxInputs),
		VerifyingKey: stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			G1: struct{ K []sw_bn254.G1Affine }{
				K: make([]sw_bn254.G1Affine, maxInputs+1),
			},
			PublicAndCommitmentCommitted: [][]int{},
		},
	}
}

func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}

	// The inner Groth16 verifier consumes scalars as 4×64-bit-limb
	// emulated.Element[BN254Fr]. The outer public signals are single native
	// BLS12-381 Fr values. Derive the limb representation in-circuit from
	// each Inputs[i].
	innerWitness := stdgroth16.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], len(c.Inputs)),
	}
	for i, in := range c.Inputs {
		innerWitness.Public[i] = emulated.Element[sw_bn254.ScalarField]{
			Limbs: nativeToBn254FrLimbs(api, in),
		}
	}

	// WithCompleteArithmetic is required because IC[i+1] for slots beyond the
	// inner system's n_real is the (0,0) point at infinity paired with a zero
	// scalar; the default sw_emulated MSM path rejects both edges.
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, innerWitness, stdgroth16.WithCompleteArithmetic()); err != nil {
		return err
	}

	perm, err := poseidon2.NewPoseidon2FromParameters(api, PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, perm, 0)
	for _, limb := range innerVKLimbs(&c.VerifyingKey) {
		hasher.Write(limb)
	}
	api.AssertIsEqual(c.InnerVKHash, hasher.Sum())

	return nil
}

// nativeToBn254FrLimbs decomposes a native BLS12-381 Fr variable into 4
// little-endian 64-bit limbs matching emulated.Element[BN254Fr].
//
// Soundness note: BN254 Fr modulus is < 2^254 by a small margin, so the
// decomposition accepts values in [BN254_Fr_modulus, 2^254). A non-canonical
// scalar in that gap still passes the inner pairing (EC scalar mul is modular)
// but produces a non-matching InnerVKHash / outer Inputs[i] — the Aiken
// validator's hardcoded constants should catch the mismatch.
func nativeToBn254FrLimbs(api frontend.API, v frontend.Variable) []frontend.Variable {
	const bn254FrBits = 254
	const bitsPerLimb = 64
	bits := api.ToBinary(v, bn254FrBits)
	limbs := make([]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		start := i * bitsPerLimb
		end := start + bitsPerLimb
		if end > len(bits) {
			end = len(bits)
		}
		limbs[i] = api.FromBinary(bits[start:end]...)
	}
	return limbs
}

// innerVKLimbs flattens the gnark recursive-form inner VK into a deterministic
// limb sequence used as the Poseidon2-MD preimage.
//
// Order: E ∈ Gt (A0..A11) || GammaNeg.{X,Y}.{A0,A1} || DeltaNeg.{X,Y}.{A0,A1} ||
// IC[0].{X,Y} || IC[1].{X,Y} || ... || IC[MAX_INPUTS].{X,Y}.
//
// Each emulated.Element contributes 4 little-endian 64-bit limbs.
func innerVKLimbs(vk *stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]) []frontend.Variable {
	var out []frontend.Variable
	e := &vk.E
	for _, el := range []*emulated.Element[emulated.BN254Fp]{
		&e.A0, &e.A1, &e.A2, &e.A3, &e.A4, &e.A5, &e.A6, &e.A7, &e.A8, &e.A9, &e.A10, &e.A11,
	} {
		out = append(out, el.Limbs...)
	}
	for _, g := range []*sw_bn254.G2Affine{&vk.G2.GammaNeg, &vk.G2.DeltaNeg} {
		out = append(out, g.P.X.A0.Limbs...)
		out = append(out, g.P.X.A1.Limbs...)
		out = append(out, g.P.Y.A0.Limbs...)
		out = append(out, g.P.Y.A1.Limbs...)
	}
	for i := range vk.G1.K {
		out = append(out, vk.G1.K[i].X.Limbs...)
		out = append(out, vk.G1.K[i].Y.Limbs...)
	}
	return out
}
