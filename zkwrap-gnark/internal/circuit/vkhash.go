package circuit

import (
	"fmt"
	"math/big"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidonbls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
)

// ComputeInnerVKHash mirrors innerVKLimbs + the in-circuit Poseidon2-MD
// off-circuit so the InnerVKHash public-witness assignment matches the
// in-circuit recomputation. Operates on the native BN254 verifying key,
// padding IC to maxInputs+1 with zero G1 points.
func ComputeInnerVKHash(vk *bn254groth16.VerifyingKey, maxInputs int) (blsfr.Element, error) {
	e, err := bn254.Pair([]bn254.G1Affine{vk.G1.Alpha}, []bn254.G2Affine{vk.G2.Beta})
	if err != nil {
		return blsfr.Element{}, fmt.Errorf("precompute e(alpha,beta): %w", err)
	}
	var gammaNeg, deltaNeg bn254.G2Affine
	gammaNeg.Neg(&vk.G2.Gamma)
	deltaNeg.Neg(&vk.G2.Delta)

	hasher := poseidonbls.NewMerkleDamgardHasher()
	writeFp := func(x bn254fp.Element) {
		for _, limb := range fpLimbs64(x) {
			var fe blsfr.Element
			fe.SetUint64(limb)
			buf := fe.Bytes()
			if _, err := hasher.Write(buf[:]); err != nil {
				panic(err)
			}
		}
	}
	writeG1 := func(p bn254.G1Affine) {
		writeFp(p.X)
		writeFp(p.Y)
	}
	writeG2 := func(p bn254.G2Affine) {
		writeFp(p.X.A0)
		writeFp(p.X.A1)
		writeFp(p.Y.A0)
		writeFp(p.Y.A1)
	}

	// E ∈ Gt: 12 Fp elements (A0..A11) in the emulated basis used by gnark's
	// sw_bn254.GTEl. The mapping from native bn254.GT (C0/C1.B0/B1/B2.A0/A1)
	// applies a 9-twist: see sw_bn254.NewGTEl.
	for _, fp := range gtEmulatedBasis(&e) {
		writeFp(fp)
	}
	writeG2(gammaNeg)
	writeG2(deltaNeg)
	for i := 0; i < maxInputs+1; i++ {
		if i < len(vk.G1.K) {
			writeG1(vk.G1.K[i])
		} else {
			writeG1(bn254.G1Affine{})
		}
	}

	var digest blsfr.Element
	if err := digest.SetBytesCanonical(hasher.Sum(nil)); err != nil {
		return blsfr.Element{}, fmt.Errorf("digest decode: %w", err)
	}
	return digest, nil
}

// PadInnerVK returns a copy of vk with IC padded to maxInputs+1 by appending
// zero G1 points. The wrapper circuit's IC slot count is fixed at MAX_INPUTS+1
// regardless of the inner system's n_real.
func PadInnerVK(vk *bn254groth16.VerifyingKey, maxInputs int) (*bn254groth16.VerifyingKey, error) {
	out := *vk
	out.G1.K = make([]bn254.G1Affine, maxInputs+1)
	copy(out.G1.K, vk.G1.K)
	if err := out.Precompute(); err != nil {
		return nil, fmt.Errorf("precompute padded vk: %w", err)
	}
	return &out, nil
}

// gtEmulatedBasis converts a native bn254.GT into the 12 Fp coordinates that
// gnark's sw_bn254.GTEl carries (A0..A11). Mirrors sw_bn254.NewGTEl, which
// applies a 9-twist.
func gtEmulatedBasis(gt *bn254.GT) [12]bn254fp.Element {
	var out [12]bn254fp.Element
	twist := func(a0, a1 bn254fp.Element) bn254fp.Element {
		var t, r bn254fp.Element
		t.SetUint64(9)
		t.Mul(&t, &a1)
		r.Sub(&a0, &t)
		return r
	}
	out[0] = twist(gt.C0.B0.A0, gt.C0.B0.A1)
	out[1] = twist(gt.C1.B0.A0, gt.C1.B0.A1)
	out[2] = twist(gt.C0.B1.A0, gt.C0.B1.A1)
	out[3] = twist(gt.C1.B1.A0, gt.C1.B1.A1)
	out[4] = twist(gt.C0.B2.A0, gt.C0.B2.A1)
	out[5] = twist(gt.C1.B2.A0, gt.C1.B2.A1)
	out[6] = gt.C0.B0.A1
	out[7] = gt.C1.B0.A1
	out[8] = gt.C0.B1.A1
	out[9] = gt.C1.B1.A1
	out[10] = gt.C0.B2.A1
	out[11] = gt.C1.B2.A1
	return out
}

// fpLimbs64 decomposes a BN254 Fp element into 4 little-endian 64-bit limbs.
func fpLimbs64(x bn254fp.Element) [4]uint64 {
	var bi big.Int
	x.BigInt(&bi)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	tmp := new(big.Int).Set(&bi)
	var out [4]uint64
	for i := 0; i < 4; i++ {
		out[i] = new(big.Int).And(tmp, mask).Uint64()
		tmp.Rsh(tmp, 64)
	}
	return out
}
