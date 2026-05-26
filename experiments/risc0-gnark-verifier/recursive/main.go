// Phase-2 step-1 benchmark: parameterised MAX_INPUTS wrapper circuit.
//
// Implements the wrapper circuit per ADR-0001 / ADR-0002 / ADR-0005:
//   - Inner BN254 Groth16 verification (proof + VK are private witness)
//   - Outer public signals: [InnerVKHash, input_0..input_{MAX_INPUTS-1}]
//   - InnerVKHash = Poseidon2-MD over BLS12-381 Fr of the gnark-recursive-form
//     inner VK limbs
//   - Inner-witness scalars are derived in-circuit from the outer public inputs
//
// The circuit is universal in `n_real`: it does not know how many of the
// MAX_INPUTS slots are real for a given inner system. The fixture loader below
// is RISC-Zero-specific and uses `innerNPublic = 5` to choose how many real
// values to assign before zero-padding to MAX_INPUTS — that is a property of
// the test data, not of the circuit.
//
// Run for a single value of MAX_INPUTS:
//
//	go run ./recursive -max-inputs 8
//
// Reports constraint count, compile/setup/prove/verify time, and peak RSS.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidonbls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"

	"github.com/consensys/gnark/backend/groth16"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"risc0-gnark-verifier/parse"
)

const (
	fixturesDir  = "../risc0-hello-world/fixtures"
	innerNPublic = 5 // n_real for RISC Zero

	// Poseidon2 over BLS12-381 Fr, gnark-crypto default parameters.
	// In-circuit and off-circuit hashers must agree on these.
	poseidonWidth         = 2
	poseidonFullRounds    = 6
	poseidonPartialRounds = 50
)

// OuterCircuit wraps a BN254 Groth16 inner proof inside a BLS12-381 Groth16
// outer proof. Outer public signals: [InnerVKHash, input_0..input_{MAX-1}].
//
// The circuit is universal in `n_real`: it has no knowledge of how many of the
// MAX_INPUTS slots are "real" for a given inner system. The prover assigns the
// inner system's public inputs to the first n_real slots and zero to the rest;
// the Aiken validator (per ADR-0002) should enforce the excess-zero check on-chain.
type OuterCircuit struct {
	InnerVKHash frontend.Variable   `gnark:",public"`
	Inputs      []frontend.Variable `gnark:",public"`

	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
}

func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}

	// The inner Groth16 verifier consumes scalars as 4×64-bit-limb
	// emulated.Element[BN254Fr]. The outer public signals are single native
	// BLS12-381 Fr values. We derive the limb representation in-circuit from
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
	// inner system's n_real is the (0,0) point at infinity (canonical zero-pad
	// convention) paired with a zero scalar. The default sw_emulated MSM path
	// requires non-zero points and non-zero scalars; complete arithmetic
	// handles both edge cases at the cost of extra constraints.
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, innerWitness, stdgroth16.WithCompleteArithmetic()); err != nil {
		return err
	}

	perm, err := poseidon2.NewPoseidon2FromParameters(api, poseidonWidth, poseidonFullRounds, poseidonPartialRounds)
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
// little-endian 64-bit limbs that match emulated.Element[BN254Fr]'s layout.
// api.ToBinary(v, 254) range-checks v < 2^254 (BN254 Fr is ~254 bits).
//
// Soundness note: BN254 Fr modulus is < 2^254 (by a small margin), so the
// decomposition accepts values in the gap [BN254_Fr_modulus, 2^254). A
// non-canonical scalar in that gap still passes the inner Groth16 pairing
// (because elliptic-curve scalar multiplication is intrinsically modular),
// but produces an outer InnerVKHash + outer Inputs[i] that won't match the
// Aiken validator's hardcoded constants. The Aiken layer catches the mismatch
// per ADR-0002.
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

// computeInnerVKHash mirrors innerVKLimbs + the in-circuit Poseidon2-MD
// off-circuit, so that the InnerVKHash public-witness assignment matches the
// in-circuit recomputation. Operates on the native BN254 verifying key, padding
// IC to MAX_INPUTS+1 with zero G1 points.
func computeInnerVKHash(vk *bn254groth16.VerifyingKey, maxInputs int) (blsfr.Element, error) {
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
	// sw_bn254.GTEl. The mapping from the native bn254.GT (C0/C1.B0/B1/B2.A0/A1)
	// applies a 9-twist: see sw_bn254.NewGTEl in std/algebra/emulated/sw_bn254/pairing.go.
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

// gtEmulatedBasis converts a native bn254.GT into the 12 Fp coordinates that
// gnark's sw_bn254.GTEl carries (A0..A11). Mirrors sw_bn254.NewGTEl, which
// applies a 9-twist:
//
//	A0 = C0.B0.A0 - 9·C0.B0.A1, A6 = C0.B0.A1
//	A1 = C1.B0.A0 - 9·C1.B0.A1, A7 = C1.B0.A1
//	A2 = C0.B1.A0 - 9·C0.B1.A1, A8 = C0.B1.A1
//	A3 = C1.B1.A0 - 9·C1.B1.A1, A9 = C1.B1.A1
//	A4 = C0.B2.A0 - 9·C0.B2.A1, A10 = C0.B2.A1
//	A5 = C1.B2.A0 - 9·C1.B2.A1, A11 = C1.B2.A1
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

// fpLimbs64 decomposes a BN254 Fp element into 4 little-endian 64-bit limbs,
// matching gnark's emulated.Element[BN254Fp] limb layout.
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

// padInnerVK returns a copy of the inner VK with IC padded to maxInputs+1 by
// appending zero G1 points. Required so the wrapper circuit's IC slot count
// matches MAX_INPUTS regardless of the inner system's n_real.
func padInnerVK(vk *bn254groth16.VerifyingKey, maxInputs int) *bn254groth16.VerifyingKey {
	out := *vk
	out.G1.K = make([]bn254.G1Affine, maxInputs+1)
	copy(out.G1.K, vk.G1.K)
	if err := out.Precompute(); err != nil {
		panic(fmt.Errorf("precompute padded vk: %w", err))
	}
	return &out
}

type benchResult struct {
	maxInputs     int
	constraints   int
	compileTime   time.Duration
	setupTime     time.Duration
	proveTime     time.Duration
	verifyTime    time.Duration
	peakRSSKbytes int
}

func main() {
	maxInputs := flag.Int("max-inputs", 5, "wrapper circuit MAX_INPUTS")
	flag.Parse()
	if *maxInputs < innerNPublic {
		die("max-inputs", fmt.Errorf("must be >= innerNPublic (%d)", innerNPublic))
	}

	vk, err := parse.LoadVK(fixturesDir + "/vk.json")
	die("load vk", err)
	proof, err := parse.LoadSeal(fixturesDir + "/seal.bin")
	die("load seal", err)
	pubInputs, err := parse.LoadPublicInputs(fixturesDir + "/public_inputs.json")
	die("load public inputs", err)
	if len(pubInputs) != innerNPublic {
		die("public inputs count", fmt.Errorf("got %d, expected %d", len(pubInputs), innerNPublic))
	}

	res := runOnce(*maxInputs, vk, proof, pubInputs)
	printResult(res)
}

func runOnce(maxInputs int, vk *bn254groth16.VerifyingKey, proof *bn254groth16.Proof, pubInputs []bn254fr.Element) benchResult {
	res := benchResult{maxInputs: maxInputs}

	paddedVK := padInnerVK(vk, maxInputs)

	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](paddedVK)
	die("vk to circuit", err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
	die("proof to circuit", err)

	placeholder := &OuterCircuit{
		Inputs: make([]frontend.Variable, maxInputs),
		VerifyingKey: stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			G1: struct{ K []sw_bn254.G1Affine }{
				K: make([]sw_bn254.G1Affine, maxInputs+1),
			},
			PublicAndCommitmentCommitted: [][]int{},
		},
	}

	fmt.Printf("=== MAX_INPUTS=%d ===\n", maxInputs)
	fmt.Print("Compiling outer circuit... ")
	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, placeholder)
	die("compile", err)
	res.compileTime = time.Since(t)
	res.constraints = ccs.GetNbConstraints()
	fmt.Printf("%d constraints (%s)\n", res.constraints, res.compileTime)

	fmt.Print("Setup (unsafe random)... ")
	t = time.Now()
	pk, outerVK, err := groth16.Setup(ccs)
	die("setup", err)
	res.setupTime = time.Since(t)
	fmt.Printf("done (%s)\n", res.setupTime)

	innerVKHash, err := computeInnerVKHash(vk, maxInputs)
	die("compute InnerVKHash", err)

	inputs := make([]frontend.Variable, maxInputs)
	for i := 0; i < maxInputs; i++ {
		if i < innerNPublic {
			var bi big.Int
			pubInputs[i].BigInt(&bi)
			inputs[i] = bi
		} else {
			inputs[i] = 0
		}
	}
	var hashBi big.Int
	innerVKHash.BigInt(&hashBi)
	assignment := &OuterCircuit{
		InnerVKHash:  hashBi,
		Inputs:       inputs,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
	}
	outerWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	die("outer witness", err)

	fmt.Print("Proving... ")
	t = time.Now()
	outerProof, err := groth16.Prove(ccs, pk, outerWitness)
	die("prove", err)
	res.proveTime = time.Since(t)
	fmt.Printf("done (%s)\n", res.proveTime)

	outerPubWitness, err := outerWitness.Public()
	die("public witness", err)
	fmt.Print("Verifying outer proof... ")
	t = time.Now()
	if err := groth16.Verify(outerProof, outerVK, outerPubWitness); err != nil {
		die("verify outer", err)
	}
	res.verifyTime = time.Since(t)
	fmt.Printf("PASS (%s)\n", res.verifyTime)

	res.peakRSSKbytes = readPeakRSSKb()
	return res
}

func printResult(r benchResult) {
	fmt.Println()
	fmt.Println("---- benchmark summary ----")
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "MAX_INPUTS    : %d\n", r.maxInputs)
	fmt.Fprintf(w, "constraints   : %d\n", r.constraints)
	fmt.Fprintf(w, "compile time  : %s\n", r.compileTime)
	fmt.Fprintf(w, "setup time    : %s\n", r.setupTime)
	fmt.Fprintf(w, "prove time    : %s\n", r.proveTime)
	fmt.Fprintf(w, "verify time   : %s\n", r.verifyTime)
	fmt.Fprintf(w, "peak RSS      : %.2f MiB\n", float64(r.peakRSSKbytes)/1024.0)
}

// readPeakRSSKb reads VmHWM from /proc/self/status, in kibibytes.
func readPeakRSSKb() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
