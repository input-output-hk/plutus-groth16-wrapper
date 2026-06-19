// Command refverify is a DETERMINISTIC reference verifier for the gnark PLONK
// proof exported by ../export. It reads the JSON artifacts (exactly what the
// Aiken verifier will consume), reproduces gnark's verification using only
// primitives a Cardano validator has (SHA-256 + BLS12-381 ops), and dumps every
// intermediate challenge as a golden vector for the Aiken port.
//
// It diverges from gnark's Go plonk.Verify in ONE place: the final
// two-opening KZG batch. gnark's kzg.BatchVerifyMultiPoints folds with a
// *random* λ (not reproducible on-chain); here λ is derived by SHA-256 from the
// folded state, mirroring gnark's PLONK Solidity verifier. A valid proof
// verifies under any λ, so this stays sound. THROWAWAY spike code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/hash_to_field"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
)

func main() {
	dir := "../artifacts"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	vk, err := loadVK(dir + "/outer_vk.json")
	die("load vk", err)
	pf, err := loadProof(dir + "/outer_proof.json")
	die("load proof", err)

	golden, err := verify(vk, pf)
	die("verify (valid proof)", err)
	fmt.Fprintln(os.Stderr, "valid proof: PASS")

	// tamper-negative: bump the first public input; verification must fail.
	tampered := *pf
	tampered.PublicInputs = append([]fr.Element(nil), pf.PublicInputs...)
	var one fr.Element
	one.SetOne()
	tampered.PublicInputs[0].Add(&tampered.PublicInputs[0], &one)
	if _, err := verify(vk, &tampered); err == nil {
		die("tamper check", fmt.Errorf("tampered proof unexpectedly verified"))
	}
	fmt.Fprintln(os.Stderr, "tampered proof: correctly REJECTED")

	out := dir + "/golden.json"
	die("write golden", writeJSON(out, golden))
	fmt.Fprintf(os.Stderr, "wrote golden vectors to %s\n", out)
}

// ---- verification ----------------------------------------------------------

type Golden struct {
	Gamma        string   `json:"gamma"`
	Beta         string   `json:"beta"`
	Alpha        string   `json:"alpha"`
	Zeta         string   `json:"zeta"`
	PI           string   `json:"pi"`
	HashedCmt    []string `json:"hashed_commitments"`
	ConstLin     string   `json:"const_lin"`
	OpeningLin   string   `json:"opening_lin"`
	GammaKZG     string   `json:"gamma_kzg"`
	BatchLambdaU string   `json:"batch_lambda_u"`
	LinDigest    string   `json:"lin_digest_compressed"`
	LinDigestU   string   `json:"lin_digest_uncompressed"`
	FoldedDigest string   `json:"folded_digest_compressed"`
	FoldedEval   string   `json:"folded_eval"`
}

func verify(vk *VK, p *Proof) (*Golden, error) {
	g := &Golden{}

	// --- transcript: gamma, beta, alpha, zeta (SHA-256) ---
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma", "beta", "alpha", "zeta")

	// gamma binds: S0,S1,S2,Ql,Qr,Qm,Qo,Qk,Qcp[], PI[], LRO[0..2]
	for _, pt := range []bls12381.G1Affine{vk.S[0], vk.S[1], vk.S[2], vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk} {
		bind(fs, "gamma", marshalG1(pt))
	}
	for _, pt := range vk.Qcp {
		bind(fs, "gamma", marshalG1(pt))
	}
	for i := range p.PublicInputs {
		bind(fs, "gamma", marshalFr(p.PublicInputs[i]))
	}
	bind(fs, "gamma", marshalG1(p.LRO[0]), marshalG1(p.LRO[1]), marshalG1(p.LRO[2]))
	gamma := challenge(fs, "gamma")

	beta := challenge(fs, "beta")

	for i := range p.Bsb22 {
		bind(fs, "alpha", marshalG1(p.Bsb22[i]))
	}
	bind(fs, "alpha", marshalG1(p.Z))
	alpha := challenge(fs, "alpha")

	bind(fs, "zeta", marshalG1(p.H[0]), marshalG1(p.H[1]), marshalG1(p.H[2]))
	zeta := challenge(fs, "zeta")

	g.Gamma, g.Beta, g.Alpha, g.Zeta = frHex(gamma), frHex(beta), frHex(alpha), frHex(zeta)

	// --- zh, L1, PI ---
	one := fr.One()
	var zetaPowerM, zhZeta, lagrangeZero fr.Element
	var bExpo big.Int
	bExpo.SetUint64(vk.Size)
	zetaPowerM.Exp(zeta, &bExpo)
	zhZeta.Sub(&zetaPowerM, &one)
	lagrangeZero.Sub(&zeta, &one).Inverse(&lagrangeZero).Mul(&lagrangeZero, &zhZeta).Mul(&lagrangeZero, &vk.SizeInv)

	var pi fr.Element
	{
		dens := make([]fr.Element, len(p.PublicInputs))
		accw := fr.One()
		for i := range p.PublicInputs {
			dens[i].Sub(&zeta, &accw)
			accw.Mul(&accw, &vk.Generator)
		}
		invDens := fr.BatchInvert(dens)
		accw = fr.One()
		var xiLi fr.Element
		for i := range p.PublicInputs {
			xiLi.Mul(&zhZeta, &invDens[i]).Mul(&xiLi, &vk.SizeInv).Mul(&xiLi, &accw).Mul(&xiLi, &p.PublicInputs[i])
			accw.Mul(&accw, &vk.Generator)
			pi.Add(&pi, &xiLi)
		}

		// BSB22 commitment contribution, RFC-9380 hash-to-field (DST "BSB22-Plonk").
		htf := hash_to_field.New([]byte("BSB22-Plonk"))
		nbBuf := fr.Bytes
		if htf.Size() < fr.Bytes {
			nbBuf = htf.Size()
		}
		var hashedCmt, wPowI, den, lagrange fr.Element
		for i, cci := range vk.CommitmentConstraintIndexes {
			htf.Write(marshalG1(p.Bsb22[i]))
			hb := htf.Sum(nil)
			htf.Reset()
			hashedCmt.SetBytes(hb[:nbBuf])
			g.HashedCmt = append(g.HashedCmt, frHex(hashedCmt))

			wPowI.Exp(vk.Generator, big.NewInt(int64(vk.NbPublicVariables)+int64(cci)))
			den.Sub(&zeta, &wPowI)
			lagrange.SetOne().Sub(&zetaPowerM, &lagrange).Mul(&lagrange, &wPowI).Div(&lagrange, &den).Mul(&lagrange, &vk.SizeInv)
			xiLi.Mul(&lagrange, &hashedCmt)
			pi.Add(&pi, &xiLi)
		}
	}
	g.PI = frHex(pi)

	// --- linearization constant term ---
	l := p.Batched.ClaimedValues[1]
	r := p.Batched.ClaimedValues[2]
	o := p.Batched.ClaimedValues[3]
	s1 := p.Batched.ClaimedValues[4]
	s2 := p.Batched.ClaimedValues[5]
	zu := p.ZShifted.ClaimedValue

	var alphaSqL1 fr.Element
	alphaSqL1.Mul(&lagrangeZero, &alpha).Mul(&alphaSqL1, &alpha)

	var constLin, tmp fr.Element
	constLin.Mul(&beta, &s1).Add(&constLin, &gamma).Add(&constLin, &l)
	tmp.Mul(&s2, &beta).Add(&tmp, &gamma).Add(&tmp, &r)
	constLin.Mul(&constLin, &tmp)
	tmp.Add(&o, &gamma)
	constLin.Mul(&tmp, &constLin).Mul(&constLin, &alpha).Mul(&constLin, &zu)
	constLin.Sub(&constLin, &alphaSqL1).Add(&constLin, &pi)
	constLin.Neg(&constLin)

	openingLin := p.Batched.ClaimedValues[0]
	g.ConstLin, g.OpeningLin = frHex(constLin), frHex(openingLin)
	if !constLin.Equal(&openingLin) {
		return g, fmt.Errorf("algebraic relation does not hold")
	}

	// --- linearized polynomial digest (MSM) ---
	var _s1, _s2 fr.Element
	_s1.Mul(&beta, &s1).Add(&_s1, &l).Add(&_s1, &gamma)
	tmp.Mul(&beta, &s2).Add(&tmp, &r).Add(&tmp, &gamma)
	_s1.Mul(&_s1, &tmp).Mul(&_s1, &beta).Mul(&_s1, &alpha).Mul(&_s1, &zu)

	_s2.Mul(&beta, &zeta).Add(&_s2, &gamma).Add(&_s2, &l)
	tmp.Mul(&beta, &vk.CosetShift).Mul(&tmp, &zeta).Add(&tmp, &gamma).Add(&tmp, &r)
	_s2.Mul(&_s2, &tmp)
	tmp.Mul(&beta, &vk.CosetShift).Mul(&tmp, &vk.CosetShift).Mul(&tmp, &zeta).Add(&tmp, &o).Add(&tmp, &gamma)
	_s2.Mul(&_s2, &tmp).Mul(&_s2, &alpha).Neg(&_s2)

	var coeffZ fr.Element
	coeffZ.Add(&alphaSqL1, &_s2)
	var rl fr.Element
	rl.Mul(&l, &r)

	nPlusTwo := big.NewInt(int64(vk.Size) + 2)
	var zN2Zh, zN2SqZh, zh fr.Element
	zN2Zh.Exp(zeta, nPlusTwo)
	zN2SqZh.Mul(&zN2Zh, &zN2Zh)
	zN2Zh.Mul(&zN2Zh, &zhZeta).Neg(&zN2Zh)
	zN2SqZh.Mul(&zN2SqZh, &zhZeta).Neg(&zN2SqZh)
	zh.Neg(&zhZeta)

	points := append([]bls12381.G1Affine{}, p.Bsb22...)
	points = append(points, vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk, vk.S[2], p.Z, p.H[0], p.H[1], p.H[2])
	qC := make([]fr.Element, len(p.Bsb22))
	copy(qC, p.Batched.ClaimedValues[6:])
	scalars := append([]fr.Element{}, qC...)
	scalars = append(scalars, l, r, rl, o, one, _s1, coeffZ, zh, zN2Zh, zN2SqZh)

	var linDigest bls12381.G1Affine
	if _, err := linDigest.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return g, err
	}
	g.LinDigest = hex.EncodeToString(compressG1(linDigest))
	g.LinDigestU = hex.EncodeToString(marshalG1(linDigest))

	// --- KZG fold (gamma_kzg) over [linDigest, L,R,O, S1,S2, Qcp...] ---
	digests := []bls12381.G1Affine{linDigest, p.LRO[0], p.LRO[1], p.LRO[2], vk.S[0], vk.S[1]}
	digests = append(digests, vk.Qcp...)
	claimed := p.Batched.ClaimedValues // [lin, l, r, o, s1, s2, qcp...]

	gammaKZG := deriveGammaKZG(zeta, digests, claimed, zu)
	g.GammaKZG = frHex(gammaKZG)

	gammai := make([]fr.Element, len(digests))
	gammai[0].SetOne()
	if len(gammai) > 1 {
		gammai[1] = gammaKZG
	}
	for i := 2; i < len(gammai); i++ {
		gammai[i].Mul(&gammai[i-1], &gammaKZG)
	}
	foldedDigest, foldedEval, err := foldKZG(digests, claimed, gammai)
	if err != nil {
		return g, err
	}
	g.FoldedDigest = hex.EncodeToString(compressG1(foldedDigest))
	g.FoldedEval = frHex(foldedEval)

	// --- deterministic two-opening batch (Solidity-style λ) ---
	// opening 0: foldedDigest at zeta, proof H0 = Batched.H, eval0 = foldedEval
	// opening 1: Z          at ζω,   proof H1 = ZShifted.H, eval1 = zu
	var shiftedZeta fr.Element
	shiftedZeta.Mul(&zeta, &vk.Generator)

	u := deriveBatchLambda(foldedDigest, p.Z)
	g.BatchLambdaU = frHex(u)

	H0, H1 := p.Batched.H, p.ZShifted.H

	// foldedQuotients = H0 + u·H1
	var uBig big.Int
	u.BigInt(&uBig)
	var uH1, foldedQuot bls12381.G1Affine
	uH1.ScalarMultiplication(&H1, &uBig)
	foldedQuot.Add(&H0, &uH1)

	// foldedDigests = (foldedDigest + u·Z) - (foldedEval + u·zu)·G1 + (zeta·H0 + u·shiftedZeta·H1)
	var uZ, acc bls12381.G1Affine
	uZ.ScalarMultiplication(&p.Z, &uBig)
	acc.Add(&foldedDigest, &uZ)

	var foldedEvalScalar fr.Element
	foldedEvalScalar.Mul(&u, &zu).Add(&foldedEvalScalar, &foldedEval)
	var fesBig big.Int
	foldedEvalScalar.BigInt(&fesBig)
	var evalCommit bls12381.G1Affine
	evalCommit.ScalarMultiplication(&vk.KzgG1, &fesBig)
	acc.Sub(&acc, &evalCommit)

	var zetaBig, uShiftedBig big.Int
	zeta.BigInt(&zetaBig)
	var uShifted fr.Element
	uShifted.Mul(&u, &shiftedZeta)
	uShifted.BigInt(&uShiftedBig)
	var t0, t1 bls12381.G1Affine
	t0.ScalarMultiplication(&H0, &zetaBig)
	t1.ScalarMultiplication(&H1, &uShiftedBig)
	t0.Add(&t0, &t1)
	acc.Add(&acc, &t0)

	// pairing: e(acc, [1]_2) · e(-foldedQuot, [s]_2) == 1
	var negQuot bls12381.G1Affine
	negQuot.Neg(&foldedQuot)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{acc, negQuot},
		[]bls12381.G2Affine{vk.KzgG2[0], vk.KzgG2[1]},
	)
	if err != nil {
		return g, err
	}
	if !ok {
		return g, fmt.Errorf("pairing check failed")
	}
	return g, nil
}

// ---- transcript helpers ----------------------------------------------------

func bind(fs *fiatshamir.Transcript, name string, vals ...[]byte) {
	for _, v := range vals {
		if err := fs.Bind(name, v); err != nil {
			panic(err)
		}
	}
}

func challenge(fs *fiatshamir.Transcript, name string) fr.Element {
	b, err := fs.ComputeChallenge(name)
	if err != nil {
		panic(err)
	}
	var e fr.Element
	e.SetBytes(b)
	return e
}

// deriveGammaKZG reproduces gnark's KZG-fold challenge (kzg.deriveGamma). It
// MUST match the prover exactly — the prover's batched-opening quotient
// (BatchedProof.H) is computed with this gamma_kzg — so it binds UNCOMPRESSED
// digests (gnark .Marshal()). On-chain the only computed digest is the
// linearized-poly digest; the Aiken verifier gets its uncompressed bytes from
// the proof and binds them via compress(computed) == compress(provided).
func deriveGammaKZG(point fr.Element, digests []bls12381.G1Affine, claimed []fr.Element, zu fr.Element) fr.Element {
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma")
	bind(fs, "gamma", marshalFr(point))
	for i := range digests {
		bind(fs, "gamma", marshalG1(digests[i]))
	}
	for i := range claimed {
		bind(fs, "gamma", marshalFr(claimed[i]))
	}
	bind(fs, "gamma", marshalFr(zu))
	return challenge(fs, "gamma")
}

// deriveBatchLambda derives the two-opening batching scalar by SHA-256 over the
// folded digest and the grand-product commitment, COMPRESSED (mirrors gnark's
// Solidity batch_verify_multi_points `random`, adapted to compressed points).
func deriveBatchLambda(foldedDigest, z bls12381.G1Affine) fr.Element {
	h := sha256.New()
	h.Write(compressG1(foldedDigest))
	h.Write(compressG1(z))
	var e fr.Element
	e.SetBytes(h.Sum(nil))
	return e
}

func foldKZG(di []bls12381.G1Affine, fai, ci []fr.Element) (bls12381.G1Affine, fr.Element, error) {
	var foldedEval, tmp fr.Element
	for i := range di {
		tmp.Mul(&fai[i], &ci[i])
		foldedEval.Add(&foldedEval, &tmp)
	}
	var foldedDigest bls12381.G1Affine
	_, err := foldedDigest.MultiExp(di, ci, ecc.MultiExpConfig{})
	return foldedDigest, foldedEval, err
}

func marshalG1(p bls12381.G1Affine) []byte  { return p.Marshal() }          // uncompressed 96B
func compressG1(p bls12381.G1Affine) []byte { b := p.Bytes(); return b[:] } // compressed 48B
func marshalFr(e fr.Element) []byte         { b := e.Bytes(); return b[:] }
func frHex(e fr.Element) string             { b := e.Bytes(); return hex.EncodeToString(b[:]) }

// ---- artifact loading ------------------------------------------------------

type VK struct {
	Size                        uint64
	SizeInv                     fr.Element
	Generator                   fr.Element
	NbPublicVariables           uint64
	CosetShift                  fr.Element
	KzgG1                       bls12381.G1Affine
	KzgG2                       [2]bls12381.G2Affine
	S                           [3]bls12381.G1Affine
	Ql, Qr, Qm, Qo, Qk          bls12381.G1Affine
	Qcp                         []bls12381.G1Affine
	CommitmentConstraintIndexes []uint64
}

type Proof struct {
	PublicInputs []fr.Element
	LRO          [3]bls12381.G1Affine
	Z            bls12381.G1Affine
	H            [3]bls12381.G1Affine
	Bsb22        []bls12381.G1Affine
	Batched      struct {
		H             bls12381.G1Affine
		ClaimedValues []fr.Element
	}
	ZShifted struct {
		H            bls12381.G1Affine
		ClaimedValue fr.Element
	}
}

func loadVK(path string) (*VK, error) {
	var j struct {
		Size                        uint64 `json:"size"`
		SizeInv                     string `json:"size_inv"`
		Generator                   string `json:"generator"`
		NbPublicVariables           uint64 `json:"nb_public_variables"`
		CosetShift                  string `json:"coset_shift"`
		Kzg                         struct{ G1, G2_0, G2_1 string }
		S                           []string `json:"s"`
		Ql, Qr, Qm, Qo, Qk          string
		Qcp                         []string `json:"qcp"`
		CommitmentConstraintIndexes []uint64 `json:"commitment_constraint_indexes"`
	}
	if err := readJSON(path, &j); err != nil {
		return nil, err
	}
	vk := &VK{Size: j.Size, NbPublicVariables: j.NbPublicVariables, CommitmentConstraintIndexes: j.CommitmentConstraintIndexes}
	vk.SizeInv = frFrom(j.SizeInv)
	vk.Generator = frFrom(j.Generator)
	vk.CosetShift = frFrom(j.CosetShift)
	vk.KzgG1 = g1From(j.Kzg.G1)
	vk.KzgG2[0] = g2From(j.Kzg.G2_0)
	vk.KzgG2[1] = g2From(j.Kzg.G2_1)
	for i := 0; i < 3; i++ {
		vk.S[i] = g1From(j.S[i])
	}
	vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk = g1From(j.Ql), g1From(j.Qr), g1From(j.Qm), g1From(j.Qo), g1From(j.Qk)
	for _, s := range j.Qcp {
		vk.Qcp = append(vk.Qcp, g1From(s))
	}
	return vk, nil
}

type g1obj struct {
	C string `json:"c"`
	U string `json:"u"`
}

func loadProof(path string) (*Proof, error) {
	var j struct {
		PublicInputs []string `json:"public_inputs"`
		LRO          []g1obj  `json:"lro"`
		Z            g1obj    `json:"z"`
		H            []g1obj  `json:"h"`
		Bsb22        []g1obj  `json:"bsb22_commitments"`
		Batched      struct {
			H             g1obj    `json:"h"`
			ClaimedValues []string `json:"claimed_values"`
		} `json:"batched_proof"`
		ZShifted struct {
			H            g1obj  `json:"h"`
			ClaimedValue string `json:"claimed_value"`
		} `json:"z_shifted_opening"`
	}
	if err := readJSON(path, &j); err != nil {
		return nil, err
	}
	p := &Proof{}
	for _, s := range j.PublicInputs {
		p.PublicInputs = append(p.PublicInputs, frFrom(s))
	}
	for i := 0; i < 3; i++ {
		p.LRO[i] = g1From(j.LRO[i].C)
		p.H[i] = g1From(j.H[i].C)
	}
	p.Z = g1From(j.Z.C)
	for _, b := range j.Bsb22 {
		p.Bsb22 = append(p.Bsb22, g1From(b.C))
	}
	p.Batched.H = g1From(j.Batched.H.C)
	for _, s := range j.Batched.ClaimedValues {
		p.Batched.ClaimedValues = append(p.Batched.ClaimedValues, frFrom(s))
	}
	p.ZShifted.H = g1From(j.ZShifted.H.C)
	p.ZShifted.ClaimedValue = frFrom(j.ZShifted.ClaimedValue)
	return p, nil
}

func frFrom(h string) fr.Element {
	b, err := hex.DecodeString(h)
	die("fr hex", err)
	var e fr.Element
	e.SetBytes(b)
	return e
}

func g1From(h string) bls12381.G1Affine {
	b, err := hex.DecodeString(h)
	die("g1 hex", err)
	var p bls12381.G1Affine
	if _, err := p.SetBytes(b); err != nil {
		die("g1 setbytes", err)
	}
	return p
}

func g2From(h string) bls12381.G2Affine {
	b, err := hex.DecodeString(h)
	die("g2 hex", err)
	var p bls12381.G2Affine
	if _, err := p.SetBytes(b); err != nil {
		die("g2 setbytes", err)
	}
	return p
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
