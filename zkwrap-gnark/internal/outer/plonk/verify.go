package plonk

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/hash_to_field"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
)

// VerifyDeterministic reproduces gnark PLONK verification using only the
// primitives a Cardano validator has — SHA-256 Fiat-Shamir + BLS12-381 ops —
// and returns the linearized-polynomial digest (linDigest) as a byproduct. The
// only divergence from gnark's Go plonk.Verify is the two-opening batch scalar,
// derived by SHA-256 (gnark's Solidity style) instead of a random lambda. A
// valid proof verifies under any lambda, so this stays sound.
//
// prove calls it to (a) obtain linDigest for the proof artifact and (b) confirm
// the freshly produced proof is on-chain-verifiable before writing it.
//
// publicWitness is the public-input vector [InnerVKHash, inputs...].
func VerifyDeterministic(vk *bls12381plonk.VerifyingKey, p *bls12381plonk.Proof, publicWitness []fr.Element) (bls12381.G1Affine, error) {
	var zero bls12381.G1Affine

	if len(p.Bsb22Commitments) != len(vk.Qcp) {
		return zero, fmt.Errorf("bsb22 commitments %d != qcp %d", len(p.Bsb22Commitments), len(vk.Qcp))
	}
	if uint64(len(publicWitness)) != vk.NbPublicVariables {
		return zero, fmt.Errorf("public witness length %d != nb_public_variables %d", len(publicWitness), vk.NbPublicVariables)
	}

	// --- transcript: gamma, beta, alpha, zeta (SHA-256) ---
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma", "beta", "alpha", "zeta")

	for _, pt := range []bls12381.G1Affine{vk.S[0], vk.S[1], vk.S[2], vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk} {
		if err := fsBind(fs, "gamma", fsMarshalG1(pt)); err != nil {
			return zero, err
		}
	}
	for _, pt := range vk.Qcp {
		if err := fsBind(fs, "gamma", fsMarshalG1(pt)); err != nil {
			return zero, err
		}
	}
	for i := range publicWitness {
		if err := fsBind(fs, "gamma", fsMarshalFr(publicWitness[i])); err != nil {
			return zero, err
		}
	}
	if err := fsBind(fs, "gamma", fsMarshalG1(p.LRO[0]), fsMarshalG1(p.LRO[1]), fsMarshalG1(p.LRO[2])); err != nil {
		return zero, err
	}
	gamma, err := fsChallenge(fs, "gamma")
	if err != nil {
		return zero, err
	}
	beta, err := fsChallenge(fs, "beta")
	if err != nil {
		return zero, err
	}
	for i := range p.Bsb22Commitments {
		if err := fsBind(fs, "alpha", fsMarshalG1(p.Bsb22Commitments[i])); err != nil {
			return zero, err
		}
	}
	if err := fsBind(fs, "alpha", fsMarshalG1(p.Z)); err != nil {
		return zero, err
	}
	alpha, err := fsChallenge(fs, "alpha")
	if err != nil {
		return zero, err
	}
	if err := fsBind(fs, "zeta", fsMarshalG1(p.H[0]), fsMarshalG1(p.H[1]), fsMarshalG1(p.H[2])); err != nil {
		return zero, err
	}
	zeta, err := fsChallenge(fs, "zeta")
	if err != nil {
		return zero, err
	}

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
		dens := make([]fr.Element, len(publicWitness))
		accw := fr.One()
		for i := range publicWitness {
			dens[i].Sub(&zeta, &accw)
			accw.Mul(&accw, &vk.Generator)
		}
		invDens := fr.BatchInvert(dens)
		accw = fr.One()
		var xiLi fr.Element
		for i := range publicWitness {
			xiLi.Mul(&zhZeta, &invDens[i]).Mul(&xiLi, &vk.SizeInv).Mul(&xiLi, &accw).Mul(&xiLi, &publicWitness[i])
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
			htf.Write(fsMarshalG1(p.Bsb22Commitments[i]))
			hb := htf.Sum(nil)
			htf.Reset()
			hashedCmt.SetBytes(hb[:nbBuf])

			wPowI.Exp(vk.Generator, big.NewInt(int64(vk.NbPublicVariables)+int64(cci)))
			den.Sub(&zeta, &wPowI)
			lagrange.SetOne().Sub(&zetaPowerM, &lagrange).Mul(&lagrange, &wPowI).Div(&lagrange, &den).Mul(&lagrange, &vk.SizeInv)
			xiLi.Mul(&lagrange, &hashedCmt)
			pi.Add(&pi, &xiLi)
		}
	}

	// --- linearization constant term (algebraic relation) ---
	l := p.BatchedProof.ClaimedValues[1]
	r := p.BatchedProof.ClaimedValues[2]
	o := p.BatchedProof.ClaimedValues[3]
	s1 := p.BatchedProof.ClaimedValues[4]
	s2 := p.BatchedProof.ClaimedValues[5]
	zu := p.ZShiftedOpening.ClaimedValue

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

	openingLin := p.BatchedProof.ClaimedValues[0]
	if !constLin.Equal(&openingLin) {
		return zero, fmt.Errorf("algebraic relation does not hold")
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

	points := append([]bls12381.G1Affine{}, p.Bsb22Commitments...)
	points = append(points, vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk, vk.S[2], p.Z, p.H[0], p.H[1], p.H[2])
	qC := make([]fr.Element, len(p.Bsb22Commitments))
	copy(qC, p.BatchedProof.ClaimedValues[6:])
	scalars := append([]fr.Element{}, qC...)
	scalars = append(scalars, l, r, rl, o, one, _s1, coeffZ, zh, zN2Zh, zN2SqZh)

	var linDigest bls12381.G1Affine
	if _, err := linDigest.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return zero, fmt.Errorf("linearized-poly MSM: %w", err)
	}

	// --- KZG fold (gamma_kzg) over [linDigest, L,R,O, S1,S2, Qcp...] ---
	digests := []bls12381.G1Affine{linDigest, p.LRO[0], p.LRO[1], p.LRO[2], vk.S[0], vk.S[1]}
	digests = append(digests, vk.Qcp...)
	claimed := p.BatchedProof.ClaimedValues // [lin, l, r, o, s1, s2, qcp...]

	gammaKZG, err := deriveGammaKZG(zeta, digests, claimed, zu)
	if err != nil {
		return zero, err
	}

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
		return zero, err
	}

	// --- deterministic two-opening batch (Solidity-style lambda) ---
	var shiftedZeta fr.Element
	shiftedZeta.Mul(&zeta, &vk.Generator)

	u := deriveBatchLambda(foldedDigest, p.Z)

	H0, H1 := p.BatchedProof.H, p.ZShiftedOpening.H

	var uBig big.Int
	u.BigInt(&uBig)
	var uH1, foldedQuot bls12381.G1Affine
	uH1.ScalarMultiplication(&H1, &uBig)
	foldedQuot.Add(&H0, &uH1)

	var uZ, acc bls12381.G1Affine
	uZ.ScalarMultiplication(&p.Z, &uBig)
	acc.Add(&foldedDigest, &uZ)

	var foldedEvalScalar fr.Element
	foldedEvalScalar.Mul(&u, &zu).Add(&foldedEvalScalar, &foldedEval)
	var fesBig big.Int
	foldedEvalScalar.BigInt(&fesBig)
	var evalCommit bls12381.G1Affine
	evalCommit.ScalarMultiplication(&vk.Kzg.G1, &fesBig)
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

	var negQuot bls12381.G1Affine
	negQuot.Neg(&foldedQuot)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{acc, negQuot},
		[]bls12381.G2Affine{vk.Kzg.G2[0], vk.Kzg.G2[1]},
	)
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, fmt.Errorf("pairing check failed")
	}
	return linDigest, nil
}

// deriveGammaKZG reproduces gnark's KZG-fold challenge (kzg.deriveGamma),
// binding UNCOMPRESSED digests (gnark .Marshal()).
func deriveGammaKZG(point fr.Element, digests []bls12381.G1Affine, claimed []fr.Element, zu fr.Element) (fr.Element, error) {
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma")
	if err := fsBind(fs, "gamma", fsMarshalFr(point)); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fsBind(fs, "gamma", fsMarshalG1(digests[i])); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimed {
		if err := fsBind(fs, "gamma", fsMarshalFr(claimed[i])); err != nil {
			return fr.Element{}, err
		}
	}
	if err := fsBind(fs, "gamma", fsMarshalFr(zu)); err != nil {
		return fr.Element{}, err
	}
	return fsChallenge(fs, "gamma")
}

// deriveBatchLambda derives the two-opening batching scalar by SHA-256 over the
// folded digest and the grand-product commitment, COMPRESSED (gnark's Solidity
// batch_verify_multi_points `random`, adapted to compressed points).
func deriveBatchLambda(foldedDigest, z bls12381.G1Affine) fr.Element {
	h := sha256.New()
	fd := foldedDigest.Bytes()
	zb := z.Bytes()
	h.Write(fd[:])
	h.Write(zb[:])
	var e fr.Element
	e.SetBytes(h.Sum(nil))
	return e
}

func foldKZG(di []bls12381.G1Affine, ci, fai []fr.Element) (bls12381.G1Affine, fr.Element, error) {
	var foldedEval, tmp fr.Element
	for i := range di {
		tmp.Mul(&fai[i], &ci[i])
		foldedEval.Add(&foldedEval, &tmp)
	}
	var foldedDigest bls12381.G1Affine
	_, err := foldedDigest.MultiExp(di, fai, ecc.MultiExpConfig{})
	return foldedDigest, foldedEval, err
}

func fsBind(fs *fiatshamir.Transcript, name string, vals ...[]byte) error {
	for _, v := range vals {
		if err := fs.Bind(name, v); err != nil {
			return err
		}
	}
	return nil
}

func fsChallenge(fs *fiatshamir.Transcript, name string) (fr.Element, error) {
	b, err := fs.ComputeChallenge(name)
	if err != nil {
		return fr.Element{}, err
	}
	var e fr.Element
	e.SetBytes(b)
	return e, nil
}

func fsMarshalG1(p bls12381.G1Affine) []byte { return p.Marshal() }
func fsMarshalFr(e fr.Element) []byte        { b := e.Bytes(); return b[:] }
