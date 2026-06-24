package plonk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
)

// proofFile is the canonical JSON envelope of a PLONK outer proof. Every G1
// point carries both encodings: "c" compressed (for EC ops) and "u"
// uncompressed (the exact preimage gnark hashes in the SHA-256 transcript,
// which Plutus cannot reproduce from a point). See
// docs/schemas/plonk-outer-proof-artifacts.md.
type proofFile struct {
	Backend         string       `json:"backend"`
	NumInputs       int          `json:"num_inputs"`
	InnerVKHash     string       `json:"inner_vk_hash"`
	Inputs          []string     `json:"inputs"`
	LRO             []g1Obj      `json:"lro"`
	Z               g1Obj        `json:"z"`
	H               []g1Obj      `json:"h"`
	Bsb22           []g1Obj      `json:"bsb22_commitments"`
	LinDigest       g1Obj        `json:"lin_digest"`
	BatchedProof    batchedProof `json:"batched_proof"`
	ZShiftedOpening openingProof `json:"z_shifted_opening"`
}

type g1Obj struct {
	C string `json:"c"`
	U string `json:"u"`
}

type batchedProof struct {
	H             g1Obj    `json:"h"`
	ClaimedValues []string `json:"claimed_values"`
}

type openingProof struct {
	H            g1Obj  `json:"h"`
	ClaimedValue string `json:"claimed_value"`
}

func g1ObjOf(p bls12381.G1Affine) g1Obj {
	return g1Obj{C: outer.G1Hex(p), U: outer.G1HexUncompressed(p)}
}

// WriteProof serializes the outer PLONK proof + public inputs + the
// linearized-polynomial digest. len(inputs) must equal numInputs (exact, no
// padding). linDigest is the verifier-internal linearized-polynomial commitment
// the on-chain transcript needs in uncompressed form (see the schema).
func WriteProof(w io.Writer, p *bls12381plonk.Proof, innerVKHash fr.Element, inputs []fr.Element, linDigest bls12381.G1Affine, numInputs int) error {
	if len(inputs) != numInputs {
		return fmt.Errorf("inputs length %d != num_inputs %d", len(inputs), numInputs)
	}

	inputsHex := make([]string, len(inputs))
	for i := range inputs {
		inputsHex[i] = outer.FrHex(inputs[i])
	}
	lro := []g1Obj{g1ObjOf(p.LRO[0]), g1ObjOf(p.LRO[1]), g1ObjOf(p.LRO[2])}
	h := []g1Obj{g1ObjOf(p.H[0]), g1ObjOf(p.H[1]), g1ObjOf(p.H[2])}
	bsb := make([]g1Obj, len(p.Bsb22Commitments))
	for i := range p.Bsb22Commitments {
		bsb[i] = g1ObjOf(p.Bsb22Commitments[i])
	}
	claimed := make([]string, len(p.BatchedProof.ClaimedValues))
	for i := range p.BatchedProof.ClaimedValues {
		claimed[i] = outer.FrHex(p.BatchedProof.ClaimedValues[i])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(proofFile{
		Backend:     outer.BackendPlonk,
		NumInputs:   numInputs,
		InnerVKHash: outer.FrHex(innerVKHash),
		Inputs:      inputsHex,
		LRO:         lro,
		Z:           g1ObjOf(p.Z),
		H:           h,
		Bsb22:       bsb,
		LinDigest:   g1ObjOf(linDigest),
		BatchedProof: batchedProof{
			H:             g1ObjOf(p.BatchedProof.H),
			ClaimedValues: claimed,
		},
		ZShiftedOpening: openingProof{
			H:            g1ObjOf(p.ZShiftedOpening.H),
			ClaimedValue: outer.FrHex(p.ZShiftedOpening.ClaimedValue),
		},
	})
}

// ReadProof parses the JSON envelope and reconstructs the gnark PLONK proof
// from the compressed points. Returns proof, inner VK hash, inputs, the
// linearized-poly digest, and the num_inputs value embedded in the file.
func ReadProof(r io.Reader) (*bls12381plonk.Proof, fr.Element, []fr.Element, bls12381.G1Affine, int, error) {
	var f proofFile
	fail := func(err error) (*bls12381plonk.Proof, fr.Element, []fr.Element, bls12381.G1Affine, int, error) {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, 0, err
	}
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return fail(fmt.Errorf("decode %s: %w", outer.FileProof, err))
	}
	if f.Backend != outer.BackendPlonk {
		return fail(fmt.Errorf("backend: got %q, want %q", f.Backend, outer.BackendPlonk))
	}
	if len(f.Inputs) != f.NumInputs {
		return fail(fmt.Errorf("inputs length %d != num_inputs %d", len(f.Inputs), f.NumInputs))
	}
	if len(f.LRO) != 3 {
		return fail(fmt.Errorf("lro: got %d points, want 3", len(f.LRO)))
	}
	if len(f.H) != 3 {
		return fail(fmt.Errorf("h: got %d points, want 3", len(f.H)))
	}

	p := &bls12381plonk.Proof{}
	for i := 0; i < 3; i++ {
		if err := setG1FromObj(&p.LRO[i], fmt.Sprintf("lro[%d]", i), f.LRO[i]); err != nil {
			return fail(err)
		}
		if err := setG1FromObj(&p.H[i], fmt.Sprintf("h[%d]", i), f.H[i]); err != nil {
			return fail(err)
		}
	}
	if err := setG1FromObj(&p.Z, "z", f.Z); err != nil {
		return fail(err)
	}
	p.Bsb22Commitments = make([]bls12381.G1Affine, len(f.Bsb22))
	for i := range f.Bsb22 {
		if err := setG1FromObj(&p.Bsb22Commitments[i], fmt.Sprintf("bsb22_commitments[%d]", i), f.Bsb22[i]); err != nil {
			return fail(err)
		}
	}
	if err := setG1FromObj(&p.BatchedProof.H, "batched_proof.h", f.BatchedProof.H); err != nil {
		return fail(err)
	}
	p.BatchedProof.ClaimedValues = make([]fr.Element, len(f.BatchedProof.ClaimedValues))
	for i, s := range f.BatchedProof.ClaimedValues {
		if err := outer.SetFrFromHex(&p.BatchedProof.ClaimedValues[i], fmt.Sprintf("batched_proof.claimed_values[%d]", i), s); err != nil {
			return fail(err)
		}
	}
	if err := setG1FromObj(&p.ZShiftedOpening.H, "z_shifted_opening.h", f.ZShiftedOpening.H); err != nil {
		return fail(err)
	}
	if err := outer.SetFrFromHex(&p.ZShiftedOpening.ClaimedValue, "z_shifted_opening.claimed_value", f.ZShiftedOpening.ClaimedValue); err != nil {
		return fail(err)
	}

	var linDigest bls12381.G1Affine
	if err := setG1FromObj(&linDigest, "lin_digest", f.LinDigest); err != nil {
		return fail(err)
	}

	var innerVKHash fr.Element
	if err := outer.SetFrFromHex(&innerVKHash, "inner_vk_hash", f.InnerVKHash); err != nil {
		return fail(err)
	}
	inputs := make([]fr.Element, len(f.Inputs))
	for i, s := range f.Inputs {
		if err := outer.SetFrFromHex(&inputs[i], fmt.Sprintf("inputs[%d]", i), s); err != nil {
			return fail(err)
		}
	}
	return p, innerVKHash, inputs, linDigest, f.NumInputs, nil
}

// setG1FromObj parses the compressed encoding and, when the uncompressed form
// is present, validates it decompresses to the same point (the schema's
// integrity rule — the "u" form is a redeemer-side artifact, not trusted).
func setG1FromObj(p *bls12381.G1Affine, field string, o g1Obj) error {
	if err := outer.SetG1FromHex(p, field+".c", o.C); err != nil {
		return err
	}
	if o.U != "" {
		if want := outer.G1HexUncompressed(*p); !strings.EqualFold(o.U, want) {
			return fmt.Errorf("%s.u does not match the compressed point", field)
		}
		// also confirm it is valid uncompressed bytes
		if _, err := hex.DecodeString(o.U); err != nil {
			return fmt.Errorf("%s.u: hex decode: %w", field, err)
		}
	}
	return nil
}
