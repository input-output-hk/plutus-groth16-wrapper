package groth16

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
)

type proofFile struct {
	Backend     string   `json:"backend"`
	MaxInputs   int      `json:"max_inputs"`
	Proof       proofObj `json:"proof"`
	InnerVKHash string   `json:"inner_vk_hash"`
	Inputs      []string `json:"inputs"`
}

type proofObj struct {
	Ar                      string   `json:"ar"`
	Bs                      string   `json:"bs"`
	Krs                     string   `json:"krs"`
	Commitments             []string `json:"commitments"`
	CommitmentsUncompressed []string `json:"commitments_uncompressed"`
	CommitmentPok           string   `json:"commitment_pok"`
}

// WriteProof serializes the outer proof + public inputs as the canonical
// JSON envelope. len(inputs) must equal maxInputs (the schema rule that lets
// the Aiken validator hardcode the slot count).
func WriteProof(w io.Writer, p *bls12381groth16.Proof, innerVKHash fr.Element, inputs []fr.Element, maxInputs int) error {
	if len(inputs) != maxInputs {
		return fmt.Errorf("inputs length %d != max_inputs %d", len(inputs), maxInputs)
	}

	commitmentsHex := make([]string, len(p.Commitments))
	commitmentsUncompressedHex := make([]string, len(p.Commitments))
	for i := range p.Commitments {
		commitmentsHex[i] = outer.G1Hex(p.Commitments[i])
		commitmentsUncompressedHex[i] = outer.G1HexUncompressed(p.Commitments[i])
	}

	inputsHex := make([]string, len(inputs))
	for i := range inputs {
		inputsHex[i] = outer.FrHex(inputs[i])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(proofFile{
		Backend:   outer.BackendGroth16,
		MaxInputs: maxInputs,
		Proof: proofObj{
			Ar:                      outer.G1Hex(p.Ar),
			Bs:                      outer.G2Hex(p.Bs),
			Krs:                     outer.G1Hex(p.Krs),
			Commitments:             commitmentsHex,
			CommitmentsUncompressed: commitmentsUncompressedHex,
			CommitmentPok:           outer.G1Hex(p.CommitmentPok),
		},
		InnerVKHash: outer.FrHex(innerVKHash),
		Inputs:      inputsHex,
	})
}

// ReadProof parses the canonical JSON envelope. Returns proof, inner VK
// hash, padded inputs, and the max_inputs value embedded in the file.
func ReadProof(r io.Reader) (*bls12381groth16.Proof, fr.Element, []fr.Element, int, error) {
	var f proofFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("decode outer_proof.json: %w", err)
	}
	if f.Backend != outer.BackendGroth16 {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("backend: got %q, want %q", f.Backend, outer.BackendGroth16)
	}
	if len(f.Inputs) != f.MaxInputs {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("inputs length %d != max_inputs %d", len(f.Inputs), f.MaxInputs)
	}

	p := &bls12381groth16.Proof{}
	if err := outer.SetG1FromHex(&p.Ar, "proof.ar", f.Proof.Ar); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	if err := outer.SetG2FromHex(&p.Bs, "proof.bs", f.Proof.Bs); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	if err := outer.SetG1FromHex(&p.Krs, "proof.krs", f.Proof.Krs); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	p.Commitments = make([]bls12381.G1Affine, len(f.Proof.Commitments))
	for i, s := range f.Proof.Commitments {
		if err := outer.SetG1FromHex(&p.Commitments[i], fmt.Sprintf("proof.commitments[%d]", i), s); err != nil {
			return nil, fr.Element{}, nil, 0, err
		}
	}
	// commitments_uncompressed is a redeemer-side artifact (the exact bytes
	// gnark hashes for commit_fr). It is redundant with the compressed
	// commitment, so when present we validate it matches rather than trust it.
	if n := len(f.Proof.CommitmentsUncompressed); n > 0 {
		if n != len(p.Commitments) {
			return nil, fr.Element{}, nil, 0, fmt.Errorf(
				"proof.commitments_uncompressed length %d != commitments %d", n, len(p.Commitments))
		}
		for i := range p.Commitments {
			if want := outer.G1HexUncompressed(p.Commitments[i]); !strings.EqualFold(f.Proof.CommitmentsUncompressed[i], want) {
				return nil, fr.Element{}, nil, 0, fmt.Errorf(
					"proof.commitments_uncompressed[%d] does not match the compressed commitment", i)
			}
		}
	}
	if err := outer.SetG1FromHex(&p.CommitmentPok, "proof.commitment_pok", f.Proof.CommitmentPok); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}

	var hash fr.Element
	if err := outer.SetFrFromHex(&hash, "inner_vk_hash", f.InnerVKHash); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	inputs := make([]fr.Element, len(f.Inputs))
	for i, s := range f.Inputs {
		if err := outer.SetFrFromHex(&inputs[i], fmt.Sprintf("inputs[%d]", i), s); err != nil {
			return nil, fr.Element{}, nil, 0, err
		}
	}
	return p, hash, inputs, f.MaxInputs, nil
}
