package artifacts

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type outerProofFile struct {
	Backend     string   `json:"backend"`
	MaxInputs   int      `json:"max_inputs"`
	Proof       proofObj `json:"proof"`
	InnerVKHash string   `json:"inner_vk_hash"`
	Inputs      []string `json:"inputs"`
}

type proofObj struct {
	Ar            string   `json:"ar"`
	Bs            string   `json:"bs"`
	Krs           string   `json:"krs"`
	Commitments   []string `json:"commitments"`
	CommitmentPok string   `json:"commitment_pok"`
}

// WriteOuterProof serializes the outer proof + public inputs as the canonical
// JSON envelope. len(inputs) must equal maxInputs (the schema rule that lets
// the Aiken validator hardcode the slot count).
func WriteOuterProof(w io.Writer, p *bls12381groth16.Proof, innerVKHash fr.Element, inputs []fr.Element, maxInputs int) error {
	if len(inputs) != maxInputs {
		return fmt.Errorf("inputs length %d != max_inputs %d", len(inputs), maxInputs)
	}

	commitmentsHex := make([]string, len(p.Commitments))
	for i := range p.Commitments {
		commitmentsHex[i] = g1Hex(p.Commitments[i])
	}

	hashBytes := innerVKHash.Bytes()
	inputsHex := make([]string, len(inputs))
	for i := range inputs {
		b := inputs[i].Bytes()
		inputsHex[i] = hex.EncodeToString(b[:])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(outerProofFile{
		Backend:   OuterBackend,
		MaxInputs: maxInputs,
		Proof: proofObj{
			Ar:            g1Hex(p.Ar),
			Bs:            g2Hex(p.Bs),
			Krs:           g1Hex(p.Krs),
			Commitments:   commitmentsHex,
			CommitmentPok: g1Hex(p.CommitmentPok),
		},
		InnerVKHash: hex.EncodeToString(hashBytes[:]),
		Inputs:      inputsHex,
	})
}

// ReadOuterProof parses the canonical JSON envelope. Returns proof, inner VK
// hash, padded inputs, and the max_inputs value embedded in the file.
func ReadOuterProof(r io.Reader) (*bls12381groth16.Proof, fr.Element, []fr.Element, int, error) {
	var f outerProofFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("decode outer_proof.json: %w", err)
	}
	if f.Backend != OuterBackend {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("backend: got %q, want %q", f.Backend, OuterBackend)
	}
	if len(f.Inputs) != f.MaxInputs {
		return nil, fr.Element{}, nil, 0, fmt.Errorf("inputs length %d != max_inputs %d", len(f.Inputs), f.MaxInputs)
	}

	p := &bls12381groth16.Proof{}
	if err := setG1FromHex(&p.Ar, "proof.ar", f.Proof.Ar); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	if err := setG2FromHex(&p.Bs, "proof.bs", f.Proof.Bs); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	if err := setG1FromHex(&p.Krs, "proof.krs", f.Proof.Krs); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	p.Commitments = make([]bls12381.G1Affine, len(f.Proof.Commitments))
	for i, s := range f.Proof.Commitments {
		if err := setG1FromHex(&p.Commitments[i], fmt.Sprintf("proof.commitments[%d]", i), s); err != nil {
			return nil, fr.Element{}, nil, 0, err
		}
	}
	if err := setG1FromHex(&p.CommitmentPok, "proof.commitment_pok", f.Proof.CommitmentPok); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}

	var hash fr.Element
	if err := setFrFromHex(&hash, "inner_vk_hash", f.InnerVKHash); err != nil {
		return nil, fr.Element{}, nil, 0, err
	}
	inputs := make([]fr.Element, len(f.Inputs))
	for i, s := range f.Inputs {
		if err := setFrFromHex(&inputs[i], fmt.Sprintf("inputs[%d]", i), s); err != nil {
			return nil, fr.Element{}, nil, 0, err
		}
	}
	return p, hash, inputs, f.MaxInputs, nil
}

func setFrFromHex(e *fr.Element, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if len(b) != 32 {
		return fmt.Errorf("%s: got %d bytes, want 32", field, len(b))
	}
	if err := e.SetBytesCanonical(b); err != nil {
		return fmt.Errorf("%s: not a canonical Fr element: %w", field, err)
	}
	return nil
}
