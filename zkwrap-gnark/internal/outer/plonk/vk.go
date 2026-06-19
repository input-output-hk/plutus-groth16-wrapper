// Package plonk implements the PLONK outer-proof file artifacts produced and
// consumed by the zkwrap-gnark binary, per
// docs/schemas/plonk-outer-proof-artifacts.md.
package plonk

import (
	"encoding/json"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
)

// vkFile is the canonical JSON form of the PLONK outer verifying key.
type vkFile struct {
	Backend                     string   `json:"backend"`
	NumInputs                   int      `json:"num_inputs"`
	Size                        uint64   `json:"size"`
	SizeInv                     string   `json:"size_inv"`
	Generator                   string   `json:"generator"`
	NbPublicVariables           uint64   `json:"nb_public_variables"`
	CosetShift                  string   `json:"coset_shift"`
	Kzg                         kzgVK    `json:"kzg"`
	S                           []string `json:"s"`
	Ql                          string   `json:"ql"`
	Qr                          string   `json:"qr"`
	Qm                          string   `json:"qm"`
	Qo                          string   `json:"qo"`
	Qk                          string   `json:"qk"`
	Qcp                         []string `json:"qcp"`
	CommitmentConstraintIndexes []uint64 `json:"commitment_constraint_indexes"`
}

type kzgVK struct {
	G1   string `json:"g1"`
	G2_0 string `json:"g2_0"`
	G2_1 string `json:"g2_1"`
}

// WriteVK serializes the PLONK outer VK as canonical JSON for the given
// num_inputs (= the inner system's n_real; PLONK does not pad).
func WriteVK(w io.Writer, vk *bls12381plonk.VerifyingKey, numInputs int) error {
	s := make([]string, len(vk.S))
	for i := range vk.S {
		s[i] = outer.G1Hex(vk.S[i])
	}
	qcp := make([]string, len(vk.Qcp))
	for i := range vk.Qcp {
		qcp[i] = outer.G1Hex(vk.Qcp[i])
	}
	cci := make([]uint64, len(vk.CommitmentConstraintIndexes))
	copy(cci, vk.CommitmentConstraintIndexes)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(vkFile{
		Backend:           outer.BackendPlonk,
		NumInputs:         numInputs,
		Size:              vk.Size,
		SizeInv:           outer.FrHex(vk.SizeInv),
		Generator:         outer.FrHex(vk.Generator),
		NbPublicVariables: vk.NbPublicVariables,
		CosetShift:        outer.FrHex(vk.CosetShift),
		Kzg: kzgVK{
			G1:   outer.G1Hex(vk.Kzg.G1),
			G2_0: outer.G2Hex(vk.Kzg.G2[0]),
			G2_1: outer.G2Hex(vk.Kzg.G2[1]),
		},
		S:                           s,
		Ql:                          outer.G1Hex(vk.Ql),
		Qr:                          outer.G1Hex(vk.Qr),
		Qm:                          outer.G1Hex(vk.Qm),
		Qo:                          outer.G1Hex(vk.Qo),
		Qk:                          outer.G1Hex(vk.Qk),
		Qcp:                         qcp,
		CommitmentConstraintIndexes: cci,
	})
}

// ReadVK parses the canonical JSON form and reconstructs the gnark PLONK VK.
// The KZG pairing lines (precomputed at setup, not serialized) are recomputed
// from G2 here so plonk.Verify works on the reconstructed key. Returns the VK
// and the num_inputs value embedded in the file.
func ReadVK(r io.Reader) (*bls12381plonk.VerifyingKey, int, error) {
	var f vkFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, 0, fmt.Errorf("decode %s: %w", outer.FileVK, err)
	}
	if f.Backend != outer.BackendPlonk {
		return nil, 0, fmt.Errorf("backend: got %q, want %q", f.Backend, outer.BackendPlonk)
	}
	if len(f.S) != 3 {
		return nil, 0, fmt.Errorf("s: got %d points, want 3", len(f.S))
	}

	vk := &bls12381plonk.VerifyingKey{}
	vk.Size = f.Size
	vk.NbPublicVariables = f.NbPublicVariables
	if err := outer.SetFrFromHex(&vk.SizeInv, "size_inv", f.SizeInv); err != nil {
		return nil, 0, err
	}
	if err := outer.SetFrFromHex(&vk.Generator, "generator", f.Generator); err != nil {
		return nil, 0, err
	}
	if err := outer.SetFrFromHex(&vk.CosetShift, "coset_shift", f.CosetShift); err != nil {
		return nil, 0, err
	}

	if err := outer.SetG1FromHex(&vk.Kzg.G1, "kzg.g1", f.Kzg.G1); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG2FromHex(&vk.Kzg.G2[0], "kzg.g2_0", f.Kzg.G2_0); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG2FromHex(&vk.Kzg.G2[1], "kzg.g2_1", f.Kzg.G2_1); err != nil {
		return nil, 0, err
	}
	vk.Kzg.Lines[0] = bls12381.PrecomputeLines(vk.Kzg.G2[0])
	vk.Kzg.Lines[1] = bls12381.PrecomputeLines(vk.Kzg.G2[1])

	for i := 0; i < 3; i++ {
		if err := outer.SetG1FromHex(&vk.S[i], fmt.Sprintf("s[%d]", i), f.S[i]); err != nil {
			return nil, 0, err
		}
	}
	if err := outer.SetG1FromHex(&vk.Ql, "ql", f.Ql); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG1FromHex(&vk.Qr, "qr", f.Qr); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG1FromHex(&vk.Qm, "qm", f.Qm); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG1FromHex(&vk.Qo, "qo", f.Qo); err != nil {
		return nil, 0, err
	}
	if err := outer.SetG1FromHex(&vk.Qk, "qk", f.Qk); err != nil {
		return nil, 0, err
	}
	vk.Qcp = make([]bls12381.G1Affine, len(f.Qcp))
	for i, s := range f.Qcp {
		if err := outer.SetG1FromHex(&vk.Qcp[i], fmt.Sprintf("qcp[%d]", i), s); err != nil {
			return nil, 0, err
		}
	}
	vk.CommitmentConstraintIndexes = make([]uint64, len(f.CommitmentConstraintIndexes))
	copy(vk.CommitmentConstraintIndexes, f.CommitmentConstraintIndexes)

	return vk, f.NumInputs, nil
}
