// Package artifacts implements the file artifacts produced and consumed by
// the zkwrap-gnark binary, per docs/schemas/outer-proof-artifacts.md.
package artifacts

import (
	"encoding/json"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

const OuterBackend = "gnark-groth16-bls12381"

type outerVKFile struct {
	Backend                      string             `json:"backend"`
	MaxInputs                    int                `json:"max_inputs"`
	AlphaG1                      string             `json:"alpha_g1"`
	BetaG2                       string             `json:"beta_g2"`
	GammaG2                      string             `json:"gamma_g2"`
	DeltaG2                      string             `json:"delta_g2"`
	IC                           []string           `json:"ic"`
	CommitmentKeys               []commitmentKeyObj `json:"commitment_keys"`
	PublicAndCommitmentCommitted [][]int            `json:"public_and_commitment_committed"`
}

type commitmentKeyObj struct {
	G         string `json:"g"`
	GSigmaNeg string `json:"g_sigma_neg"`
}

// WriteOuterVK serializes the outer VK as the canonical JSON form for the
// max_inputs value embedded into the trusted setup. The IC array length is not
// enforced here (it is set by gnark setup); callers must pass the same
// max_inputs that was used at setup time.
func WriteOuterVK(w io.Writer, vk *bls12381groth16.VerifyingKey, maxInputs int) error {
	ic := make([]string, len(vk.G1.K))
	for i := range vk.G1.K {
		ic[i] = g1Hex(vk.G1.K[i])
	}

	ckJSON := make([]commitmentKeyObj, len(vk.CommitmentKeys))
	for i, ck := range vk.CommitmentKeys {
		ckJSON[i] = commitmentKeyObj{
			G:         g2Hex(ck.G),
			GSigmaNeg: g2Hex(ck.GSigmaNeg),
		}
	}

	pacc := vk.PublicAndCommitmentCommitted
	if pacc == nil {
		pacc = [][]int{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(outerVKFile{
		Backend:                      OuterBackend,
		MaxInputs:                    maxInputs,
		AlphaG1:                      g1Hex(vk.G1.Alpha),
		BetaG2:                       g2Hex(vk.G2.Beta),
		GammaG2:                      g2Hex(vk.G2.Gamma),
		DeltaG2:                      g2Hex(vk.G2.Delta),
		IC:                           ic,
		CommitmentKeys:               ckJSON,
		PublicAndCommitmentCommitted: pacc,
	})
}

// ReadOuterVK parses the canonical JSON form and reconstructs the gnark VK.
// Returns the VK and the max_inputs value embedded in the file.
func ReadOuterVK(r io.Reader) (*bls12381groth16.VerifyingKey, int, error) {
	var f outerVKFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, 0, fmt.Errorf("decode outer_vk.json: %w", err)
	}
	if f.Backend != OuterBackend {
		return nil, 0, fmt.Errorf("backend: got %q, want %q", f.Backend, OuterBackend)
	}

	vk := &bls12381groth16.VerifyingKey{}
	if err := setG1FromHex(&vk.G1.Alpha, "alpha_g1", f.AlphaG1); err != nil {
		return nil, 0, err
	}
	if err := setG2FromHex(&vk.G2.Beta, "beta_g2", f.BetaG2); err != nil {
		return nil, 0, err
	}
	if err := setG2FromHex(&vk.G2.Gamma, "gamma_g2", f.GammaG2); err != nil {
		return nil, 0, err
	}
	if err := setG2FromHex(&vk.G2.Delta, "delta_g2", f.DeltaG2); err != nil {
		return nil, 0, err
	}
	vk.G1.K = make([]bls12381.G1Affine, len(f.IC))
	for i, s := range f.IC {
		if err := setG1FromHex(&vk.G1.K[i], fmt.Sprintf("ic[%d]", i), s); err != nil {
			return nil, 0, err
		}
	}

	vk.CommitmentKeys = make([]pedersen.VerifyingKey, len(f.CommitmentKeys))
	for i, ck := range f.CommitmentKeys {
		if err := setG2FromHex(&vk.CommitmentKeys[i].G, fmt.Sprintf("commitment_keys[%d].g", i), ck.G); err != nil {
			return nil, 0, err
		}
		if err := setG2FromHex(&vk.CommitmentKeys[i].GSigmaNeg, fmt.Sprintf("commitment_keys[%d].g_sigma_neg", i), ck.GSigmaNeg); err != nil {
			return nil, 0, err
		}
	}

	vk.PublicAndCommitmentCommitted = f.PublicAndCommitmentCommitted
	if vk.PublicAndCommitmentCommitted == nil {
		vk.PublicAndCommitmentCommitted = [][]int{}
	}

	if err := vk.Precompute(); err != nil {
		return nil, 0, fmt.Errorf("precompute outer VK: %w", err)
	}
	return vk, f.MaxInputs, nil
}
