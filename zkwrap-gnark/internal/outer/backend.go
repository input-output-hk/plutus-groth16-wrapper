package outer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Outer-backend identifiers, recorded in the `backend` field of every artifact
// (outer_vk.json, outer_proof.json). See docs/schemas/outer-proof-artifacts.md
// (Groth16) and docs/schemas/plonk-outer-proof-artifacts.md (PLONK).
const (
	BackendGroth16 = "gnark-groth16-bls12381"
	BackendPlonk   = "gnark-plonk-bls12381"
)

// File names within a setup-dir bundle, shared by both backends. The file
// contents differ per backend (e.g. circuit.r1cs holds an R1CS for Groth16, a
// SparseR1CS for PLONK); the backend recorded in outer_vk.json disambiguates.
const (
	FilePK      = "outer_pk.bin"
	FileVK      = "outer_vk.json"
	FileCircuit = "circuit.r1cs"
	FileProof   = "outer_proof.json"
)

// PeekBackend reads only the `backend` field of a setup bundle's outer_vk.json,
// so prove/verify can dispatch on the backend recorded at setup time without
// committing to a concrete VK type first.
func PeekBackend(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileVK))
	if err != nil {
		return "", fmt.Errorf("open %s: %w", FileVK, err)
	}
	var hdr struct {
		Backend string `json:"backend"`
	}
	if err := json.Unmarshal(b, &hdr); err != nil {
		return "", fmt.Errorf("decode %s: %w", FileVK, err)
	}
	if hdr.Backend == "" {
		return "", fmt.Errorf("%s: missing backend field", FileVK)
	}
	return hdr.Backend, nil
}
