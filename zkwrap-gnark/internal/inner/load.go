// Package inner loads the canonical inner proof directory format defined
// in docs/schemas/canonical-inner-proof.md. The format is the contract
// between Rust plugins and the Go prover; this package is the Go side.
package inner

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
)

const (
	vkHeaderSize = 64 + 128*3 + 4 // alpha (G1) + 3×G2 + nIC uint32
	proofSize    = 256
	g1Size       = 64
	g2Size       = 128
	frSize       = 32
)

// CanonicalProof is the loaded form of a canonical inner proof directory.
// NReal is implicit as len(PublicInputs).
type CanonicalProof struct {
	VK           *bn254groth16.VerifyingKey
	Proof        *bn254groth16.Proof
	PublicInputs []fr.Element
	SystemID     string
}

// NReal returns the number of real inner public inputs (no padding).
func (c *CanonicalProof) NReal() int { return len(c.PublicInputs) }

type metaFile struct {
	SystemID string `json:"system_id"`
	NReal    int    `json:"n_real"`
}

// Load reads the four files from dir and returns a CanonicalProof. It enforces
// the validation rules in docs/schemas/canonical-inner-proof.md:
//
//   - meta.json's n_real matches the public_inputs.bin element count
//   - vk.bin's n_ic equals n_real + 1
//   - all curve points are valid (gnark SetBytes rejects off-curve)
//   - all Fr elements are canonical (< r)
func Load(dir string) (*CanonicalProof, error) {
	meta, err := loadMeta(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}

	publicInputs, err := loadPublicInputs(filepath.Join(dir, "public_inputs.bin"))
	if err != nil {
		return nil, err
	}
	if len(publicInputs) != meta.NReal {
		return nil, fmt.Errorf("public_inputs.bin: got %d elements, meta.n_real says %d", len(publicInputs), meta.NReal)
	}

	vk, err := loadVK(filepath.Join(dir, "vk.bin"), meta.NReal)
	if err != nil {
		return nil, err
	}

	proof, err := loadProof(filepath.Join(dir, "proof.bin"))
	if err != nil {
		return nil, err
	}

	return &CanonicalProof{
		VK:           vk,
		Proof:        proof,
		PublicInputs: publicInputs,
		SystemID:     meta.SystemID,
	}, nil
}

func loadMeta(path string) (metaFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return metaFile{}, fmt.Errorf("meta.json: %w", err)
	}
	var m metaFile
	if err := json.Unmarshal(data, &m); err != nil {
		return metaFile{}, fmt.Errorf("meta.json: %w", err)
	}
	if m.SystemID == "" {
		return metaFile{}, fmt.Errorf("meta.json: system_id is empty")
	}
	if m.NReal < 0 {
		return metaFile{}, fmt.Errorf("meta.json: n_real %d is negative", m.NReal)
	}
	return m, nil
}

func loadPublicInputs(path string) ([]fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("public_inputs.bin: %w", err)
	}
	if len(data)%frSize != 0 {
		return nil, fmt.Errorf("public_inputs.bin: %d bytes is not a multiple of %d", len(data), frSize)
	}
	n := len(data) / frSize
	out := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		if err := out[i].SetBytesCanonical(data[i*frSize : (i+1)*frSize]); err != nil {
			return nil, fmt.Errorf("public_inputs.bin[%d]: %w", i, err)
		}
	}
	return out, nil
}

func loadVK(path string, nReal int) (*bn254groth16.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vk.bin: %w", err)
	}
	if len(data) < vkHeaderSize {
		return nil, fmt.Errorf("vk.bin: got %d bytes, less than header size %d", len(data), vkHeaderSize)
	}

	nIC := binary.BigEndian.Uint32(data[vkHeaderSize-4 : vkHeaderSize])
	if int(nIC) != nReal+1 {
		return nil, fmt.Errorf("vk.bin: n_ic=%d, but meta.n_real+1=%d", nIC, nReal+1)
	}
	wantSize := vkHeaderSize + int(nIC)*g1Size
	if len(data) != wantSize {
		return nil, fmt.Errorf("vk.bin: got %d bytes, want %d (header + n_ic×64)", len(data), wantSize)
	}

	vk := &bn254groth16.VerifyingKey{}
	off := 0
	if err := setG1(&vk.G1.Alpha, data[off:off+g1Size], "alpha_g1"); err != nil {
		return nil, err
	}
	off += g1Size
	if err := setG2(&vk.G2.Beta, data[off:off+g2Size], "beta_g2"); err != nil {
		return nil, err
	}
	off += g2Size
	if err := setG2(&vk.G2.Gamma, data[off:off+g2Size], "gamma_g2"); err != nil {
		return nil, err
	}
	off += g2Size
	if err := setG2(&vk.G2.Delta, data[off:off+g2Size], "delta_g2"); err != nil {
		return nil, err
	}
	off += g2Size + 4

	vk.G1.K = make([]bn254.G1Affine, nIC)
	for i := uint32(0); i < nIC; i++ {
		if err := setG1(&vk.G1.K[i], data[off:off+g1Size], fmt.Sprintf("IC[%d]", i)); err != nil {
			return nil, err
		}
		off += g1Size
	}

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("vk.bin: precompute: %w", err)
	}
	return vk, nil
}

func loadProof(path string) (*bn254groth16.Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("proof.bin: %w", err)
	}
	if len(data) != proofSize {
		return nil, fmt.Errorf("proof.bin: got %d bytes, want %d", len(data), proofSize)
	}
	p := &bn254groth16.Proof{}
	if err := setG1(&p.Ar, data[0:64], "proof.ar"); err != nil {
		return nil, err
	}
	if err := setG2(&p.Bs, data[64:192], "proof.bs"); err != nil {
		return nil, err
	}
	if err := setG1(&p.Krs, data[192:256], "proof.krs"); err != nil {
		return nil, err
	}
	return p, nil
}

// setG1 reads a 64-byte uncompressed G1 affine point (X || Y, big-endian Fq each).
// gnark's SetBytes auto-detects compression by the high flag bits; uncompressed
// raw bytes are accepted as long as the resulting point is on-curve.
func setG1(p *bn254.G1Affine, data []byte, field string) error {
	if len(data) != g1Size {
		return fmt.Errorf("%s: got %d bytes, want %d", field, len(data), g1Size)
	}
	if _, err := p.SetBytes(data); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

// setG2 reads a 128-byte uncompressed G2 affine point in gnark WriteRawTo order:
// X.A1 || X.A0 || Y.A1 || Y.A0.
func setG2(p *bn254.G2Affine, data []byte, field string) error {
	if len(data) != g2Size {
		return fmt.Errorf("%s: got %d bytes, want %d", field, len(data), g2Size)
	}
	if _, err := p.SetBytes(data); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}
