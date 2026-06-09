package outer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
)

// File names within a setup-dir bundle (docs/schemas/outer-proof-artifacts.md).
const (
	FilePK      = "outer_pk.bin"
	FileVK      = "outer_vk.json"
	FileCircuit = "circuit.r1cs"
	FileProof   = "outer_proof.json"
)

// WriteSetupBundle writes outer_pk.bin (gnark native binary), outer_vk.json
// (canonical JSON), and circuit.r1cs (gnark native binary) into dir. The
// directory is created if it doesn't exist. Existing files are overwritten
// silently.
func WriteSetupBundle(dir string, pk groth16.ProvingKey, vk *bls12381groth16.VerifyingKey, ccs constraint.ConstraintSystem, maxInputs int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	pkFile, err := os.Create(filepath.Join(dir, FilePK))
	if err != nil {
		return fmt.Errorf("create %s: %w", FilePK, err)
	}
	if _, err := pk.WriteRawTo(pkFile); err != nil {
		_ = pkFile.Close()
		return fmt.Errorf("write %s: %w", FilePK, err)
	}
	if err := pkFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", FilePK, err)
	}

	r1csFile, err := os.Create(filepath.Join(dir, FileCircuit))
	if err != nil {
		return fmt.Errorf("create %s: %w", FileCircuit, err)
	}
	if _, err := ccs.WriteTo(r1csFile); err != nil {
		_ = r1csFile.Close()
		return fmt.Errorf("write %s: %w", FileCircuit, err)
	}
	if err := r1csFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", FileCircuit, err)
	}

	vkFile, err := os.Create(filepath.Join(dir, FileVK))
	if err != nil {
		return fmt.Errorf("create %s: %w", FileVK, err)
	}
	if err := WriteVK(vkFile, vk, maxInputs); err != nil {
		_ = vkFile.Close()
		return fmt.Errorf("write %s: %w", FileVK, err)
	}
	if err := vkFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", FileVK, err)
	}
	return nil
}

// ReadSetupBundle loads the three setup artifacts from dir, returning the
// proving key, the verifying key, the compiled R1CS, and the max_inputs value
// recorded in outer_vk.json.
func ReadSetupBundle(dir string) (groth16.ProvingKey, *bls12381groth16.VerifyingKey, constraint.ConstraintSystem, int, error) {
	vkFile, err := os.Open(filepath.Join(dir, FileVK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", FileVK, err)
	}
	vk, maxInputs, err := ReadVK(vkFile)
	_ = vkFile.Close()
	if err != nil {
		return nil, nil, nil, 0, err
	}

	ccs := groth16.NewCS(ecc.BLS12_381)
	r1csFile, err := os.Open(filepath.Join(dir, FileCircuit))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", FileCircuit, err)
	}
	if _, err := ccs.ReadFrom(r1csFile); err != nil {
		_ = r1csFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", FileCircuit, err)
	}
	_ = r1csFile.Close()

	pk := groth16.NewProvingKey(ecc.BLS12_381)
	pkFile, err := os.Open(filepath.Join(dir, FilePK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", FilePK, err)
	}
	if _, err := pk.ReadFrom(pkFile); err != nil {
		_ = pkFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", FilePK, err)
	}
	_ = pkFile.Close()

	return pk, vk, ccs, maxInputs, nil
}
