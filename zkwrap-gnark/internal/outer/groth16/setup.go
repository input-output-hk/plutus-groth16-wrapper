package groth16

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
)

// WriteSetupBundle writes outer_pk.bin (gnark native binary), outer_vk.json
// (canonical JSON), and circuit.r1cs (gnark native binary) into dir. The
// directory is created if it doesn't exist. Existing files are overwritten
// silently.
func WriteSetupBundle(dir string, pk gnarkgroth16.ProvingKey, vk *bls12381groth16.VerifyingKey, ccs constraint.ConstraintSystem, maxInputs int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	pkFile, err := os.Create(filepath.Join(dir, outer.FilePK))
	if err != nil {
		return fmt.Errorf("create %s: %w", outer.FilePK, err)
	}
	if _, err := pk.WriteRawTo(pkFile); err != nil {
		_ = pkFile.Close()
		return fmt.Errorf("write %s: %w", outer.FilePK, err)
	}
	if err := pkFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outer.FilePK, err)
	}

	r1csFile, err := os.Create(filepath.Join(dir, outer.FileCircuit))
	if err != nil {
		return fmt.Errorf("create %s: %w", outer.FileCircuit, err)
	}
	if _, err := ccs.WriteTo(r1csFile); err != nil {
		_ = r1csFile.Close()
		return fmt.Errorf("write %s: %w", outer.FileCircuit, err)
	}
	if err := r1csFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outer.FileCircuit, err)
	}

	vkFile, err := os.Create(filepath.Join(dir, outer.FileVK))
	if err != nil {
		return fmt.Errorf("create %s: %w", outer.FileVK, err)
	}
	if err := WriteVK(vkFile, vk, maxInputs); err != nil {
		_ = vkFile.Close()
		return fmt.Errorf("write %s: %w", outer.FileVK, err)
	}
	if err := vkFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outer.FileVK, err)
	}
	return nil
}

// ReadSetupBundle loads the three setup artifacts from dir, returning the
// proving key, the verifying key, the compiled R1CS, and the max_inputs value
// recorded in outer_vk.json.
func ReadSetupBundle(dir string) (gnarkgroth16.ProvingKey, *bls12381groth16.VerifyingKey, constraint.ConstraintSystem, int, error) {
	vkFile, err := os.Open(filepath.Join(dir, outer.FileVK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FileVK, err)
	}
	vk, maxInputs, err := ReadVK(vkFile)
	_ = vkFile.Close()
	if err != nil {
		return nil, nil, nil, 0, err
	}

	ccs := gnarkgroth16.NewCS(ecc.BLS12_381)
	r1csFile, err := os.Open(filepath.Join(dir, outer.FileCircuit))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FileCircuit, err)
	}
	if _, err := ccs.ReadFrom(r1csFile); err != nil {
		_ = r1csFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", outer.FileCircuit, err)
	}
	_ = r1csFile.Close()

	pk := gnarkgroth16.NewProvingKey(ecc.BLS12_381)
	pkFile, err := os.Open(filepath.Join(dir, outer.FilePK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FilePK, err)
	}
	if _, err := pk.UnsafeReadFrom(pkFile); err != nil {
		_ = pkFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", outer.FilePK, err)
	}
	_ = pkFile.Close()

	return pk, vk, ccs, maxInputs, nil
}
