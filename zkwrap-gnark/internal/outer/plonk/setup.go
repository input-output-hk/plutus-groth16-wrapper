package plonk

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/constraint"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/outer"
)

// WriteSetupBundle writes outer_pk.bin (gnark native PLONK proving key, which
// embeds the VK), outer_vk.json (canonical PLONK VK JSON), and circuit.r1cs
// (gnark native SparseR1CS) into dir. File names match the Groth16 bundle; the
// backend recorded in outer_vk.json disambiguates them.
func WriteSetupBundle(dir string, pk gnarkplonk.ProvingKey, vk *bls12381plonk.VerifyingKey, ccs constraint.ConstraintSystem, numInputs int) error {
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

	csFile, err := os.Create(filepath.Join(dir, outer.FileCircuit))
	if err != nil {
		return fmt.Errorf("create %s: %w", outer.FileCircuit, err)
	}
	if _, err := ccs.WriteTo(csFile); err != nil {
		_ = csFile.Close()
		return fmt.Errorf("write %s: %w", outer.FileCircuit, err)
	}
	if err := csFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outer.FileCircuit, err)
	}

	vkFile, err := os.Create(filepath.Join(dir, outer.FileVK))
	if err != nil {
		return fmt.Errorf("create %s: %w", outer.FileVK, err)
	}
	if err := WriteVK(vkFile, vk, numInputs); err != nil {
		_ = vkFile.Close()
		return fmt.Errorf("write %s: %w", outer.FileVK, err)
	}
	if err := vkFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outer.FileVK, err)
	}
	return nil
}

// ReadSetupBundle loads the PLONK setup artifacts from dir. The returned VK is
// the one embedded in the proving key (KZG pairing lines fully populated
// natively), which prove uses to compute the linearized-poly digest; num_inputs
// is read from outer_vk.json.
func ReadSetupBundle(dir string) (gnarkplonk.ProvingKey, *bls12381plonk.VerifyingKey, constraint.ConstraintSystem, int, error) {
	vkFile, err := os.Open(filepath.Join(dir, outer.FileVK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FileVK, err)
	}
	_, numInputs, err := ReadVK(vkFile)
	_ = vkFile.Close()
	if err != nil {
		return nil, nil, nil, 0, err
	}

	ccs := gnarkplonk.NewCS(ecc.BLS12_381)
	csFile, err := os.Open(filepath.Join(dir, outer.FileCircuit))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FileCircuit, err)
	}
	if _, err := ccs.ReadFrom(csFile); err != nil {
		_ = csFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", outer.FileCircuit, err)
	}
	_ = csFile.Close()

	pk := gnarkplonk.NewProvingKey(ecc.BLS12_381)
	pkFile, err := os.Open(filepath.Join(dir, outer.FilePK))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("open %s: %w", outer.FilePK, err)
	}
	if _, err := pk.UnsafeReadFrom(pkFile); err != nil {
		_ = pkFile.Close()
		return nil, nil, nil, 0, fmt.Errorf("read %s: %w", outer.FilePK, err)
	}
	_ = pkFile.Close()

	vk, ok := pk.VerifyingKey().(*bls12381plonk.VerifyingKey)
	if !ok {
		return nil, nil, nil, 0, fmt.Errorf("proving key embeds VK of unexpected type %T", pk.VerifyingKey())
	}

	return pk, vk, ccs, numInputs, nil
}
