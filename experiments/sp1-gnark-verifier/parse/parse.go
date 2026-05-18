package parse

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
)

// LoadVK reads the SP1 groth16_vk.bin file.
//
// SP1 stores VK in gnark's binary WriteTo format with compressed BN254 points:
//
//	[0:32]   G1.Alpha   (compressed G1, 32 bytes)
//	[32:64]  G1.Beta    (compressed G1, 32 bytes — skip, not used in verification)
//	[64:128] G2.Beta    (compressed G2, 64 bytes)
//	[128:192] G2.Gamma  (compressed G2, 64 bytes)
//	[192:224] G1.Delta  (compressed G1, 32 bytes — skip, not used in verification)
//	[224:288] G2.Delta  (compressed G2, 64 bytes)
//	[288:292] num_k     (uint32 big-endian)
//	[292+]   G1.K[i]   (compressed G1, 32 bytes each)
func LoadVK(path string) (*bn254groth16.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 292 {
		return nil, fmt.Errorf("vk.bin too short: %d bytes", len(data))
	}

	vk := new(bn254groth16.VerifyingKey)

	if _, err := vk.G1.Alpha.SetBytes(data[0:32]); err != nil {
		return nil, fmt.Errorf("G1.Alpha: %w", err)
	}
	// data[32:64] = G1.Beta — unused in Groth16 verification, skip
	if _, err := vk.G2.Beta.SetBytes(data[64:128]); err != nil {
		return nil, fmt.Errorf("G2.Beta: %w", err)
	}
	if _, err := vk.G2.Gamma.SetBytes(data[128:192]); err != nil {
		return nil, fmt.Errorf("G2.Gamma: %w", err)
	}
	// data[192:224] = G1.Delta — unused in Groth16 verification, skip
	if _, err := vk.G2.Delta.SetBytes(data[224:288]); err != nil {
		return nil, fmt.Errorf("G2.Delta: %w", err)
	}

	numK := int(binary.BigEndian.Uint32(data[288:292]))
	minLen := 292 + numK*32
	if len(data) < minLen {
		return nil, fmt.Errorf("vk.bin too short for %d K points: have %d, need %d", numK, len(data), minLen)
	}
	vk.G1.K = make([]bn254.G1Affine, numK)
	for i := 0; i < numK; i++ {
		off := 292 + i*32
		if _, err := vk.G1.K[i].SetBytes(data[off : off+32]); err != nil {
			return nil, fmt.Errorf("G1.K[%d]: %w", i, err)
		}
	}

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("precompute: %w", err)
	}
	return vk, nil
}

// LoadSeal reads seal.bin — 324 bytes of a gnark BN254 Groth16 proof in SP1's WriteRawTo format.
//
// SP1's gnark fork always writes CommitmentPok even when there are no commitments:
//
//	[0:64]    Ar            G1 uncompressed (X big-endian 32B | Y big-endian 32B)
//	[64:192]  Bs            G2 uncompressed (X.A1 32B | X.A0 32B | Y.A1 32B | Y.A0 32B)
//	[192:256] Krs           G1 uncompressed (X big-endian 32B | Y big-endian 32B)
//	[256:260] num_commitments  uint32 big-endian (= 0 for SP1)
//	[260:324] CommitmentPok G1 uncompressed (X big-endian 32B | Y big-endian 32B)
func LoadSeal(path string) (*bn254groth16.Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != 324 {
		return nil, fmt.Errorf("expected 324 bytes, got %d", len(data))
	}

	proof := &bn254groth16.Proof{}

	// Ar (G1)
	proof.Ar.X.SetBytes(data[0:32])
	proof.Ar.Y.SetBytes(data[32:64])

	// Bs (G2) — layout: [X.A1 | X.A0 | Y.A1 | Y.A0]
	proof.Bs.X.A1.SetBytes(data[64:96])
	proof.Bs.X.A0.SetBytes(data[96:128])
	proof.Bs.Y.A1.SetBytes(data[128:160])
	proof.Bs.Y.A0.SetBytes(data[160:192])

	// Krs (G1)
	proof.Krs.X.SetBytes(data[192:224])
	proof.Krs.Y.SetBytes(data[224:256])

	// [256:260] num_commitments (uint32 BE) — expected 0 for SP1; no Commitments slice to fill
	// CommitmentPok (G1)
	proof.CommitmentPok.X.SetBytes(data[260:292])
	proof.CommitmentPok.Y.SetBytes(data[292:324])

	return proof, nil
}

// LoadPublicInputs reads public_inputs.json — two decimal BN254 Fr elements.
func LoadPublicInputs(path string) (fr.Vector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Inputs []string `json:"inputs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	result := make(fr.Vector, len(raw.Inputs))
	for i, s := range raw.Inputs {
		var b big.Int
		if _, ok := b.SetString(s, 10); !ok {
			return nil, fmt.Errorf("input[%d]: invalid decimal: %q", i, s)
		}
		result[i].SetBigInt(&b)
	}
	return result, nil
}
