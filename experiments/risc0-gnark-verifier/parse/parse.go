package parse

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
)

type vkRaw struct {
	IC     [][3]string `json:"IC"`
	Alpha1 [3]string   `json:"vk_alpha_1"`
	Beta2  [][2]string `json:"vk_beta_2"`
	Gamma2 [][2]string `json:"vk_gamma_2"`
	Delta2 [][2]string `json:"vk_delta_2"`
}

func LoadVK(path string) (*bn254groth16.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw vkRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	vk := &bn254groth16.VerifyingKey{}

	if err := parseG1Dec(&vk.G1.Alpha, raw.Alpha1[0], raw.Alpha1[1]); err != nil {
		return nil, fmt.Errorf("vk_alpha_1: %w", err)
	}
	// snarkjs G2 format: [[A0_dec, A1_dec], [A0_dec, A1_dec], ["1","0"]]
	if err := parseG2Dec(&vk.G2.Beta, raw.Beta2); err != nil {
		return nil, fmt.Errorf("vk_beta_2: %w", err)
	}
	if err := parseG2Dec(&vk.G2.Gamma, raw.Gamma2); err != nil {
		return nil, fmt.Errorf("vk_gamma_2: %w", err)
	}
	if err := parseG2Dec(&vk.G2.Delta, raw.Delta2); err != nil {
		return nil, fmt.Errorf("vk_delta_2: %w", err)
	}

	vk.G1.K = make([]bn254.G1Affine, len(raw.IC))
	for i, ic := range raw.IC {
		if err := parseG1Dec(&vk.G1.K[i], ic[0], ic[1]); err != nil {
			return nil, fmt.Errorf("IC[%d]: %w", i, err)
		}
	}

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("precompute: %w", err)
	}
	return vk, nil
}

func LoadSeal(path string) (*bn254groth16.Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != 256 {
		return nil, fmt.Errorf("expected 256 bytes, got %d", len(data))
	}

	proof := &bn254groth16.Proof{}

	// A (G1): bytes[0:64]
	proof.Ar.X.SetBytes(data[0:32])
	proof.Ar.Y.SetBytes(data[32:64])

	// B (G2): bytes[64:192] — seal.bin layout is [X.A1, X.A0, Y.A1, Y.A0] (A1 first)
	proof.Bs.X.A1.SetBytes(data[64:96])
	proof.Bs.X.A0.SetBytes(data[96:128])
	proof.Bs.Y.A1.SetBytes(data[128:160])
	proof.Bs.Y.A0.SetBytes(data[160:192])

	// C (G1): bytes[192:256]
	proof.Krs.X.SetBytes(data[192:224])
	proof.Krs.Y.SetBytes(data[224:256])

	return proof, nil
}

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
		stripped := s
		if len(s) >= 2 && s[:2] == "0x" {
			stripped = s[2:]
		}
		b, err := hex.DecodeString(stripped)
		if err != nil {
			return nil, fmt.Errorf("input[%d]: %w", i, err)
		}
		result[i].SetBytes(b)
	}
	return result, nil
}

func parseG1Dec(p *bn254.G1Affine, xDec, yDec string) error {
	var x, y big.Int
	if _, ok := x.SetString(xDec, 10); !ok {
		return fmt.Errorf("bad X: %q", xDec)
	}
	if _, ok := y.SetString(yDec, 10); !ok {
		return fmt.Errorf("bad Y: %q", yDec)
	}
	p.X.SetBigInt(&x)
	p.Y.SetBigInt(&y)
	return nil
}

// parseG2Dec parses a snarkjs G2 coord pair: coords[i] = [A0_decimal, A1_decimal].
func parseG2Dec(p *bn254.G2Affine, coords [][2]string) error {
	if len(coords) < 2 {
		return fmt.Errorf("need 2 coord rows, got %d", len(coords))
	}
	if err := setFp(&p.X.A0, coords[0][0]); err != nil {
		return fmt.Errorf("X.A0: %w", err)
	}
	if err := setFp(&p.X.A1, coords[0][1]); err != nil {
		return fmt.Errorf("X.A1: %w", err)
	}
	if err := setFp(&p.Y.A0, coords[1][0]); err != nil {
		return fmt.Errorf("Y.A0: %w", err)
	}
	if err := setFp(&p.Y.A1, coords[1][1]); err != nil {
		return fmt.Errorf("Y.A1: %w", err)
	}
	return nil
}

func setFp(e *fp.Element, dec string) error {
	var b big.Int
	if _, ok := b.SetString(dec, 10); !ok {
		return fmt.Errorf("bad decimal: %q", dec)
	}
	e.SetBigInt(&b)
	return nil
}
