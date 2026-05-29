// Command gen-testdata regenerates checked-in test fixtures under testdata/
// from upstream inputs in experiments/. Run this when the canonical
// inner-proof schema changes or when refreshing the upstream RISC Zero
// fixture.
//
// Usage (from the zkwrap-gnark module root):
//
//	go run ./cmd/gen-testdata
//	go run ./cmd/gen-testdata --src ../experiments/risc0-hello-world/fixtures --dst ./testdata/canonical-inner/risc0-hello-world
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	src := flag.String("src", "../experiments/risc0-hello-world/fixtures", "RISC Zero fixture directory (source)")
	dst := flag.String("dst", "./testdata/canonical-inner/risc0-hello-world", "canonical inner-proof output directory")
	flag.Parse()

	if err := convertRisc0ToCanonical(*src, *dst); err != nil {
		log.Fatalf("gen-testdata: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote canonical inner-proof artifacts to %s\n", *dst)
}

// convertRisc0ToCanonical reads the RISC Zero fixture format
// (snarkjs vk.json, raw seal.bin, hex public_inputs.json) and writes a
// canonical-inner-proof directory per docs/schemas/canonical-inner-proof.md.
func convertRisc0ToCanonical(srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dstDir, err)
	}

	vk, err := readRisc0VK(filepath.Join(srcDir, "vk.json"))
	if err != nil {
		return fmt.Errorf("read vk.json: %w", err)
	}
	pubInputs, err := readRisc0PublicInputs(filepath.Join(srcDir, "public_inputs.json"))
	if err != nil {
		return fmt.Errorf("read public_inputs.json: %w", err)
	}
	nReal := len(pubInputs)
	if len(vk.G1.K) != nReal+1 {
		return fmt.Errorf("vk.IC=%d does not match n_real+1=%d", len(vk.G1.K), nReal+1)
	}

	// vk.bin
	var vkBuf bytes.Buffer
	writeG1Raw(&vkBuf, vk.G1.Alpha)
	writeG2Raw(&vkBuf, vk.G2.Beta)
	writeG2Raw(&vkBuf, vk.G2.Gamma)
	writeG2Raw(&vkBuf, vk.G2.Delta)
	var nIC [4]byte
	binary.BigEndian.PutUint32(nIC[:], uint32(len(vk.G1.K)))
	vkBuf.Write(nIC[:])
	for _, p := range vk.G1.K {
		writeG1Raw(&vkBuf, p)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "vk.bin"), vkBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write vk.bin: %w", err)
	}

	// proof.bin = seal.bin (RISC Zero seal is already in canonical layout)
	seal, err := os.ReadFile(filepath.Join(srcDir, "seal.bin"))
	if err != nil {
		return fmt.Errorf("read seal.bin: %w", err)
	}
	if len(seal) != 256 {
		return fmt.Errorf("seal.bin: got %d bytes, want 256", len(seal))
	}
	if err := os.WriteFile(filepath.Join(dstDir, "proof.bin"), seal, 0o644); err != nil {
		return fmt.Errorf("write proof.bin: %w", err)
	}

	// public_inputs.bin
	var pubBuf bytes.Buffer
	for _, fe := range pubInputs {
		b := fe.Bytes()
		pubBuf.Write(b[:])
	}
	if err := os.WriteFile(filepath.Join(dstDir, "public_inputs.bin"), pubBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write public_inputs.bin: %w", err)
	}

	// meta.json
	meta, err := json.MarshalIndent(map[string]any{
		"system_id": "risc0-v3",
		"n_real":    nReal,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "meta.json"), meta, 0o644); err != nil {
		return fmt.Errorf("write meta.json: %w", err)
	}
	return nil
}

type risc0VK struct {
	G1 struct {
		Alpha bn254.G1Affine
		K     []bn254.G1Affine
	}
	G2 struct {
		Beta, Gamma, Delta bn254.G2Affine
	}
}

type snarkjsVKRaw struct {
	IC     [][3]string `json:"IC"`
	Alpha1 [3]string   `json:"vk_alpha_1"`
	Beta2  [][2]string `json:"vk_beta_2"`
	Gamma2 [][2]string `json:"vk_gamma_2"`
	Delta2 [][2]string `json:"vk_delta_2"`
}

func readRisc0VK(path string) (*risc0VK, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw snarkjsVKRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	vk := &risc0VK{}
	if err := parseG1Dec(&vk.G1.Alpha, raw.Alpha1[0], raw.Alpha1[1]); err != nil {
		return nil, fmt.Errorf("alpha: %w", err)
	}
	if err := parseG2Dec(&vk.G2.Beta, raw.Beta2); err != nil {
		return nil, fmt.Errorf("beta: %w", err)
	}
	if err := parseG2Dec(&vk.G2.Gamma, raw.Gamma2); err != nil {
		return nil, fmt.Errorf("gamma: %w", err)
	}
	if err := parseG2Dec(&vk.G2.Delta, raw.Delta2); err != nil {
		return nil, fmt.Errorf("delta: %w", err)
	}
	vk.G1.K = make([]bn254.G1Affine, len(raw.IC))
	for i, row := range raw.IC {
		if err := parseG1Dec(&vk.G1.K[i], row[0], row[1]); err != nil {
			return nil, fmt.Errorf("IC[%d]: %w", i, err)
		}
	}
	return vk, nil
}

func parseG1Dec(p *bn254.G1Affine, xDec, yDec string) error {
	var x, y big.Int
	if _, ok := x.SetString(xDec, 10); !ok {
		return fmt.Errorf("bad X %q", xDec)
	}
	if _, ok := y.SetString(yDec, 10); !ok {
		return fmt.Errorf("bad Y %q", yDec)
	}
	p.X.SetBigInt(&x)
	p.Y.SetBigInt(&y)
	return nil
}

// parseG2Dec parses snarkjs G2: coords[0]=[X.A0_dec, X.A1_dec],
// coords[1]=[Y.A0_dec, Y.A1_dec].
func parseG2Dec(p *bn254.G2Affine, coords [][2]string) error {
	if len(coords) < 2 {
		return fmt.Errorf("need 2 rows, got %d", len(coords))
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

func setFp(e *bn254fp.Element, dec string) error {
	var b big.Int
	if _, ok := b.SetString(dec, 10); !ok {
		return fmt.Errorf("bad dec %q", dec)
	}
	e.SetBigInt(&b)
	return nil
}

func readRisc0PublicInputs(path string) ([]fr.Element, error) {
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
	out := make([]fr.Element, len(raw.Inputs))
	for i, s := range raw.Inputs {
		s = strings.TrimPrefix(s, "0x")
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("input[%d]: %w", i, err)
		}
		out[i].SetBytes(b)
	}
	return out, nil
}

func writeG1Raw(w io.Writer, p bn254.G1Affine) {
	x := p.X.Bytes()
	y := p.Y.Bytes()
	w.Write(x[:])
	w.Write(y[:])
}

// writeG2Raw writes the gnark WriteRawTo coordinate order: X.A1 || X.A0 || Y.A1 || Y.A0.
func writeG2Raw(w io.Writer, p bn254.G2Affine) {
	xa1 := p.X.A1.Bytes()
	xa0 := p.X.A0.Bytes()
	ya1 := p.Y.A1.Bytes()
	ya0 := p.Y.A0.Bytes()
	w.Write(xa1[:])
	w.Write(xa0[:])
	w.Write(ya1[:])
	w.Write(ya0[:])
}
