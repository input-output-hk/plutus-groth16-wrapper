package outer

import (
	"encoding/hex"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Shared BLS12-381 / Fr hex codecs used by both the groth16 and plonk artifact
// packages. Curve points are serialized as compressed zcash-flavored encoding,
// lowercase hex without 0x prefix or separators (the format Cardano's bls12_381
// builtins consume directly). See docs/schemas/outer-proof-artifacts.md.

// G1Hex returns the 48-byte compressed encoding as hex.
func G1Hex(p bls12381.G1Affine) string {
	b := p.Bytes()
	return hex.EncodeToString(b[:])
}

// G2Hex returns the 96-byte compressed encoding as hex.
func G2Hex(p bls12381.G2Affine) string {
	b := p.Bytes()
	return hex.EncodeToString(b[:])
}

// G1HexUncompressed serializes a G1 point as the 96-byte gnark RawBytes form
// (x_be || y_be, top 3 bits of byte 0 = 0b000 for a finite point).
func G1HexUncompressed(p bls12381.G1Affine) string {
	b := p.RawBytes()
	return hex.EncodeToString(b[:])
}

// FrHex serializes a BLS12-381 Fr element as 32-byte big-endian lowercase hex.
func FrHex(e fr.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

// SetG1FromHex parses a compressed (or uncompressed) G1 point from hex.
func SetG1FromHex(p *bls12381.G1Affine, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if _, err := p.SetBytes(b); err != nil {
		return fmt.Errorf("%s: not a valid compressed G1 point: %w", field, err)
	}
	return nil
}

// SetG2FromHex parses a compressed G2 point from hex.
func SetG2FromHex(p *bls12381.G2Affine, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if _, err := p.SetBytes(b); err != nil {
		return fmt.Errorf("%s: not a valid compressed G2 point: %w", field, err)
	}
	return nil
}

// SetFrFromHex parses a 32-byte big-endian canonical BLS12-381 Fr element.
func SetFrFromHex(e *fr.Element, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if len(b) != 32 {
		return fmt.Errorf("%s: got %d bytes, want 32", field, len(b))
	}
	if err := e.SetBytesCanonical(b); err != nil {
		return fmt.Errorf("%s: not a canonical Fr element: %w", field, err)
	}
	return nil
}
