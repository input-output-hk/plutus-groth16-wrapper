package artifacts

import (
	"encoding/hex"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Curve points are serialized as compressed zcash-flavored encoding, lowercase
// hex without 0x prefix or separators (the format Cardano's bls12_381 builtins
// consume directly). See docs/schemas/outer-proof-artifacts.md.

func g1Hex(p bls12381.G1Affine) string {
	b := p.Bytes()
	return hex.EncodeToString(b[:])
}

func g2Hex(p bls12381.G2Affine) string {
	b := p.Bytes()
	return hex.EncodeToString(b[:])
}

func setG1FromHex(p *bls12381.G1Affine, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if _, err := p.SetBytes(b); err != nil {
		return fmt.Errorf("%s: not a valid compressed G1 point: %w", field, err)
	}
	return nil
}

func setG2FromHex(p *bls12381.G2Affine, field, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s: hex decode: %w", field, err)
	}
	if _, err := p.SetBytes(b); err != nil {
		return fmt.Errorf("%s: not a valid compressed G2 point: %w", field, err)
	}
	return nil
}
