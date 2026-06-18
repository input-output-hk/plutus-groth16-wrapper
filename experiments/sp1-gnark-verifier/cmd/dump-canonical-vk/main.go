// Command dump-canonical-vk converts SP1's compressed gnark groth16_vk.bin into
// the canonical uncompressed Bn254Vk layout used by the zkwrap canonical
// inner-proof bundle (docs/schemas/canonical-inner-proof.md):
//
//	alpha_g1 (G1, 64B)  beta_g2 gamma_g2 delta_g2 (G2, 128B each)
//	n_ic (uint32 BE, 4B)  IC[0..n_ic] (G1, 64B each)
//
// gnark's G1Affine.Marshal / G2Affine.Marshal already emit the uncompressed
// big-endian X||Y (G1) and X.A1||X.A0||Y.A1||Y.A0 (G2) order the canonical
// format expects, so we just load the SP1 VK and re-marshal each point.
//
// This is an experimental cross-check / reference. The zkwrap-sp1 crate
// regenerates the same bytes in pure Rust (`cargo run -p zkwrap-sp1 --bin
// gen-canonical-vk --features gen-vk`); the plugin does not depend on this tool.
//
// Usage: go run ./cmd/dump-canonical-vk <sp1-groth16_vk.bin> <out-canonical-vk.bin>
package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"sp1-gnark-verifier/parse"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dump-canonical-vk <in-vk.bin> <out-vk.bin>")
		os.Exit(2)
	}
	vk, err := parse.LoadVK(os.Args[1])
	die("load vk", err)

	var out []byte
	out = append(out, vk.G1.Alpha.Marshal()...) // 64B
	out = append(out, vk.G2.Beta.Marshal()...)  // 128B
	out = append(out, vk.G2.Gamma.Marshal()...) // 128B
	out = append(out, vk.G2.Delta.Marshal()...) // 128B

	nIC := uint32(len(vk.G1.K))
	var nbuf [4]byte
	binary.BigEndian.PutUint32(nbuf[:], nIC)
	out = append(out, nbuf[:]...)
	for i := range vk.G1.K {
		out = append(out, vk.G1.K[i].Marshal()...) // 64B each
	}

	die("write", os.WriteFile(os.Args[2], out, 0o644))
	fmt.Printf("wrote %d bytes (n_ic=%d) to %s\n", len(out), nIC, os.Args[2])
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
