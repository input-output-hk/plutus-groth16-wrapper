package circuit

// This test is a fixture generator, not an assertion test. Run it explicitly to
// (re)produce the authoritative Poseidon2/InnerVKHash test vectors consumed by
// the Rust port in zkwrap-rs/zkwrap-core:
//
//	go test ./internal/circuit -run TestDumpVKHashVectors -dump-vectors
//
// Without the -dump-vectors flag it is a no-op so it never interferes with the
// normal test run. The emitted JSON is the source of truth: the Go side here is
// the reference implementation (gnark-crypto), and the Rust side must match it
// limb-for-limb and bit-for-bit.

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidonbls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"

	"github.com/input-output-hk/plutus-groth16-wrapper/zkwrap-gnark/internal/inner"
)

var dumpVectors = flag.Bool("dump-vectors", false, "regenerate the Rust InnerVKHash test-vector fixture")

const (
	canonicalInnerDir = "../../testdata/canonical-inner/risc0-hello-world"
	fixtureOut        = "../../../zkwrap-rs/zkwrap-core/testdata/inner_vk_hash_vectors.json"
	maxInputs         = 8
)

type vectorFile struct {
	Seed      string     `json:"seed"`
	Params    paramsJSON `json:"params"`
	RoundKeys [][]string `json:"round_keys"` // generation order; hex 32B BE per Fr
	PermKATs  []permKAT  `json:"perm_kats"`
	MDKATs    []mdKAT    `json:"md_kats"`
	VK        vkJSON     `json:"vk"`
}

type paramsJSON struct {
	Width           int `json:"width"`
	NbFullRounds    int `json:"nb_full_rounds"`
	NbPartialRounds int `json:"nb_partial_rounds"`
	SBoxDegree      int `json:"sbox_degree"`
}

type permKAT struct {
	In  []string `json:"in"`  // hex 32B BE per Fr
	Out []string `json:"out"` // hex 32B BE per Fr
}

type mdKAT struct {
	Blocks []string `json:"blocks"` // hex 32B BE per Fr block
	Digest string   `json:"digest"` // hex 32B BE
}

type vkJSON struct {
	MaxInputs   int      `json:"max_inputs"`
	NReal       int      `json:"n_real"`
	VKBytesHex  string   `json:"vk_bytes_hex"` // raw vk.bin: alpha_g1|beta_g2|gamma_g2|delta_g2|n_ic|IC...
	GTLimbs     []string `json:"gt_limbs"`   // 12 BN254 Fp, hex 32B BE; gtEmulatedBasis(e(alpha,beta))
	GammaNeg    []string `json:"gamma_neg"`  // 4 BN254 Fp: X.A0, X.A1, Y.A0, Y.A1
	DeltaNeg    []string `json:"delta_neg"`  // 4 BN254 Fp: same order
	IC          [][]string `json:"ic"`      // each [X, Y] BN254 Fp; len == n_real+1 (unpadded)
	LimbSeqU64  []uint64 `json:"limb_seq_u64"` // full ordered u64 limbs fed to the hasher
	InnerVKHash string   `json:"inner_vk_hash"` // hex 32B BE
}

func frHex(e blsfr.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

func fpHex(e bn254fp.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

func TestDumpVKHashVectors(t *testing.T) {
	if !*dumpVectors {
		t.Skip("pass -dump-vectors to regenerate the Rust fixture")
	}

	out := vectorFile{
		Seed: "Poseidon2-BLS12_381[t=2,rF=6,rP=50,d=5]",
		Params: paramsJSON{
			Width: 2, NbFullRounds: 6, NbPartialRounds: 50, SBoxDegree: 5,
		},
	}

	// Round keys, in generation order.
	params := poseidonbls.GetDefaultParameters()
	for _, rk := range params.RoundKeys {
		row := make([]string, len(rk))
		for i := range rk {
			row[i] = frHex(rk[i])
		}
		out.RoundKeys = append(out.RoundKeys, row)
	}

	// Permutation KATs. Permutation is in-place; clone the input for the record.
	permInputs := [][2]uint64{{0, 0}, {1, 2}, {123456789, 987654321}}
	for _, in := range permInputs {
		var st [2]blsfr.Element
		st[0].SetUint64(in[0])
		st[1].SetUint64(in[1])
		inHex := []string{frHex(st[0]), frHex(st[1])}
		perm := poseidonbls.NewPermutation(2, 6, 50)
		if err := perm.Permutation(st[:]); err != nil {
			t.Fatalf("permutation: %v", err)
		}
		out.PermKATs = append(out.PermKATs, permKAT{
			In:  inHex,
			Out: []string{frHex(st[0]), frHex(st[1])},
		})
	}

	// Also add a KAT with a large near-modulus value to exercise reduction.
	{
		var a, b blsfr.Element
		// arbitrary fixed 31-byte values, guaranteed < r
		_ = a.SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
		_ = b.SetBytes([]byte{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12})
		st := [2]blsfr.Element{a, b}
		inHex := []string{frHex(st[0]), frHex(st[1])}
		perm := poseidonbls.NewPermutation(2, 6, 50)
		if err := perm.Permutation(st[:]); err != nil {
			t.Fatalf("permutation: %v", err)
		}
		out.PermKATs = append(out.PermKATs, permKAT{In: inHex, Out: []string{frHex(st[0]), frHex(st[1])}})
	}

	// MD KATs: hash 1, 2, and 3 blocks of small values.
	for _, blockVals := range [][]uint64{{7}, {7, 8}, {1, 2, 3}} {
		h := poseidonbls.NewMerkleDamgardHasher()
		blocks := make([]string, 0, len(blockVals))
		for _, v := range blockVals {
			var fe blsfr.Element
			fe.SetUint64(v)
			buf := fe.Bytes()
			blocks = append(blocks, hex.EncodeToString(buf[:]))
			if _, err := h.Write(buf[:]); err != nil {
				t.Fatalf("md write: %v", err)
			}
		}
		out.MDKATs = append(out.MDKATs, mdKAT{
			Blocks: blocks,
			Digest: hex.EncodeToString(h.Sum(nil)),
		})
	}

	// Real VK fixture.
	cp, err := inner.Load(canonicalInnerDir)
	if err != nil {
		t.Fatalf("load canonical inner: %v", err)
	}
	vk := cp.VK

	vkBytes, err := os.ReadFile(filepath.Join(canonicalInnerDir, "vk.bin"))
	if err != nil {
		t.Fatalf("read vk.bin: %v", err)
	}
	out.VK.VKBytesHex = hex.EncodeToString(vkBytes)

	e, err := bn254.Pair([]bn254.G1Affine{vk.G1.Alpha}, []bn254.G2Affine{vk.G2.Beta})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	gtLimbs := gtEmulatedBasis(&e)
	for _, fp := range gtLimbs {
		out.VK.GTLimbs = append(out.VK.GTLimbs, fpHex(fp))
	}

	var gammaNeg, deltaNeg bn254.G2Affine
	gammaNeg.Neg(&vk.G2.Gamma)
	deltaNeg.Neg(&vk.G2.Delta)
	out.VK.GammaNeg = []string{fpHex(gammaNeg.X.A0), fpHex(gammaNeg.X.A1), fpHex(gammaNeg.Y.A0), fpHex(gammaNeg.Y.A1)}
	out.VK.DeltaNeg = []string{fpHex(deltaNeg.X.A0), fpHex(deltaNeg.X.A1), fpHex(deltaNeg.Y.A0), fpHex(deltaNeg.Y.A1)}

	for _, k := range vk.G1.K {
		out.VK.IC = append(out.VK.IC, []string{fpHex(k.X), fpHex(k.Y)})
	}
	out.VK.NReal = len(vk.G1.K) - 1
	out.VK.MaxInputs = maxInputs

	// Full ordered u64 limb sequence, mirroring ComputeInnerVKHash exactly.
	appendFp := func(x bn254fp.Element) {
		for _, limb := range fpLimbs64(x) {
			out.VK.LimbSeqU64 = append(out.VK.LimbSeqU64, limb)
		}
	}
	appendG1 := func(p bn254.G1Affine) { appendFp(p.X); appendFp(p.Y) }
	appendG2 := func(p bn254.G2Affine) { appendFp(p.X.A0); appendFp(p.X.A1); appendFp(p.Y.A0); appendFp(p.Y.A1) }
	for _, fp := range gtLimbs {
		appendFp(fp)
	}
	appendG2(gammaNeg)
	appendG2(deltaNeg)
	for i := 0; i < maxInputs+1; i++ {
		if i < len(vk.G1.K) {
			appendG1(vk.G1.K[i])
		} else {
			appendG1(bn254.G1Affine{})
		}
	}

	digest, err := ComputeInnerVKHash(vk, maxInputs)
	if err != nil {
		t.Fatalf("ComputeInnerVKHash: %v", err)
	}
	out.VK.InnerVKHash = frHex(digest)

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fixtureOut), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fixtureOut, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (inner_vk_hash=%s)", fixtureOut, out.VK.InnerVKHash)
}
