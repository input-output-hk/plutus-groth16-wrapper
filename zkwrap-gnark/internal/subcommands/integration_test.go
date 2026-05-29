package subcommands

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// fixtureDir is the RISC Zero Phase-1 fixture relative to this package.
// The integration test converts it on the fly to canonical inner-proof
// format and exercises the whole zkwrap-gnark CLI against it.
const fixtureDir = "../../../experiments/risc0-hello-world/fixtures"

// TestIntegration_SetupProveVerify is the end-to-end smoke check that the
// binary is a working lift of the experiment prototype. It runs the full
// unsafe-setup → prove → verify cycle against a real RISC Zero fixture and
// also exercises the --out overwrite rule by rerunning prove twice.
//
// The wrapper-circuit trusted setup is slow (≈30s+ on workstation hardware),
// so this test is skipped under `go test -short`.
func TestIntegration_SetupProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: trusted setup is slow; skipped in -short mode")
	}
	if _, err := os.Stat(filepath.Join(fixtureDir, "vk.json")); err != nil {
		t.Skipf("fixture not present at %s: %v", fixtureDir, err)
	}

	// MAX_INPUTS = 5 is the minimum that fits the RISC Zero fixture's n_real=5;
	// minimising it keeps the setup cost bounded.
	const maxInputs = 5

	root := t.TempDir()
	canonicalDir := filepath.Join(root, "canonical")
	setupDir := filepath.Join(root, "setup")
	proofPath := filepath.Join(root, "outer_proof.json")

	convertRisc0ToCanonical(t, fixtureDir, canonicalDir)

	// unsafe-setup
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"unsafe-setup",
			"--max-inputs", "5",
			"--out", setupDir,
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("unsafe-setup: exit %d\nstderr: %s", code, stderr.String())
		}
		assertFileNonEmpty(t, filepath.Join(setupDir, "outer_pk.bin"))
		assertFileNonEmpty(t, filepath.Join(setupDir, "outer_vk.json"))
		assertFileNonEmpty(t, filepath.Join(setupDir, "circuit.r1cs"))
	}

	// prove (first run)
	proveOnce := func() {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"prove",
			"--inner", canonicalDir,
			"--setup", setupDir,
			"--out", proofPath,
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("prove: exit %d\nstderr: %s", code, stderr.String())
		}
	}
	proveOnce()
	firstProof := mustRead(t, proofPath)

	// --out overwrite: rerun prove on the same path; the file must be replaced
	// in-place (not refused), and the second proof must still parse.
	proveOnce()
	secondProof := mustRead(t, proofPath)
	if len(secondProof) == 0 {
		t.Fatalf("second prove: outer_proof.json is empty")
	}
	if !json.Valid(secondProof) {
		t.Errorf("second prove: outer_proof.json is not valid JSON")
	}
	// Both proofs verify; they need not be byte-equal (gnark uses fresh
	// randomness per Prove call), but they must both refer to the same VK
	// hash and the same inputs.
	if got, want := topLevelString(t, firstProof, "inner_vk_hash"), topLevelString(t, secondProof, "inner_vk_hash"); got != want {
		t.Errorf("inner_vk_hash diverges across runs: %q vs %q", got, want)
	}

	// verify
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"verify",
			"--proof", proofPath,
			"--setup", setupDir,
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("verify: exit %d\nstderr: %s", code, stderr.String())
		}
	}
}

func assertFileNonEmpty(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Errorf("%s is empty", path)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func topLevelString(t *testing.T, data []byte, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("key %s is not a string", key)
	}
	return s
}

// convertRisc0ToCanonical reads the RISC Zero fixture format
// (snarkjs vk.json, raw seal.bin, hex public_inputs.json) and writes a
// canonical-inner-proof directory per docs/schemas/canonical-inner-proof.md.
func convertRisc0ToCanonical(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}

	vk := readRisc0VK(t, filepath.Join(srcDir, "vk.json"))
	pubInputs := readRisc0PublicInputs(t, filepath.Join(srcDir, "public_inputs.json"))
	nReal := len(pubInputs)
	if len(vk.G1.K) != nReal+1 {
		t.Fatalf("vk.IC=%d does not match n_real+1=%d", len(vk.G1.K), nReal+1)
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
		t.Fatal(err)
	}

	// proof.bin = seal.bin (RISC Zero seal is already in canonical layout)
	seal := mustRead(t, filepath.Join(srcDir, "seal.bin"))
	if len(seal) != 256 {
		t.Fatalf("seal.bin: got %d bytes, want 256", len(seal))
	}
	if err := os.WriteFile(filepath.Join(dstDir, "proof.bin"), seal, 0o644); err != nil {
		t.Fatal(err)
	}

	// public_inputs.bin
	var pubBuf bytes.Buffer
	for _, fe := range pubInputs {
		b := fe.Bytes()
		pubBuf.Write(b[:])
	}
	if err := os.WriteFile(filepath.Join(dstDir, "public_inputs.bin"), pubBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	// meta.json
	meta, _ := json.Marshal(map[string]any{
		"system_id": "risc0-v3",
		"n_real":    nReal,
	})
	if err := os.WriteFile(filepath.Join(dstDir, "meta.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
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

func readRisc0VK(t *testing.T, path string) *risc0VK {
	t.Helper()
	data := mustRead(t, path)
	var raw snarkjsVKRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("vk.json: %v", err)
	}

	vk := &risc0VK{}
	parseG1Dec(t, &vk.G1.Alpha, raw.Alpha1[0], raw.Alpha1[1])
	parseG2Dec(t, &vk.G2.Beta, raw.Beta2)
	parseG2Dec(t, &vk.G2.Gamma, raw.Gamma2)
	parseG2Dec(t, &vk.G2.Delta, raw.Delta2)

	vk.G1.K = make([]bn254.G1Affine, len(raw.IC))
	for i, row := range raw.IC {
		parseG1Dec(t, &vk.G1.K[i], row[0], row[1])
	}
	return vk
}

func parseG1Dec(t *testing.T, p *bn254.G1Affine, xDec, yDec string) {
	t.Helper()
	var x, y big.Int
	if _, ok := x.SetString(xDec, 10); !ok {
		t.Fatalf("parseG1Dec: bad X %q", xDec)
	}
	if _, ok := y.SetString(yDec, 10); !ok {
		t.Fatalf("parseG1Dec: bad Y %q", yDec)
	}
	p.X.SetBigInt(&x)
	p.Y.SetBigInt(&y)
}

// parseG2Dec parses snarkjs G2: coords[0]=[X.A0_dec, X.A1_dec],
// coords[1]=[Y.A0_dec, Y.A1_dec].
func parseG2Dec(t *testing.T, p *bn254.G2Affine, coords [][2]string) {
	t.Helper()
	if len(coords) < 2 {
		t.Fatalf("parseG2Dec: need 2 rows, got %d", len(coords))
	}
	setFp(t, &p.X.A0, coords[0][0])
	setFp(t, &p.X.A1, coords[0][1])
	setFp(t, &p.Y.A0, coords[1][0])
	setFp(t, &p.Y.A1, coords[1][1])
}

func setFp(t *testing.T, e *bn254fp.Element, dec string) {
	t.Helper()
	var b big.Int
	if _, ok := b.SetString(dec, 10); !ok {
		t.Fatalf("setFp: bad dec %q", dec)
	}
	e.SetBigInt(&b)
}

func readRisc0PublicInputs(t *testing.T, path string) []fr.Element {
	t.Helper()
	data := mustRead(t, path)
	var raw struct {
		Inputs []string `json:"inputs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	out := make([]fr.Element, len(raw.Inputs))
	for i, s := range raw.Inputs {
		s = strings.TrimPrefix(s, "0x")
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("input[%d]: %v", i, err)
		}
		out[i].SetBytes(b)
	}
	return out
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
