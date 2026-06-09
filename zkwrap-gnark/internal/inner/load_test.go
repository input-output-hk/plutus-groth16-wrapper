package inner

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// writeFixture builds a synthetic canonical inner proof on disk per
// docs/schemas/canonical-inner-proof.md and returns its directory.
//
// Points are real BN254 generators (so on-curve checks pass) and inputs are
// small ints; n_real is configurable so validation rules can be exercised.
func writeFixture(t *testing.T, opts fixtureOpts) string {
	t.Helper()
	dir := t.TempDir()

	_, _, g1, g2 := bn254.Generators()

	// vk.bin
	var vkBuf []byte
	appendG1 := func(p bn254.G1Affine) {
		x := p.X.Bytes()
		y := p.Y.Bytes()
		vkBuf = append(vkBuf, x[:]...)
		vkBuf = append(vkBuf, y[:]...)
	}
	appendG2 := func(p bn254.G2Affine) {
		xa1 := p.X.A1.Bytes()
		xa0 := p.X.A0.Bytes()
		ya1 := p.Y.A1.Bytes()
		ya0 := p.Y.A0.Bytes()
		vkBuf = append(vkBuf, xa1[:]...)
		vkBuf = append(vkBuf, xa0[:]...)
		vkBuf = append(vkBuf, ya1[:]...)
		vkBuf = append(vkBuf, ya0[:]...)
	}
	appendG1(g1) // alpha
	appendG2(g2) // beta
	appendG2(g2) // gamma
	appendG2(g2) // delta

	nIC := opts.nICOverride
	if nIC == 0 {
		nIC = uint32(opts.nReal + 1)
	}
	var nIcBytes [4]byte
	binary.BigEndian.PutUint32(nIcBytes[:], nIC)
	vkBuf = append(vkBuf, nIcBytes[:]...)
	for i := uint32(0); i < nIC; i++ {
		appendG1(g1)
	}
	if opts.vkTrailingByte {
		vkBuf = append(vkBuf, 0xff)
	}
	if err := os.WriteFile(filepath.Join(dir, "vk.bin"), vkBuf, 0o644); err != nil {
		t.Fatal(err)
	}

	// proof.bin (256 bytes)
	var proofBuf [256]byte
	x := g1.X.Bytes()
	y := g1.Y.Bytes()
	copy(proofBuf[0:32], x[:])
	copy(proofBuf[32:64], y[:])
	{
		xa1 := g2.X.A1.Bytes()
		xa0 := g2.X.A0.Bytes()
		ya1 := g2.Y.A1.Bytes()
		ya0 := g2.Y.A0.Bytes()
		copy(proofBuf[64:96], xa1[:])
		copy(proofBuf[96:128], xa0[:])
		copy(proofBuf[128:160], ya1[:])
		copy(proofBuf[160:192], ya0[:])
	}
	copy(proofBuf[192:224], x[:])
	copy(proofBuf[224:256], y[:])
	if err := os.WriteFile(filepath.Join(dir, "proof.bin"), proofBuf[:], 0o644); err != nil {
		t.Fatal(err)
	}

	// public_inputs.bin
	pubBuf := make([]byte, 0, opts.nReal*32)
	for i := 0; i < opts.nReal; i++ {
		var fe fr.Element
		fe.SetUint64(uint64(i + 1))
		b := fe.Bytes()
		pubBuf = append(pubBuf, b[:]...)
	}
	if err := os.WriteFile(filepath.Join(dir, "public_inputs.bin"), pubBuf, 0o644); err != nil {
		t.Fatal(err)
	}

	// meta.json
	systemID := opts.systemID
	if systemID == "" {
		systemID = "risc0-v3"
	}
	metaNReal := opts.nReal
	if opts.metaNRealOverride != nil {
		metaNReal = *opts.metaNRealOverride
	}
	meta, _ := json.Marshal(map[string]any{
		"system_id": systemID,
		"n_real":    metaNReal,
	})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type fixtureOpts struct {
	nReal             int
	systemID          string
	nICOverride       uint32 // 0 = derive from nReal
	metaNRealOverride *int   // nil = same as nReal
	vkTrailingByte    bool
}

func TestLoadCanonical_HappyPath(t *testing.T) {
	dir := writeFixture(t, fixtureOpts{nReal: 5})

	ip, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ip.SystemID != "risc0-v3" {
		t.Errorf("system_id: got %q, want risc0-v3", ip.SystemID)
	}
	if ip.NReal() != 5 {
		t.Errorf("n_real: got %d, want 5", ip.NReal())
	}
	if len(ip.PublicInputs) != 5 {
		t.Errorf("public_inputs len: got %d, want 5", len(ip.PublicInputs))
	}
	for i, fe := range ip.PublicInputs {
		var want fr.Element
		want.SetUint64(uint64(i + 1))
		if !fe.Equal(&want) {
			t.Errorf("public_inputs[%d]: got %s, want %s", i, fe.String(), want.String())
		}
	}
	if len(ip.VK.G1.K) != 6 {
		t.Errorf("vk.IC len: got %d, want n_real+1 = 6", len(ip.VK.G1.K))
	}
}

func TestLoadCanonical_NICMismatchVsMetaNReal(t *testing.T) {
	// vk.bin says n_ic = 7, but meta.n_real says 5 (so meta.n_real+1 = 6).
	dir := writeFixture(t, fixtureOpts{nReal: 5, nICOverride: 7})

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for n_ic vs meta.n_real mismatch")
	}
	// Failure source should be vk.bin; n_ic should appear in the message.
	if !strings.Contains(err.Error(), "n_ic") || !strings.Contains(err.Error(), "vk.bin") {
		t.Errorf("error should mention vk.bin and n_ic: %v", err)
	}
}

func TestLoadCanonical_PublicInputsCountMismatchVsMeta(t *testing.T) {
	// public_inputs.bin has 5 elements, but meta.n_real says 3.
	override := 3
	dir := writeFixture(t, fixtureOpts{nReal: 5, metaNRealOverride: &override})

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for public_inputs.bin vs meta.n_real mismatch")
	}
	if !strings.Contains(err.Error(), "public_inputs.bin") {
		t.Errorf("error should mention public_inputs.bin: %v", err)
	}
}

func TestLoadCanonical_TruncatedVK(t *testing.T) {
	dir := writeFixture(t, fixtureOpts{nReal: 5})

	// Truncate vk.bin to a non-multiple of the expected layout.
	vkPath := filepath.Join(dir, "vk.bin")
	data, err := os.ReadFile(vkPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vkPath, data[:len(data)-10], 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for truncated vk.bin")
	}
	if !strings.Contains(err.Error(), "vk.bin") {
		t.Errorf("error should mention vk.bin: %v", err)
	}
}

func TestLoadCanonical_TrailingBytesInVK(t *testing.T) {
	// The schema does not include any trailing bytes after the IC array;
	// the loader's size check should reject anything longer than expected.
	dir := writeFixture(t, fixtureOpts{nReal: 5, vkTrailingByte: true})

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for vk.bin with trailing byte")
	}
}

func TestLoadCanonical_MalformedMeta(t *testing.T) {
	dir := writeFixture(t, fixtureOpts{nReal: 5})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for malformed meta.json")
	}
}

func TestLoadCanonical_MissingFile(t *testing.T) {
	dir := writeFixture(t, fixtureOpts{nReal: 5})
	if err := os.Remove(filepath.Join(dir, "proof.bin")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load: expected error for missing proof.bin")
	}
	if !strings.Contains(err.Error(), "proof.bin") {
		t.Errorf("error should mention proof.bin: %v", err)
	}
}
