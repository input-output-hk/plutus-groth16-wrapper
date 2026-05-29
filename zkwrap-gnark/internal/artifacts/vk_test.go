package artifacts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// syntheticVK builds a small but valid outer VK: real points on BLS12-381 so the
// encoding tests exercise the compressed-hex path against gnark's own bytes,
// without paying the cost of a trusted setup. Includes one Pedersen commitment
// slot (the configuration gnark's recursive verifier always produces).
func syntheticVK(t *testing.T, maxInputs int) *bls12381groth16.VerifyingKey {
	t.Helper()
	_, _, g1, g2 := bls12381.Generators()
	vk := &bls12381groth16.VerifyingKey{}
	vk.G1.Alpha = g1
	vk.G2.Beta = g2
	vk.G2.Gamma = g2
	vk.G2.Delta = g2
	// IC length: constant (1) + InnerVKHash (1) + max_inputs + 1 commitment slot
	vk.G1.K = make([]bls12381.G1Affine, maxInputs+3)
	for i := range vk.G1.K {
		vk.G1.K[i] = g1
	}
	vk.CommitmentKeys = []pedersen.VerifyingKey{{G: g2, GSigmaNeg: g2}}
	vk.PublicAndCommitmentCommitted = [][]int{{maxInputs + 2}}
	return vk
}

func TestOuterVK_RoundTrip(t *testing.T) {
	in := syntheticVK(t, 8)

	var buf bytes.Buffer
	if err := WriteOuterVK(&buf, in, 8); err != nil {
		t.Fatalf("WriteOuterVK: %v", err)
	}

	out, maxInputs, err := ReadOuterVK(&buf)
	if err != nil {
		t.Fatalf("ReadOuterVK: %v", err)
	}
	if maxInputs != 8 {
		t.Fatalf("maxInputs: got %d, want 8", maxInputs)
	}

	if !in.G1.Alpha.Equal(&out.G1.Alpha) {
		t.Errorf("alpha_g1 mismatch")
	}
	if !in.G2.Beta.Equal(&out.G2.Beta) {
		t.Errorf("beta_g2 mismatch")
	}
	if !in.G2.Gamma.Equal(&out.G2.Gamma) {
		t.Errorf("gamma_g2 mismatch")
	}
	if !in.G2.Delta.Equal(&out.G2.Delta) {
		t.Errorf("delta_g2 mismatch")
	}
	if len(in.G1.K) != len(out.G1.K) {
		t.Fatalf("IC length: got %d, want %d", len(out.G1.K), len(in.G1.K))
	}
	for i := range in.G1.K {
		if !in.G1.K[i].Equal(&out.G1.K[i]) {
			t.Errorf("IC[%d] mismatch", i)
		}
	}

	if len(in.CommitmentKeys) != len(out.CommitmentKeys) {
		t.Fatalf("commitment_keys length: got %d, want %d", len(out.CommitmentKeys), len(in.CommitmentKeys))
	}
	for i := range in.CommitmentKeys {
		if !in.CommitmentKeys[i].G.Equal(&out.CommitmentKeys[i].G) {
			t.Errorf("commitment_keys[%d].g mismatch", i)
		}
		if !in.CommitmentKeys[i].GSigmaNeg.Equal(&out.CommitmentKeys[i].GSigmaNeg) {
			t.Errorf("commitment_keys[%d].g_sigma_neg mismatch", i)
		}
	}
	if len(in.PublicAndCommitmentCommitted) != len(out.PublicAndCommitmentCommitted) {
		t.Errorf("public_and_commitment_committed length mismatch")
	}
}

// TestOuterVK_SchemaShape asserts the encoded form matches docs/schemas/outer-proof-artifacts.md:
// canonical key names, lowercase hex without 0x or separators, expected byte lengths
// for compressed BLS12-381 points, and IC length = max_inputs + 2.
func TestOuterVK_SchemaShape(t *testing.T) {
	vk := syntheticVK(t, 8)

	var buf bytes.Buffer
	if err := WriteOuterVK(&buf, vk, 8); err != nil {
		t.Fatalf("WriteOuterVK: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := raw["backend"]; got != "gnark-groth16-bls12381" {
		t.Errorf("backend: got %v, want gnark-groth16-bls12381", got)
	}
	if got := raw["max_inputs"]; got != float64(8) {
		t.Errorf("max_inputs: got %v, want 8", got)
	}

	assertHex := func(field string, wantBytes int) {
		t.Helper()
		s, ok := raw[field].(string)
		if !ok {
			t.Errorf("%s: not a string", field)
			return
		}
		if s != strings.ToLower(s) {
			t.Errorf("%s: not lowercase hex", field)
		}
		if strings.HasPrefix(s, "0x") {
			t.Errorf("%s: has 0x prefix", field)
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Errorf("%s: not valid hex: %v", field, err)
			return
		}
		if len(b) != wantBytes {
			t.Errorf("%s: got %d bytes, want %d", field, len(b), wantBytes)
		}
	}
	assertHex("alpha_g1", 48)
	assertHex("beta_g2", 96)
	assertHex("gamma_g2", 96)
	assertHex("delta_g2", 96)

	ic, ok := raw["ic"].([]any)
	if !ok {
		t.Fatalf("ic: not an array")
	}
	if len(ic) != 11 {
		t.Errorf("ic length: got %d, want max_inputs+3 = 11 (constant + InnerVKHash + max_inputs + 1 commitment slot)", len(ic))
	}
	for i, e := range ic {
		s, ok := e.(string)
		if !ok {
			t.Errorf("ic[%d]: not a string", i)
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 48 {
			t.Errorf("ic[%d]: not 48-byte hex: %v len=%d", i, err, len(b))
		}
	}

	ck, ok := raw["commitment_keys"].([]any)
	if !ok {
		t.Fatalf("commitment_keys: not an array")
	}
	if len(ck) != 1 {
		t.Errorf("commitment_keys length: got %d, want 1", len(ck))
	}
	ck0, ok := ck[0].(map[string]any)
	if !ok {
		t.Fatalf("commitment_keys[0]: not an object")
	}
	for _, field := range []string{"g", "g_sigma_neg"} {
		s, ok := ck0[field].(string)
		if !ok {
			t.Errorf("commitment_keys[0].%s: not a string", field)
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 96 {
			t.Errorf("commitment_keys[0].%s: not 96-byte hex: %v len=%d", field, err, len(b))
		}
	}

	if _, ok := raw["public_and_commitment_committed"].([]any); !ok {
		t.Errorf("public_and_commitment_committed: missing or not an array")
	}
}
