package outer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381groth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

func syntheticProof(t *testing.T) *bls12381groth16.Proof {
	t.Helper()
	_, _, g1, g2 := bls12381.Generators()
	p := &bls12381groth16.Proof{}
	p.Ar = g1
	p.Bs = g2
	p.Krs = g1
	p.Commitments = []bls12381.G1Affine{g1}
	p.CommitmentPok = g1
	return p
}

func syntheticInputs(t *testing.T, n int) (innerVKHash fr.Element, inputs []fr.Element) {
	t.Helper()
	innerVKHash.SetUint64(0xdeadbeef)
	inputs = make([]fr.Element, n)
	for i := range inputs {
		inputs[i].SetUint64(uint64(i + 1))
	}
	return
}

func TestProof_RoundTrip(t *testing.T) {
	proof := syntheticProof(t)
	innerVKHash, inputs := syntheticInputs(t, 8)

	var buf bytes.Buffer
	if err := WriteProof(&buf, proof, innerVKHash, inputs, 8); err != nil {
		t.Fatalf("WriteProof: %v", err)
	}

	gotProof, gotHash, gotInputs, gotMax, err := ReadProof(&buf)
	if err != nil {
		t.Fatalf("ReadProof: %v", err)
	}
	if gotMax != 8 {
		t.Fatalf("max_inputs: got %d, want 8", gotMax)
	}
	if !proof.Ar.Equal(&gotProof.Ar) {
		t.Errorf("ar mismatch")
	}
	if !proof.Bs.Equal(&gotProof.Bs) {
		t.Errorf("bs mismatch")
	}
	if !proof.Krs.Equal(&gotProof.Krs) {
		t.Errorf("krs mismatch")
	}
	if len(proof.Commitments) != len(gotProof.Commitments) {
		t.Fatalf("commitments length: got %d, want %d", len(gotProof.Commitments), len(proof.Commitments))
	}
	for i := range proof.Commitments {
		if !proof.Commitments[i].Equal(&gotProof.Commitments[i]) {
			t.Errorf("commitments[%d] mismatch", i)
		}
	}
	if !proof.CommitmentPok.Equal(&gotProof.CommitmentPok) {
		t.Errorf("commitment_pok mismatch")
	}
	if !innerVKHash.Equal(&gotHash) {
		t.Errorf("inner_vk_hash mismatch: got %s, want %s", gotHash.String(), innerVKHash.String())
	}
	if len(gotInputs) != len(inputs) {
		t.Fatalf("inputs length: got %d, want %d", len(gotInputs), len(inputs))
	}
	for i := range inputs {
		if !inputs[i].Equal(&gotInputs[i]) {
			t.Errorf("inputs[%d] mismatch", i)
		}
	}
}

func TestProof_SchemaShape(t *testing.T) {
	proof := syntheticProof(t)
	innerVKHash, inputs := syntheticInputs(t, 8)

	var buf bytes.Buffer
	if err := WriteProof(&buf, proof, innerVKHash, inputs, 8); err != nil {
		t.Fatalf("WriteProof: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := raw["backend"]; got != "gnark-groth16-bls12381" {
		t.Errorf("backend: got %v", got)
	}
	if got := raw["max_inputs"]; got != float64(8) {
		t.Errorf("max_inputs: got %v", got)
	}

	proofObj, ok := raw["proof"].(map[string]any)
	if !ok {
		t.Fatalf("proof: not an object")
	}
	assertCompressed := func(field, val string, wantBytes int) {
		t.Helper()
		if val != strings.ToLower(val) {
			t.Errorf("%s: not lowercase", field)
		}
		if strings.HasPrefix(val, "0x") {
			t.Errorf("%s: has 0x prefix", field)
		}
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Errorf("%s: hex: %v", field, err)
			return
		}
		if len(b) != wantBytes {
			t.Errorf("%s: got %d bytes, want %d", field, len(b), wantBytes)
		}
	}
	assertCompressed("proof.ar", proofObj["ar"].(string), 48)
	assertCompressed("proof.bs", proofObj["bs"].(string), 96)
	assertCompressed("proof.krs", proofObj["krs"].(string), 48)
	assertCompressed("proof.commitment_pok", proofObj["commitment_pok"].(string), 48)
	commitments, ok := proofObj["commitments"].([]any)
	if !ok {
		t.Fatalf("proof.commitments: not an array")
	}
	if len(commitments) != 1 {
		t.Errorf("proof.commitments length: got %d, want 1", len(commitments))
	}
	for i, c := range commitments {
		assertCompressed("proof.commitments["+string(rune('0'+i))+"]", c.(string), 48)
	}
	commitmentsUncompressed, ok := proofObj["commitments_uncompressed"].([]any)
	if !ok {
		t.Fatalf("proof.commitments_uncompressed: not an array")
	}
	if len(commitmentsUncompressed) != len(commitments) {
		t.Errorf("proof.commitments_uncompressed length: got %d, want %d", len(commitmentsUncompressed), len(commitments))
	}
	for i, c := range commitmentsUncompressed {
		assertCompressed("proof.commitments_uncompressed["+string(rune('0'+i))+"]", c.(string), 96)
	}

	assertFr := func(field, val string) {
		t.Helper()
		b, err := hex.DecodeString(val)
		if err != nil || len(b) != 32 {
			t.Errorf("%s: not 32-byte hex: err=%v len=%d", field, err, len(b))
		}
	}
	assertFr("inner_vk_hash", raw["inner_vk_hash"].(string))

	ins, ok := raw["inputs"].([]any)
	if !ok {
		t.Fatalf("inputs: not an array")
	}
	if len(ins) != 8 {
		t.Errorf("inputs length: got %d, want 8", len(ins))
	}
	for i, e := range ins {
		assertFr("inputs["+string(rune('0'+i))+"]", e.(string))
	}
}

// The checked-in fixture must carry a commitments_uncompressed that matches its
// compressed commitment — ReadProof validates this, so a stale or wrong value
// fails here (and would mislead the Aiken redeemer artifact otherwise).
func TestProof_FixtureUncompressedCommitmentIsValid(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "..", "fixtures", "outer-proofs", "risc0-groth16-outer-proof.json"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	if _, _, _, _, err := ReadProof(f); err != nil {
		t.Fatalf("ReadProof(fixture): %v", err)
	}
}

// ReadProof must reject a proof whose inputs length disagrees with
// max_inputs — that is the docs/schemas/outer-proof-artifacts.md rule that
// becomes load-bearing once the Aiken validator references the proof.
func TestProof_InputsLengthMustMatchMaxInputs(t *testing.T) {
	proof := syntheticProof(t)
	innerVKHash, inputs := syntheticInputs(t, 8)

	var buf bytes.Buffer
	if err := WriteProof(&buf, proof, innerVKHash, inputs, 16); err == nil {
		t.Fatalf("WriteProof: expected error for inputs=8 vs max_inputs=16")
	}
}
