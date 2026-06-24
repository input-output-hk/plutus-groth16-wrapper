package plonk

import (
	"bytes"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	bls12381plonk "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// tinyPlonkCircuit mirrors the production proof *shape* (public inputs + one
// forced BSB22 commitment, which makes the VK carry Qcp and the proof carry
// Bsb22Commitments) without the cost of real recursion. It proves in seconds,
// giving fast coverage of the PLONK serialization and the deterministic
// verifier the production path relies on.
type tinyPlonkCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
	X frontend.Variable // private: A + B
}

func (c *tinyPlonkCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(c.A, c.B), c.X)
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api is not a Committer")
	}
	cmt, err := committer.Commit(c.A, c.B)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt, 0)
	return nil
}

// makeTinyPlonkProof runs an unsafe PLONK setup + prove over tinyPlonkCircuit
// and returns the native VK, proof, and public-witness vector [A, B].
func makeTinyPlonkProof(t *testing.T) (*bls12381plonk.VerifyingKey, *bls12381plonk.Proof, []fr.Element) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &tinyPlonkCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := gnarkplonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	assignment := &tinyPlonkCircuit{A: 3, B: 4, X: 7}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := gnarkplonk.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	if err := gnarkplonk.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("self-verify: %v", err)
	}

	bvk := vk.(*bls12381plonk.VerifyingKey)
	bproof := proof.(*bls12381plonk.Proof)
	var a, b fr.Element
	a.SetUint64(3)
	b.SetUint64(4)
	return bvk, bproof, []fr.Element{a, b}
}

func TestPlonkVKRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("plonk setup+prove is slow; skipped in -short mode")
	}
	vk, _, _ := makeTinyPlonkProof(t)

	var buf bytes.Buffer
	if err := WriteVK(&buf, vk, 1); err != nil {
		t.Fatalf("WriteVK: %v", err)
	}
	got, numInputs, err := ReadVK(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadVK: %v", err)
	}
	if numInputs != 1 {
		t.Errorf("num_inputs: got %d, want 1", numInputs)
	}
	if got.Size != vk.Size {
		t.Errorf("Size: got %d, want %d", got.Size, vk.Size)
	}
	if got.NbPublicVariables != vk.NbPublicVariables {
		t.Errorf("NbPublicVariables: got %d, want %d", got.NbPublicVariables, vk.NbPublicVariables)
	}
	if !got.Generator.Equal(&vk.Generator) || !got.SizeInv.Equal(&vk.SizeInv) || !got.CosetShift.Equal(&vk.CosetShift) {
		t.Errorf("scalar VK field mismatch after round-trip")
	}
	if !got.Ql.Equal(&vk.Ql) || !got.Qr.Equal(&vk.Qr) || !got.Qm.Equal(&vk.Qm) || !got.Qo.Equal(&vk.Qo) || !got.Qk.Equal(&vk.Qk) {
		t.Errorf("selector commitment mismatch after round-trip")
	}
	if len(got.Qcp) != len(vk.Qcp) || len(got.Qcp) == 0 {
		t.Fatalf("Qcp length: got %d, want %d (>0)", len(got.Qcp), len(vk.Qcp))
	}
	if !got.Qcp[0].Equal(&vk.Qcp[0]) {
		t.Errorf("Qcp[0] mismatch after round-trip")
	}
	if !got.Kzg.G1.Equal(&vk.Kzg.G1) || !got.Kzg.G2[0].Equal(&vk.Kzg.G2[0]) || !got.Kzg.G2[1].Equal(&vk.Kzg.G2[1]) {
		t.Errorf("KZG VK mismatch after round-trip")
	}
}

func TestPlonkVKReconstructedVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("plonk setup+prove is slow; skipped in -short mode")
	}
	vk, proof, pub := makeTinyPlonkProof(t)

	// Reconstruct the VK from JSON (exercising PrecomputeLines) and confirm a
	// proof verifies against it via canonical gnark plonk.Verify.
	var buf bytes.Buffer
	if err := WriteVK(&buf, vk, 1); err != nil {
		t.Fatalf("WriteVK: %v", err)
	}
	rvk, _, err := ReadVK(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadVK: %v", err)
	}

	assignment := &tinyPlonkCircuit{A: 3, B: 4}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	if err := gnarkplonk.Verify(proof, rvk, w); err != nil {
		t.Fatalf("plonk.Verify with reconstructed VK: %v", err)
	}
	_ = pub
}

func TestPlonkProofRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("plonk setup+prove is slow; skipped in -short mode")
	}
	vk, proof, pub := makeTinyPlonkProof(t)

	// Compute lin_digest via the deterministic verifier (also self-checks).
	linDigest, err := VerifyDeterministic(vk, proof, pub)
	if err != nil {
		t.Fatalf("VerifyDeterministic (valid): %v", err)
	}

	// Treat pub[0] as inner_vk_hash and the rest as inputs for the envelope.
	innerVKHash := pub[0]
	inputs := pub[1:]

	var buf bytes.Buffer
	if err := WriteProof(&buf, proof, innerVKHash, inputs, linDigest, len(inputs)); err != nil {
		t.Fatalf("WriteProof: %v", err)
	}
	gotProof, gotHash, gotInputs, gotLin, gotNum, err := ReadProof(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadProof: %v", err)
	}
	if gotNum != len(inputs) {
		t.Errorf("num_inputs: got %d, want %d", gotNum, len(inputs))
	}
	if !gotHash.Equal(&innerVKHash) {
		t.Errorf("inner_vk_hash mismatch after round-trip")
	}
	if len(gotInputs) != len(inputs) || (len(inputs) > 0 && !gotInputs[0].Equal(&inputs[0])) {
		t.Errorf("inputs mismatch after round-trip")
	}
	if !gotLin.Equal(&linDigest) {
		t.Errorf("lin_digest mismatch after round-trip")
	}
	if !gotProof.Z.Equal(&proof.Z) || !gotProof.LRO[0].Equal(&proof.LRO[0]) || !gotProof.H[2].Equal(&proof.H[2]) {
		t.Errorf("proof point mismatch after round-trip")
	}
	if len(gotProof.BatchedProof.ClaimedValues) != len(proof.BatchedProof.ClaimedValues) {
		t.Fatalf("claimed_values length mismatch")
	}
	if !gotProof.BatchedProof.ClaimedValues[0].Equal(&proof.BatchedProof.ClaimedValues[0]) {
		t.Errorf("claimed_values[0] mismatch after round-trip")
	}
	if !gotProof.ZShiftedOpening.ClaimedValue.Equal(&proof.ZShiftedOpening.ClaimedValue) {
		t.Errorf("z_shifted_opening.claimed_value mismatch after round-trip")
	}

	// The reconstructed proof + recomputed lin_digest must still verify, and the
	// round-tripped lin_digest must match what the deterministic verifier yields.
	gotLin2, err := VerifyDeterministic(vk, gotProof, pub)
	if err != nil {
		t.Fatalf("VerifyDeterministic (reconstructed): %v", err)
	}
	if !gotLin2.Equal(&linDigest) {
		t.Errorf("recomputed lin_digest differs after proof round-trip")
	}
}

func TestPlonkDeterministicTamperRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("plonk setup+prove is slow; skipped in -short mode")
	}
	vk, proof, pub := makeTinyPlonkProof(t)
	if _, err := VerifyDeterministic(vk, proof, pub); err != nil {
		t.Fatalf("valid proof should verify: %v", err)
	}

	tampered := append([]fr.Element(nil), pub...)
	var one fr.Element
	one.SetOne()
	tampered[0].Add(&tampered[0], &one)
	if _, err := VerifyDeterministic(vk, proof, tampered); err == nil {
		t.Fatalf("tampered public input unexpectedly verified")
	}
}
