package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// canonicalInnerDir is the checked-in canonical inner-proof testdata,
// generated from experiments/risc0-hello-world/fixtures by
// `go run ./cmd/gen-testdata`. Path is relative to this test file.
const canonicalInnerDir = "../../testdata/canonical-inner/risc0-hello-world"

// TestIntegration_SetupProveVerify is the end-to-end smoke check that the
// binary is a working lift of the experiment prototype. It runs the full
// unsafe-setup → prove → verify cycle against the checked-in canonical
// inner-proof fixture.
//
// The wrapper-circuit trusted setup is slow (≈30s+ on workstation hardware),
// so this test is skipped under `go test -short`.
func TestIntegration_SetupProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: trusted setup is slow; skipped in -short mode")
	}
	if _, err := os.Stat(filepath.Join(canonicalInnerDir, "vk.bin")); err != nil {
		t.Skipf("canonical inner-proof testdata not present at %s: %v (run `go run ./cmd/gen-testdata` from the module root)", canonicalInnerDir, err)
	}

	// MAX_INPUTS = 5 is the minimum that fits the RISC Zero fixture's n_real=5;
	// minimising it keeps the setup cost bounded.
	const maxInputs = 5

	root := t.TempDir()
	setupDir := filepath.Join(root, "setup")
	proofPath := filepath.Join(root, "outer_proof.json")

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

	// prove
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"prove",
			"--inner", canonicalInnerDir,
			"--setup", setupDir,
			"--out", proofPath,
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("prove: exit %d\nstderr: %s", code, stderr.String())
		}
	}
	if proof := mustRead(t, proofPath); !json.Valid(proof) {
		t.Errorf("prove: outer_proof.json is not valid JSON")
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
