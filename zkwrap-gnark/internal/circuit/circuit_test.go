package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// The wrapper circuit at MAX_INPUTS=N must declare exactly 1 + N user-public
// variables (InnerVKHash + N inputs). gnark adds 1 implicit ONE_WIRE, so
// ccs.GetNbPublicVariables() should be N + 2.
func TestPlaceholder_PublicVariableCount(t *testing.T) {
	if testing.Short() {
		t.Skip("compile is slow; skipped in -short mode")
	}
	for _, max := range []int{5, 8} {
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, Placeholder(max))
		if err != nil {
			t.Fatalf("compile MAX_INPUTS=%d: %v", max, err)
		}
		got := ccs.GetNbPublicVariables()
		want := max + 2
		if got != want {
			t.Errorf("MAX_INPUTS=%d: GetNbPublicVariables() = %d, want %d", max, got, want)
		}
	}
}
