# Task: RISC Zero Groth16/BN254 verification with gnark

**Phase:** 1 (Source proof compatibility exploration)
**Status:** Done
**Depends on:** `risc0-artifact-exploration.md` (fixtures committed)
**Blocks:** wrapper canonical witness schema, Phase 2 circuit

## Context

Fixtures committed under `experiments/risc0-hello-world/fixtures/`:
- `seal.bin` — 256-byte Groth16 proof: A∈G1 (64 B) | B∈G2 (128 B) | C∈G1 (64 B), big-endian 32-byte coords
- `vk.json` — snarkjs-compatible verifying key (curve: bn128, nPublic: 5)
- `public_inputs.json` — 5 BN254 Fr elements as 0x-prefixed hex strings

A Rust self-check in `dump_groth16.rs` already confirms the seal is valid via `risc0_groth16::Verifier`. This task verifies the same proof using gnark's standalone BN254 Groth16 verifier, which forces every format conversion question to be answered concretely.

See `experiments/risc0-hello-world/fixtures/README.md` for the full public input derivation and byte layout.

## Deliverable

New Go experiment at `experiments/risc0-gnark-verify/`:
- `go.mod` — standalone module, gnark + gnark-crypto deps
- `main.go` — entry point: parse fixtures, verify, exit 0 on success
- `parse.go` — fixture parsing helpers (VK, proof, public inputs)

Fixtures are loaded from hardcoded relative path `../risc0-hello-world/fixtures/`.

## Implementation steps

### 1 — Go module

```
module risc0-gnark-verify

go 1.22

require (
    github.com/consensys/gnark        v0.11.0  (or latest)
    github.com/consensys/gnark-crypto v0.14.0  (compatible)
)
```

### 2 — Parse VK from `vk.json`

snarkjs JSON → gnark BN254 VerifyingKey field mapping:

| JSON field        | gnark field      | Type                  |
|-------------------|------------------|-----------------------|
| `vk_alpha_1`      | `G1.Alpha`       | G1Affine              |
| `vk_beta_2`       | `G2.Beta`        | G2Affine              |
| `vk_gamma_2`      | `G2.Gamma`       | G2Affine              |
| `vk_delta_2`      | `G2.Delta`       | G2Affine              |
| `IC` (6 elements) | `G1.K`           | []G1Affine            |
| `vk_alphabeta_12` | skip             | recomputed via Precompute() |

snarkjs G1 format: `[x_decimal, y_decimal, "1"]`  
snarkjs G2 format: `[[a0_decimal, a1_decimal], [b0_decimal, b1_decimal], ["1","0"]]`
→ maps to gnark `E2{A0, A1}` directly (no coordinate swap needed for the VK).

After populating: call `vk.Precompute()` to compute the cached `e(α,β)` GT element.

### 3 — Parse proof from `seal.bin`

Use `fp.Element.SetBytes(buf)` to parse each 32-byte big-endian value individually.
Do NOT use `G1Affine.SetBytes` / `G2Affine.SetBytes` — those expect gnark-crypto's MSB compression flags.

G1 (A and C):
```
X = data[0:32]   Y = data[32:64]
```

G2 (B) — **key uncertainty**: Fp2 sub-element ordering within the 128 bytes.

Two candidates:
- `[X.A1, X.A0, Y.A1, Y.A0]` each 32B — matches gnark-crypto `G2Affine.RawBytes()` and Ethereum/EVM convention ← **try first**
- `[X.A0, X.A1, Y.A0, Y.A1]` — "natural" ordering

If the first attempt fails pairing check, swap to the other and re-run. The result becomes the canonical format record for `docs/schemas/risc0-artifact-format.md`.

### 4 — Parse public inputs and build witness

Parse 5 hex strings from `public_inputs.json` → `[]fr.Element` via `fr.Element.SetBytes`.

Build a gnark witness via a minimal circuit struct:
```go
type PubInputs struct {
    In [5]frontend.Variable `gnark:",public"`
}
```
Then `frontend.NewWitness(&assignment, ecc.BN254.ScalarField())` → `.Public()`.

### 5 — Verify

```go
err := groth16.Verify(proof, vk, pubW)
```

Print `PASS` or `FAIL <error>`. Exit 0 on success, 1 on failure.

## Acceptance criteria

- [x] `go run .` from `experiments/risc0-gnark-verify/` exits 0 and prints `PASS`
- [x] G2 byte ordering used in seal.bin is confirmed and noted in a comment
- [x] The concrete gnark field names used in the VK struct are noted in a comment (they are not in the public gnark interface; the internal concrete type is required)

## Post-task

After this passes, write `docs/research/risc0-artifact-format.md` with the confirmed format (this task only answers the Go-side format questions; a separate doc covers the full picture including public input derivation).

Update `risc0-artifact-exploration.md` status to Done.
