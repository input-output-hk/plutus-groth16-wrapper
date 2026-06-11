# fixtures/

Shared, checked-in test fixtures used across the repo's languages — the Go
prover (`zkwrap-gnark`), the Rust crates (`zkwrap-rs`), and the generated Aiken
validators. 

## Layout

| Path | What | Produced by |
|------|------|-------------|
| `risc0-hello-world/` | Raw RISC Zero Groth16 artifacts for the `multiply(17, 23)` guest: `receipt.json`, `seal.bin`, `vk.json`, `public_inputs.json`, and the digest/constant `*.bin` files. | `experiments/risc0-hello-world` (`dump_groth16`); copied here. |
| `canonical-inner/risc0-hello-world/` | The canonical inner-proof bundle (`vk.bin`, `proof.bin`, `public_inputs.bin`, `meta.json`) per `docs/schemas/canonical-inner-proof.md`. The `plugin → prover` contract. | `zkwrap-gnark` `go run ./cmd/gen-testdata` (and reproduced byte-for-byte by `zkwrap-risc0::canonicalize`). |
| `groth16-setup/` | Outer (gnark Groth16 / BLS12-381) trusted-setup bundle. Only `outer_vk.json` is committed; `outer_pk.bin` (~1 GB) and `circuit.r1cs` (~70 MB) are gitignored and regenerated locally. | `zkwrap-gnark unsafe-setup`. |
| `groth16-outer-proof.json` | An outer wrapper proof over the canonical inner bundle above. | `zkwrap-gnark prove`. |

Future inner systems get a sibling under `risc0-hello-world/` and
`canonical-inner/` (e.g. `sp1-…/`); a future outer scheme gets its own
`<scheme>-setup/` + `<scheme>-outer-proof.json`.

## Regenerating

From the `zkwrap-gnark` module root:

```sh
# canonical inner bundle (from fixtures/risc0-hello-world)
go run ./cmd/gen-testdata

# outer trusted setup (MAX_INPUTS must fit the inner n_real; 8 here)
go run . unsafe-setup --max-inputs 8 --out ../fixtures/groth16-setup

# outer proof over the canonical inner bundle
go run . prove \
  --inner ../fixtures/canonical-inner/risc0-hello-world \
  --setup ../fixtures/groth16-setup \
  --out   ../fixtures/groth16-outer-proof.json
```
