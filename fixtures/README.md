# fixtures/

Shared, checked-in test fixtures used across the repo's languages — the Go
prover (`zkwrap-gnark`), the Rust crates (`zkwrap-rs`), and the generated Aiken
validators. 

## Layout

| Path | What | Produced by |
|------|------|-------------|
| `risc0-hello-world/` | Raw RISC Zero Groth16 artifacts for the `multiply(17, 23)` guest: `receipt.json`, `seal.bin`, `vk.json`, `public_inputs.json`, and the digest/constant `*.bin` files. | `experiments/risc0-hello-world` (`dump_groth16`); copied here. |
| `sp1-hello-world/` | Raw SP1 v6 Groth16 artifacts for the `multiply(17, 23)` guest: `proof_bytes.bin` (356 B, `SP1ProofWithPublicValues::bytes()`), `public_values.bin`, and `manifest.json` (human-readable summary incl. the 5 decoded public inputs). The inputs to `zkwrap-sp1::canonicalize`. | `experiments/sp1-v6-hello-world` (`dump_groth16`); copied here. |
| `canonical-inner/risc0-hello-world/` | The canonical inner-proof bundle (`vk.bin`, `proof.bin`, `public_inputs.bin`, `meta.json`) per `docs/schemas/canonical-inner-proof.md`. The `plugin → prover` contract. | `zkwrap-gnark` `go run ./cmd/gen-testdata` (and reproduced byte-for-byte by `zkwrap-risc0::canonicalize`). |
| `canonical-inner/sp1-hello-world/` | The canonical SP1 v6 inner-proof bundle (`vk.bin`, `proof.bin`, `public_inputs.bin`, `meta.json`; `n_real = 5`). | Reproduced byte-for-byte by `zkwrap-sp1::canonicalize`, which decodes SP1's fixed v6.1.0 VK on the fly from `sp1-verifier`'s embedded `GROTH16_VK_BYTES`; `proof.bin`/`public_inputs.bin`/`meta.json` come from the raw `sp1-hello-world/` artifacts. |
| `groth16-setup/` | Outer (gnark Groth16 / BLS12-381) trusted-setup bundle. Only `outer_vk.json` is committed; `outer_pk.bin` (~1 GB) and `circuit.r1cs` (~70 MB) are gitignored and regenerated locally. | `zkwrap-gnark unsafe-setup`. |
| `outer-proofs/<inner>-<outer>-outer-proof.json` | Outer wrapper proofs, one per (inner system, outer backend): `risc0-groth16-outer-proof.json`, `sp1-groth16-outer-proof.json`. | `zkwrap-gnark prove`. |

Both inner systems share the single outer `groth16-setup/` (MAX_INPUTS = 8 ≥
each system's `n_real`). Future inner systems get a sibling under
`sp1-hello-world/` and `canonical-inner/`; a future outer backend adds its own
`<scheme>-setup/` and `outer-proofs/<inner>-<scheme>-outer-proof.json` entries.

## Regenerating

From the `zkwrap-gnark` module root:

```sh
# canonical inner bundle (from fixtures/risc0-hello-world)
go run ./cmd/gen-testdata

# outer trusted setup (MAX_INPUTS must fit the inner n_real; 8 here)
go run . unsafe-setup --max-inputs 8 --out ../fixtures/groth16-setup

# outer proof over the RISC Zero canonical inner bundle
go run . prove \
  --inner ../fixtures/canonical-inner/risc0-hello-world \
  --setup ../fixtures/groth16-setup \
  --out   ../fixtures/outer-proofs/risc0-groth16-outer-proof.json

# outer proof over the SP1 canonical inner bundle (reuses the same setup)
go run . prove \
  --inner ../fixtures/canonical-inner/sp1-hello-world \
  --setup ../fixtures/groth16-setup \
  --out   ../fixtures/outer-proofs/sp1-groth16-outer-proof.json
```

The SP1 raw artifacts come from `experiments/sp1-v6-hello-world` (`dump_groth16`,
SP1 v6.1.0). The canonical bundle is just what `zkwrap-sp1::canonicalize`
produces from them: `vk.bin` is decoded on the fly from `sp1-verifier`'s
embedded VK (no separate generation step), and
`proof.bin` (= `proof_bytes.bin[100..356]`) / `public_inputs.bin` (the 5 inputs)
/ `meta.json` follow from the raw artifacts. See
`docs/research/sp1-artifact-format-v6.md`.
