# Experiments

Standalone provers that regenerate the raw per-system proof artifacts
committed under [`fixtures/`](../fixtures/). Each proves `multiply(17, 23) = 391`
and dumps its Groth16/BN254 artifacts; the fixtures are already committed, so you
only need these when regenerating.

---

## risc0-hello-world

**Language:** Rust · **SDK:** risc0-zkvm v3.0.5 + risc0-groth16 v3.0.4

Proves `multiply(17, 23) = 391` with RISC Zero and dumps the Groth16/BN254
artifacts consumed by `fixtures/risc0-hello-world/`.

```bash
cd risc0-hello-world
RISC0_DEV_MODE=0 cargo run --release --features prove
```

Requires: RISC Zero toolchain (`rzup`), Docker (for the Groth16 stark-to-snark step).

---

## sp1-v6-hello-world

**Language:** Rust · **SDK:** sp1-sdk v6.2.4, `native-gnark` feature (no Docker)

Proves `multiply(17, 23) = 391` with SP1 v6 and dumps the Groth16/BN254 artifacts
consumed by `fixtures/sp1-hello-world/` (the inputs to `zkwrap-sp1::canonicalize`).

```bash
cd sp1-v6-hello-world

# Build the guest ELF (only needed if guest source changes)
cd program && cargo prove build && cd ..

# Build and run the host prover — release mode is required, debug is ~10× slower
SP1_SKIP_PROGRAM_BUILD=true \
cargo run --release --bin dump_groth16
```

Requires: SP1 toolchain (`sp1up`), Go (for the CGO gnark FFI build), and the SP1
Groth16 circuit artifacts (downloaded once, several GB).

`SP1_SKIP_PROGRAM_BUILD=true` skips guest recompilation to avoid a flag
incompatibility between the host Rust toolchain and the SP1 succinct toolchain.
