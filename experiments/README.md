# Experiments

Standalone experiments for exploring SP1 and RISC Zero Groth16/BN254 proof artifacts.
Each pair is a Rust prover that dumps fixtures plus a Go verifier that consumes them.

---

## risc0-hello-world

**Language:** Rust · **SDK:** risc0-zkvm v3.0.5 + risc0-groth16 v3.0.4

Proves `multiply(17, 23) = 391` with RISC Zero and writes Groth16/BN254 fixtures to `fixtures/`.

```bash
cd risc0-hello-world
RISC0_DEV_MODE=0 cargo run --release --features prove
```

Requires: RISC Zero toolchain (`rzup`), Docker (for the Groth16 stark-to-snark step).
Fixtures already committed — no need to re-run unless regenerating.

---

## risc0-gnark-verifier

**Language:** Go · **gnark:** v0.14.0 / gnark-crypto v0.19.0

Two programs that consume `risc0-hello-world/fixtures/`:

| Program | What it does |
|---------|-------------|
| `verify/` | Standalone BN254 Groth16 verification via gnark |
| `recursive/` | Wraps the BN254 inner proof in a BLS12-381 outer Groth16 proof |
| `recursive_plonk/` | Wraps the BN254 inner proof in a BLS12-381 outer PLONK proof |

```bash
cd risc0-gnark-verifier
go run ./verify/main.go
go run ./recursive/main.go
go run ./recursive_plonk/main.go
```

All should print `PASS`.

---

## sp1-hello-world

**Language:** Rust · **SDK:** sp1-sdk v3.4.0, `native-gnark` feature (no Docker)

Proves `multiply(17, 23) = 391` with SP1 and writes Groth16/BN254 fixtures to `fixtures/`.

```bash
cd sp1-hello-world

# Build the guest ELF (only needed if guest source changes)
cd program && cargo prove build && cd ..

# Build and run the host prover — release mode is required, debug is ~10× slower
SP1_SKIP_PROGRAM_BUILD=true \
cargo run --release --bin dump_groth16
```

Requires: SP1 toolchain (`sp1up --version v3.4.0`), Go (for CGO gnark FFI build),
SP1 circuit artifacts at `~/.sp1/circuits/groth16/v3.0.0/` (~2.78 GB, downloaded once).

`SP1_SKIP_PROGRAM_BUILD=true` skips guest recompilation to avoid a flag incompatibility
between the host Rust toolchain (≥1.83) and the SP1 succinct toolchain (1.81.0).

---

## sp1-gnark-verifier

**Language:** Go · **gnark:** v0.14.0 / gnark-crypto v0.19.0

Two programs that consume `sp1-hello-world/fixtures/`:

| Program | What it does |
|---------|-------------|
| `verify/` | Standalone BN254 Groth16 verification via gnark |
| `recursive/` | Wraps the BN254 inner proof in a BLS12-381 outer Groth16 proof |
| `recursive_plonk/` | Wraps the BN254 inner proof in a BLS12-381 outer PLONK proof |

```bash
cd sp1-gnark-verifier
go run ./verify/main.go
go run ./recursive/main.go
go run ./recursive_plonk/main.go
```

All should print `PASS`.

**SP1 vs RISC Zero:** SP1 has 2 public inputs (`vkey_hash`, `committed_values_digest`);
RISC Zero has 5. The recursive verifiers use separate outer circuits with `innerNPublic = 2`
and `innerNPublic = 5` respectively, requiring separate trusted setups.

**Groth16 vs PLONK outer:** Both `recursive/` and `recursive_plonk/` verify the same BN254
Groth16 inner proof using emulated arithmetic. The difference is the outer proof system:
Groth16 uses R1CS and a random unsafe trusted setup; PLONK uses a sparse constraint system
(SCS) and a KZG polynomial commitment scheme (unsafe SRS for testing).
