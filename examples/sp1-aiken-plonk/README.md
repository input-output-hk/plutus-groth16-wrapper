# SP1 → Cardano, end-to-end (PLONK outer backend)

A runnable demo of the whole pipeline: take an SP1 zkVM execution, wrap its
Groth16/BN254 proof in a BLS12-381 **PLONK** outer proof, generate the Aiken
validator, and check the live proof against it.

This is the PLONK twin of [`../sp1-aiken-groth16`](../sp1-aiken-groth16): the
inner SP1 proof and every step but the wrap are identical — only the outer
backend differs (and with it the trusted setup and the generated `plonk.ak`
verifier).

The guest proves knowledge of two nontrivial factors of a number
(`multiply(17, 23)` → commits `391` to the public values). The pipeline ends
with a green `aiken check`: the validator's on-chain logic accepts the real
proof, and rejects a tampered public-values / input / VK-hash.

```text
[1] prove          multiply guest → SP1 Groth16 proof           (local native-gnark)
[2] canonicalize   SP1 proof → CanonicalInnerProof              (ark-groth16 verify → binding)
[3] wrap           GnarkCliProver::prove → BLS12-381 PLONK OuterProof (gnark)
[4] build_validator generate Aiken validator project → aiken check ✅
```

Nothing is hand-staged between steps: the *live* `canonicalize_proof` output
drives a real outer proof that drives the validator. That is what demonstrates
the **binding** — the SP1 program identity (`vkey_hash`) and committed public
values are preserved all the way into the public inputs the validator checks.

## Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| SP1 toolchain | build + prove the guest | `curl -L https://sp1.succinct.xyz \| bash && sp1up` |
| SP1 Groth16 circuit artifacts | local Groth16 proving (`~/.sp1/circuits/groth16/v6.1.0/`, ~3.2 GB) | downloaded automatically on first proving run |
| Go + GCC | `native-gnark` compiles the gnark FFI via CGO | system toolchain |
| Go | build the `zkwrap-gnark` outer prover | https://go.dev/dl |
| aiken | run `aiken check` (step 4) | https://aiken-lang.org/installation-instructions |
| Outer trusted setup | the PLONK outer proving key (large) | generated in step 2 below; only the VK is committed |

## Run it

From the repo root:

```bash
# 1. Build the gnark outer prover.
( cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark )
export ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark

# 2. Generate the PLONK outer trusted setup (one-time; writes a large proving
#    key). PLONK compiles the wrapper for the exact inner n_real = 5 (no
#    padding), so --max-inputs is 5.
"$ZKWRAP_GNARK_BIN" unsafe-setup --backend plonk --max-inputs 5 --out "$HOME/zkwrap-plonk-setup"
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-plonk-setup"

# 3. Run the full live pipeline (release; local CPU Groth16 proving is slow).
#    The guest ELF is compiled fresh by build.rs (needs the SP1 toolchain on PATH).
export PATH="$HOME/.sp1/bin:$PATH"
cd examples/sp1-aiken-plonk
cargo run --release
```

`ZKWRAP_SETUP_DIR` defaults to the repo's `fixtures/plonk-setup` if unset, but
that only commits the verifying key — the proving key must be generated as above.

## Wrapping and Aiken generation

The SP1 host program imports the toolkit and calls it directly. The two
load-bearing calls are:

```rust
// [2] canonicalize the native SP1 proof (one call, takes sp1-verifier types)
let canonical = zkwrap_sp1::canonicalize(&proof.proof, proof.public_values.as_slice())?;

// [3] wrap into a BLS12-381 outer proof (spawns zkwrap-gnark).
//     The proof type you ask for selects the outer backend.
let outer = GnarkCliProver::new(&gnark_bin, &setup_dir)
    .prove::<PlonkOuterProof>(&canonical.proof)?;

// [4] generate the Aiken validator project from that proof
let project = build_validator(&Sp1ValidatorRequest {
    canonical: &canonical,
    outer_proof: &outer,      // &dyn OuterProof — backend-agnostic
    outer_vk_json: &vk_json,
    public_values: proof.public_values.as_slice(),
    project_name: "zkwrap/sp1_plonk",
})?;
project.write_to(&out_dir)?;  // writes aiken.toml, lib/, validators/, test/
```

The generated Aiken project is left under `generated/sp1-verifier/` for
inspection — `validators/verify.ak` is the deployable validator, with the
`sp1_program_vkey_hash` constant and the outer VK baked in.

## Notes

- **WSL — setup location:** keep `ZKWRAP_SETUP_DIR` on the native Linux
  filesystem (e.g. `$HOME/zkwrap-plonk-setup`), not under `/mnt/*`. gnark reads
  the proving key with many small reads — ~30 min over the Windows 9p mount vs
  ~30 s on native ext4.
