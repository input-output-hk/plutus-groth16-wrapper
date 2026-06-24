# RISC Zero → Cardano, end-to-end (PLONK outer backend)

A runnable demo of the whole pipeline: take a RISC Zero zkVM execution, wrap its
Groth16/BN254 proof in a BLS12-381 **PLONK** outer proof, generate the Aiken
validator, and check the live proof against it.

This is the PLONK twin of [`../risc0-aiken-groth16`](../risc0-aiken-groth16):
the inner RISC Zero proof and every step but the wrap are identical — only the
outer backend differs (and with it the trusted setup and the generated
`plonk.ak` verifier).

The guest proves knowledge of two nontrivial factors of a number
(`multiply(17, 23)` → commits `391` to the journal). The pipeline ends with a
green `aiken check`: the validator's on-chain logic accepts the real proof, and
rejects a tampered journal / input / VK-hash.

```text
[1] prove        multiply guest → RISC Zero Groth16 Receipt   (Docker stark2snark)
[2] canonicalize Receipt → CanonicalInnerProof                (re-verifies → binding)
[3] wrap         GnarkCliProver::prove → BLS12-381 PLONK OuterProof  (gnark)
[4] compose      generate Aiken validator project → aiken check ✅
```

Nothing is hand-staged between steps: the *live* `canonicalize` output drives a
real outer proof that drives the validator. That is what demonstrates the
**binding** — the RISC Zero receipt claim, journal, and image ID are preserved
all the way into the public inputs the validator checks.

## Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| RISC Zero toolchain | build + prove the guest | `curl -L https://risczero.com/install \| bash && rzup install` |
| **Docker** | RISC Zero's STARK→SNARK (Groth16) step runs in a container | https://docs.docker.com/get-docker (the daemon must be running) |
| Go | build the `zkwrap-gnark` outer prover | https://go.dev/dl |
| aiken | run `aiken check` (step 4) | https://aiken-lang.org/installation-instructions |
| Outer trusted setup | the PLONK outer proving key (large) | generated in step 2 below (`zkwrap-gnark unsafe-setup --backend plonk`); only the VK is committed |

> Alternative to Docker: set `BONSAI_API_KEY` + `BONSAI_API_URL` to run the
> SNARK step on Bonsai instead of locally.

## Run it

From the repo root:

```bash
# 1. Build the gnark outer prover.
( cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark )
export ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark

# 2. Generate the PLONK outer trusted setup (one-time; writes a large proving
#    key, takes a few minutes). PLONK compiles the wrapper for the exact inner
#    n_real = 5 (no padding), so --max-inputs is 5.
"$ZKWRAP_GNARK_BIN" unsafe-setup --backend plonk --max-inputs 5 --out "$HOME/zkwrap-plonk-setup"
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-plonk-setup"

# 3. Run the full live pipeline (release; the Groth16/SNARK step is slow).
cd examples/risc0-aiken-plonk
cargo run --release
```

`ZKWRAP_SETUP_DIR` defaults to the repo's `fixtures/plonk-setup` if unset, but
that only commits the verifying key — the proving key must be generated as above.

## Wrapping and Aiken generation

The risc0 host program imports the toolkit and calls it directly. The whole flow
is one Rust file — [`src/main.rs`](src/main.rs) — and the two load-bearing calls
are just:

```rust
// [3] wrap the inner proof into a BLS12-381 outer proof (spawns zkwrap-gnark).
//     The proof type you ask for selects the outer backend.
let outer = GnarkCliProver::new(&gnark_bin, &setup_dir)
    .prove::<PlonkOuterProof>(&canonical.proof)?;

// [4] generate the Aiken validator project from that proof. The factory reads
//     the outer layer from the proof's backend and bakes in the per-guest
//     constants + outer VK.
let project = build_validator(&Risc0ValidatorRequest {
    receipt: &receipt,
    canonical: &canonical,
    outer_proof: &outer,      // &dyn OuterProof — backend-agnostic
    outer_vk_json: &vk_json,
    project_name: "zkwrap/risc0_plonk",
})?;
project.write_to(&out_dir)?;  // writes aiken.toml, lib/, validators/, test/
```

The generated Aiken project is left under `generated/risc0-verifier/` for
inspection — `validators/verify.ak` is the validator, with the
per-guest constants (`image_id`, `control_root`, …) and the outer VK baked in.

## Notes

- **WSL — Docker:** install Docker Desktop on Windows and enable
  *Settings → Resources → WSL Integration* for your distro so `docker` is
  available inside WSL.
- **WSL — setup location:** keep `ZKWRAP_SETUP_DIR` on the native Linux
  filesystem (e.g. `$HOME/zkwrap-plonk-setup`), not under `/mnt/*`. gnark reads
  the proving key with many small reads — ~30 min over the Windows 9p mount vs
  ~30 s on native ext4. The prover reloads the key on every run, so this cost is
  paid each time.
