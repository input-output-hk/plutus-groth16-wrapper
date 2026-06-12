# RISC Zero → Cardano, end-to-end

A runnable demo of the whole pipeline: take a RISC Zero zkVM execution, wrap its
Groth16/BN254 proof in a BLS12-381 outer proof, generate the Aiken validator,
and check the live proof against it.

The guest proves knowledge of two nontrivial factors of a number
(`multiply(17, 23)` → commits `391` to the journal). The pipeline ends with a
green `aiken check`: the validator's on-chain logic accepts the real proof, and
rejects a tampered journal / input / VK-hash.

```text
[1] prove        multiply guest → RISC Zero Groth16 Receipt   (Docker stark2snark)
[2] canonicalize Receipt → CanonicalInnerProof                (re-verifies → binding)
[3] wrap         GnarkCliProver::prove → BLS12-381 OuterProof      (gnark, ~40s PK load + ~7s)
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
| Outer trusted setup | the ~1 GB outer proving key | generated in step 2 below (`zkwrap-gnark unsafe-setup`); only the VK is committed |

> Alternative to Docker: set `BONSAI_API_KEY` + `BONSAI_API_URL` to run the
> SNARK step on Bonsai instead of locally.

## Run it

From the repo root:

```bash
# 1. Build the gnark outer prover.
( cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark )
export ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark

# 2. Generate the outer trusted setup (one-time; writes a ~1 GB proving key,
#    takes a few minutes). MAX_INPUTS must be ≥ the inner proof's n_real
#    (RISC Zero = 5); 8 matches the committed verifying key.
"$ZKWRAP_GNARK_BIN" unsafe-setup --max-inputs 8 --out "$HOME/zkwrap-setup"
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-setup"

# 3. Run the full live pipeline (release; the Groth16/SNARK step is slow).
cd examples/risc0-aiken-groth16
cargo run --release
```

`ZKWRAP_SETUP_DIR` defaults to the repo's `fixtures/groth16-setup` if unset, but
that only commits the verifying key — the proving key must be generated as above.

## Wrapping and Aiken generation

Note that in the example the risc0 host program imports the toolkit and calls it 
directly. The whole flow is one Rust file —
[`src/main.rs`](src/main.rs) — and the two load-bearing calls are just:

```rust
// [3] wrap the inner proof into a BLS12-381 outer proof (spawns zkwrap-gnark)
let outer = GnarkCliProver::new(&gnark_bin, &setup_dir).prove(&canonical.proof)?;

// [4] generate the Aiken validator project from that proof
let project = compose(&ComposeRequest {
    outer: &Groth16Backend,   // outer layer: BLS12-381 Groth16
    inner: &Risc0Codegen,     // inner layer: RISC Zero journal auth
    inner_vk_hash: &outer.inner_vk_hash,
    codegen_meta: &canonical.codegen,
    ..
})?;
project.write_to(&out_dir)?;  // writes aiken.toml, lib/, validators/, test/
```

The generated Aiken project is left under `generated/risc0-verifier/` for
inspection — `validators/verify.ak` is the deployable validator, with the
per-guest constants (`image_id`, `control_root`, …) and the outer VK baked in.

## Notes

- **WSL — Docker:** install Docker Desktop on Windows and enable
  *Settings → Resources → WSL Integration* for your distro so `docker` is
  available inside WSL.
- **WSL — setup location:** keep `ZKWRAP_SETUP_DIR` on the native Linux
  filesystem (e.g. `$HOME/zkwrap-setup`), not under `/mnt/*`. gnark reads the
  1 GB proving key with many small reads — ~30 min over the Windows 9p mount vs
  ~30 s on native ext4. The prover reloads the key on every run, so this cost is
  paid each time.