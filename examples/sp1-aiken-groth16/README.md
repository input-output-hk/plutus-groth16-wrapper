# SP1 → Cardano, end-to-end

A runnable demo of the whole pipeline: take an SP1 zkVM execution, wrap its
Groth16/BN254 proof in a BLS12-381 outer proof, generate the Aiken validator,
and check the live proof against it.

The guest proves knowledge of two nontrivial factors of a number
(`multiply(17, 23)` → commits `391` to the public values). The pipeline ends
with a green `aiken check`: the validator's on-chain logic accepts the real
proof, and rejects a tampered public-values / input / VK-hash.

```text
[1] prove          multiply guest → SP1 Groth16 proof           (local native-gnark)
[2] canonicalize   SP1 proof → CanonicalInnerProof              (ark-groth16 verify → binding)
[3] wrap           GnarkCliProver::prove → BLS12-381 OuterProof (gnark, ~33s PK load + ~8s)
[4] build_validator generate Aiken validator project → aiken check ✅
```

Nothing is hand-staged between steps: the *live* `canonicalize_proof` output
drives a real outer proof that drives the validator. That is what demonstrates
the **binding** — the SP1 program identity (`vkey_hash`) and committed public
values are preserved all the way into the public inputs the validator checks.

## SP1 vs RISC Zero

The outer pipeline (gnark prover, `build_validator`, the deployable validator)
is identical to [`../risc0-aiken-groth16`](../risc0-aiken-groth16). Only the
inner axis differs: SP1 has 2 public inputs — `inputs[0] = vkey_hash` (baked)
and `inputs[1] = committed_values_digest = SHA256(public_values) mod 2^253`
(derived on-chain) — versus RISC Zero's 5-input journal-auth chain.

## Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| SP1 toolchain | build + prove the guest | `curl -L https://sp1.succinct.xyz \| bash && sp1up` |
| SP1 Groth16 circuit artifacts | local Groth16 proving (`~/.sp1/circuits/groth16/v3.0.0/`, ~2.7 GB) | downloaded on first `network`-feature run, or pre-populated |
| Go | build the `zkwrap-gnark` outer prover | https://go.dev/dl |
| aiken | run `aiken check` (step 4) | https://aiken-lang.org/installation-instructions |
| Outer trusted setup | the ~1 GB outer proving key | generated in step 2 below; only the VK is committed |

## Run it

From the repo root:

```bash
# 1. Build the gnark outer prover.
( cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark )
export ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark

# 2. Generate the outer trusted setup (one-time; writes a ~1 GB proving key).
#    MAX_INPUTS must be ≥ the inner proof's n_real (SP1 = 2); 8 matches the
#    committed verifying key.
"$ZKWRAP_GNARK_BIN" unsafe-setup --max-inputs 8 --out "$HOME/zkwrap-setup"
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-setup"

# 3. Run the full live pipeline (release; SP1 local Groth16 proving is slow).
export SP1_PROVER=local
export SP1_SKIP_PROGRAM_BUILD=true   # use the committed guest ELF
cd examples/sp1-aiken-groth16
cargo run --release
```

`ZKWRAP_SETUP_DIR` defaults to the repo's `fixtures/groth16-setup` if unset, but
that only commits the verifying key — the proving key must be generated as above.

## Wrapping and Aiken generation

The SP1 host program imports the toolkit and calls it directly. The two
load-bearing calls are:

```rust
// [2] canonicalize the native SP1 proof (ergonomic adapter, `sp1-sdk` feature)
let canonical = zkwrap_sp1::canonicalize_proof(&proof, &vk)?;

// [3] wrap into a BLS12-381 outer proof (spawns zkwrap-gnark)
let outer = GnarkCliProver::new(&gnark_bin, &setup_dir).prove(&canonical.proof)?;

// [4] generate the Aiken validator project from that proof
let project = build_validator(&Sp1ValidatorRequest {
    canonical: &canonical,
    outer_proof: &outer,
    outer_vk_json: &vk_json,
    public_values: proof.public_values.as_slice(),
    project_name: "zkwrap/sp1_groth16",
})?;
project.write_to(&out_dir)?;  // writes aiken.toml, lib/, validators/, test/
```

The generated Aiken project is left under `generated/sp1-verifier/` for
inspection — `validators/verify.ak` is the deployable validator, with the
`vkey_hash` constant and the outer VK baked in.

## Notes

- **WSL — setup location:** keep `ZKWRAP_SETUP_DIR` on the native Linux
  filesystem (e.g. `$HOME/zkwrap-setup`), not under `/mnt/*`. gnark reads the
  1 GB proving key with many small reads — ~30 min over the Windows 9p mount vs
  ~30 s on native ext4.
- **Rust-version mismatch:** if the host and SP1 guest toolchains differ,
  `SP1_SKIP_PROGRAM_BUILD=true` reuses the committed ELF instead of recompiling
  the guest (see `docs/research/sp1-artifact-format.md` §10).
