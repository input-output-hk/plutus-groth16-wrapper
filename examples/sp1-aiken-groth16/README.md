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
inner axis differs: SP1 v6 has 5 public inputs —
`[vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce]`.
`vkey_hash`/`exit_code`/`vk_root` are baked, `committed_values_digest =
SHA256(public_values) mod 2^253` is derived on-chain, and `proof_nonce` rides in
the redeemer. See [`docs/research/sp1-artifact-format-v6.md`](../../docs/research/sp1-artifact-format-v6.md).

## Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| SP1 toolchain | build + prove the guest | `curl -L https://sp1.succinct.xyz \| bash && sp1up` |
| SP1 Groth16 circuit artifacts | local Groth16 proving (`~/.sp1/circuits/groth16/v6.1.0/`, ~3.2 GB) | downloaded automatically on first proving run |
| Go + GCC | `native-gnark` compiles the gnark FFI via CGO | system toolchain |
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
#    MAX_INPUTS must be ≥ the inner proof's n_real (SP1 v6 = 5); 8 matches the
#    committed verifying key.
"$ZKWRAP_GNARK_BIN" unsafe-setup --max-inputs 8 --out "$HOME/zkwrap-setup"
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-setup"

# 3. Run the full live pipeline (release; local CPU Groth16 proving is slow).
#    The guest ELF is compiled fresh by build.rs (needs the SP1 toolchain on PATH).
export PATH="$HOME/.sp1/bin:$PATH"
cd examples/sp1-aiken-groth16
cargo run --release
```

> **Note:** unlike `experiments/sp1-v6-hello-world`, this example ships no
> committed guest ELF — `include_elf!` reads the one `build.rs` compiles. If
> `SP1_SKIP_PROGRAM_BUILD=true` is set (e.g. carried over from running the
> experiment), the build is skipped and you'll get
> `couldn't read .../multiply: No such file or directory`. Unset it with:
> `unset SP1_SKIP_PROGRAM_BUILD`

`ZKWRAP_SETUP_DIR` defaults to the repo's `fixtures/groth16-setup` if unset, but
that only commits the verifying key — the proving key must be generated as above.

## Wrapping and Aiken generation

The SP1 host program imports the toolkit and calls it directly. The two
load-bearing calls are:

```rust
// [2] canonicalize the native SP1 proof (one call, takes sp1-verifier types)
let canonical = zkwrap_sp1::canonicalize(&proof.proof, proof.public_values.as_slice())?;

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
`sp1_program_vkey_hash` constant and the outer VK baked in.

## Notes

- **WSL — setup location:** keep `ZKWRAP_SETUP_DIR` on the native Linux
  filesystem (e.g. `$HOME/zkwrap-setup`), not under `/mnt/*`. gnark reads the
  1 GB proving key with many small reads — ~30 min over the Windows 9p mount vs
  ~30 s on native ext4.
