# Groth16/BN Wrapper Toolkit

A toolkit that re-proves Groth16/BN254 proofs from external ZK systems inside a BLS12-381 wrapper proof, enabling on-chain verification on Cardano via an Aiken validator.

## Language

### Proof systems and curves

**Inner proof system**: A ZK proving system (RISC Zero, SP1, circom, etc.) that emits a Groth16/BN254 proof. The thing being wrapped.
_Avoid_: inner circuit, inner prover, source system

**Outer backend**: The BLS12-381 prover used to produce the wrapping proof (gnark Groth16, gnark PLONK, Halo2). Swappable independently of the inner proof system.
_Avoid_: outer prover, wrapper backend, outer circuit backend

**Wrapper circuit**: The gnark (or Halo2) circuit that emulates BN254 Groth16 verification inside a BLS12-381 proof. Compiled once per `MAX_INPUTS` value and outer backend.
_Avoid_: recursive circuit, outer circuit

**Inner VK**: The BN254 Groth16 verifying key of the inner proof system. Fixed per system release (e.g., all RISC Zero v3.x proofs share one inner VK).
_Avoid_: inner verifying key, BN254 VK

### Canonical format

**Canonical inner proof**: The normalized, language-agnostic representation of an inner Groth16/BN254 proof, produced by a plugin and consumed by the outer backend prover. Contains: inner VK (compressed BN254 binary), proof bytes (raw uncompressed BN254), public inputs (up to `n_real`, as 32-byte big-endian Fr elements), and `n_real`.
_Avoid_: inner proof bundle, wrapped input, plugin output

**`MAX_INPUTS`**: A compile-time constant baked into the wrapper circuit, defining the maximum number of inner public input slots. Fixed at trusted setup time. Systems with fewer real inputs pad the remainder with zero.
_Avoid_: max public inputs, circuit input slots

**`n_real`**: The number of genuinely meaningful public inputs for a given inner proof system, always ≤ `MAX_INPUTS`. Implicit in the canonical inner proof as `public_inputs.len()` — padding to `MAX_INPUTS` is the prover binary's job.
_Avoid_: real input count, non-padded inputs

**Canonical inner proof struct**: The Rust struct at the heart of the plugin-to-prover contract:
- `vk: Bn254Vk` — alpha_g1, beta/gamma/delta_g2, ic[] (n_real+1 points)
- `proof: Bn254Proof` — ar (G1), bs (G2), krs (G1); no CommitmentPok (unused when VK declares zero Pedersen commitments, as RISC Zero and SP1 both do)
- `public_inputs: Vec<Bn254Fr>` — real inputs only, length = n_real; 32-byte big-endian BN254 Fr elements
- `system_id: &'static str`

Wire encoding: G1 = 64 bytes uncompressed (X‖Y big-endian); G2 = 128 bytes uncompressed (X.A1‖X.A0‖Y.A1‖Y.A0 big-endian, imaginary part first — gnark WriteRawTo convention).

### Outer proof and on-chain

**InnerVKHash**: An in-circuit Poseidon hash (over BLS12-381 Fr) of the inner VK field elements, exposed as the first outer public signal. Identifies which inner proof system and version was used. The Aiken validator never recomputes this hash — it only checks `proof_signal[0] == hardcoded_constant`, where the constant is computed off-chain once at deploy time. Poseidon is used because it is native BLS12-381 field arithmetic (cheapest in gnark); Cardano never executes it.
_Avoid_: VKHash, VK commitment, verifying key hash

**Outer public inputs**: The public inputs to the outer BLS12-381 proof: `[InnerVKHash, input_0, ..., input_{MAX-1}]`. Inner public inputs are exposed directly — not hashed into a commitment. No on-chain hash computation is required anywhere in the Aiken validator.
_Avoid_: outer public signals, wrapper public outputs

**Aiken validator**: The generated on-chain Cardano script that verifies an outer BLS12-381 proof. Composed from a Layer 1 fragment (chosen by outer backend) and a Layer 2 fragment (chosen by inner proof system), plus a generated constants block.
_Avoid_: Aiken verifier, on-chain verifier, Cardano validator

**Layer 1 (proving engine)**: The generic, inner-system-agnostic on-chain verifier for an outer backend's proof — pairing checks, IC accumulation, and the backend's public-input *expansion convention* (prepend `InnerVKHash`, pad to `MAX_INPUTS`, fold any commitment input). One Layer 1 per outer backend (Groth16/BLS12-381, PLONK, etc.). Its only per-instance inputs are the embedded outer VK constants and the `InnerVKHash` constant. It is agnostic to which inner system produced the inputs.
_Avoid_: outer verifier layer, generic layer, verification engine

**Layer 2 (inner-system scaffolding)**: The system-specific fragment that derives the `n_real` real inner public inputs from the redeemer's inner artifact (e.g. RISC Zero's journal-authentication chain producing 5 inputs). Its sole output is a `List<Int>` of length `n_real`. It knows nothing about the outer public-input layout — not `InnerVKHash`, `MAX_INPUTS`, padding, or the outer backend.
_Avoid_: system layer, journal layer, adapter layer

**Composer**: The Rust code that stitches one Layer 1 + one Layer 2 into a generated Aiken **project** (`aiken.toml`, `lib/`, `validators/`, optional `test/`) that compiles and tests standalone. It **renders** Layer 1 into `lib/` with the setup-bound crypto constants (outer VK points, Pedersen commitment keys from `outer_vk.json`) baked into its `verify`; **vendors** the generic, constant-free Layer 2 logic into `lib/`; and generates `validators/verify.ak` — the app/inner-binding constants block plus the wiring of Layer 2 → Layer 1. Dispatches on the outer-backend identifier (→ Layer 1) and `system_id` (→ Layer 2). Bakes `n_real`/`MAX_INPUTS` as the *shape* of the generated glue, not as runtime constants.
_Avoid_: generator, stitcher, codegen orchestrator

**Constant-handling principle**: Two kinds of instance-specific value, handled differently by *why* they exist.
- **Setup-bound crypto** — outer VK points, Pedersen commitment keys. Come from the trusted setup; can never depend on application logic or the redeemer. **Baked directly into the Layer 1 `verify`** (rendered by the Composer), never exposed as parameters.
- **Inner/app-binding** — `InnerVKHash`, RISC Zero `image_id` / `control_root` / per-guest digests. Identify which inner system/program; may later become redeemer-driven (e.g. "accept any of N allowed programs"). These are **function parameters** of the generic `lib/` logic; the generated `validators/verify.ak` holds them as baked `const`s and passes them in, so promoting one to a redeemer field is a one-line edit at the call site.

The net effect: Layer 2 `lib/` logic stays invariant across deployments, and the policy surface (which programs/systems are accepted) lives entirely in `validators/verify.ak` — while the verifier's cryptographic identity (the outer VK) is fixed inside Layer 1 where app logic cannot reach it.

**Outer-backend identifier**: A versioned string (e.g. `gnark-groth16-bls12381`) naming which outer backend produced a proof, carried in `outer_vk.json` (authoritative) and echoed in `outer_proof.json`. Keys the composer's choice of Layer 1. Distinct from `system_id`, which keys Layer 2.
_Avoid_: backend name, engine id, proof type

### Components

**Plugin**: A Rust library crate per inner proof system (e.g. `zkwrap-risc0`, `zkwrap-sp1`) that (1) converts the system's native output into a canonical inner proof, and (2) contributes the **Layer 2** fragment. It does not own Layer 1 — that belongs to the outer backend — so adding a system never touches proof-verification code. The Composer combines the plugin's Layer 2 with the chosen Layer 1.
_Avoid_: adapter, connector, parser

**Prover binary**: The language-native executable that reads a canonical inner proof from disk and runs the outer backend to produce a BLS12-381 outer proof. Pure prover — emits `outer_proof.bin` and `outer_vk.bin` only; no Aiken code. One binary per outer backend (`zkwrap-gnark` in Go, future `zkwrap-halo2` in Rust).
_Avoid_: wrapper prover, outer prover CLI

**Inner system config**: The `meta.json` file inside the canonical inner proof bundle. MUST contain `system_id` and `n_real` (read by the prover binary); MAY contain a system-specific `codegen` section (read only by the Composer, opaque to the prover) carrying the per-guest Layer 2 constants — e.g. RISC Zero's `image_id`, `post_state_digest`, `control_root`, `bn254_control_id`. There is no separate sidecar file; `meta.json` is the inner system config.
_Avoid_: plugin metadata, system manifest, sidecar

## Example dialogue

> "We have a RISC Zero receipt. Which component handles it first?"
>
> "The RISC Zero plugin — it extracts the inner proof from the receipt and writes the canonical inner proof to disk, along with the inner system config."
>
> "Then what touches it?"
>
> "The gnark prover binary. It reads those files, loads the wrapper circuit and proving key, and runs the outer backend to produce a BLS12-381 outer proof."
>
> "Who generates the Aiken validator?"
>
> "The RISC Zero plugin — `zkwrap-risc0`. It calls its codegen function with the inner system config (`n_real = 5`, `system_id = 'risc0-v3'`) and the embedded outer VK bytes. The output is a ready-to-compile Aiken module with `InnerVKHash` baked in as a constant, `input_0..input_4` checked directly, and a journal authentication chain (~4 SHA-256 calls via the `tagged_struct` protocol) so the on-chain validator can verify the raw journal bytes against `inputs[2,3]`. No excess zero-checks for RISC Zero since all 5 slots are real."
>
> "What if we later switch to Halo2 as the outer backend?"
>
> "The plugin doesn't change — it still writes the same canonical inner proof. You switch to the Halo2 prover binary, which generates a different Aiken validator template (Halo2 proof format, different pairing ops). The canonical format is the contract between them."
