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

**VKHash**: An in-circuit Poseidon hash (over BLS12-381 Fr) of the inner VK field elements, exposed as the first outer public signal. Identifies which inner proof system and version was used. The Aiken validator never recomputes this hash — it only checks `proof_signal[0] == hardcoded_constant`, where the constant is computed off-chain once at deploy time. Poseidon is used because it is native BLS12-381 field arithmetic (cheapest in gnark); Cardano never executes it.
_Avoid_: VK commitment, verifying key hash

**Outer public inputs**: The public inputs to the outer BLS12-381 proof: `[VKHash, input_0, ..., input_{MAX-1}]`. Inner public inputs are exposed directly — not hashed into a commitment. No on-chain hash computation is required anywhere in the Aiken validator.
_Avoid_: outer public signals, wrapper public outputs

**Aiken validator**: The generated on-chain Cardano script that verifies an outer BLS12-381 proof. Parameterised by both the inner proof system (how many inputs are real, which are zero-checked) and the outer backend (proof format, embedded outer VK points).
_Avoid_: Aiken verifier, on-chain verifier, Cardano validator

### Components

**Plugin**: A Rust library crate that (1) converts an inner proof system's native output into a canonical inner proof, and (2) generates the Aiken validator for that system. One plugin per inner proof system (e.g., `zkwrap-risc0`, `zkwrap-sp1`). The generated Aiken validator has two layers: a generic BLS12-381 proof verification layer (outer VK embedded as a constant) and a system-specific layer (journal authentication chain, excess-zero checks, VKHash constant). See ADR-0004.
_Avoid_: adapter, connector, parser

**Prover binary**: The language-native executable that reads a canonical inner proof from disk and runs the outer backend to produce a BLS12-381 outer proof. Pure prover — emits `outer_proof.bin` and `outer_vk.bin` only; no Aiken code. One binary per outer backend (`zkwrap-gnark` in Go, future `zkwrap-halo2` in Rust).
_Avoid_: wrapper prover, outer prover CLI

**Inner system config**: A small metadata file (JSON) produced by a plugin alongside the canonical inner proof. Contains at minimum `n_real` and `system_id`. Used by the plugin's Aiken codegen function to parameterise the Aiken validator template (excess-zero slot count, journal authentication logic).
_Avoid_: plugin metadata, system manifest

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
> "The RISC Zero plugin — `zkwrap-risc0`. It calls its codegen function with the inner system config (`n_real = 5`, `system_id = 'risc0-v3'`) and the embedded outer VK bytes. The output is a ready-to-compile Aiken module with `VKHash` baked in as a constant, `input_0..input_4` checked directly, and a journal authentication chain (~4 SHA-256 calls via the `tagged_struct` protocol) so the on-chain validator can verify the raw journal bytes against `inputs[2,3]`. No excess zero-checks for RISC Zero since all 5 slots are real."
>
> "What if we later switch to Halo2 as the outer backend?"
>
> "The plugin doesn't change — it still writes the same canonical inner proof. You switch to the Halo2 prover binary, which generates a different Aiken validator template (Halo2 proof format, different pairing ops). The canonical format is the contract between them."
