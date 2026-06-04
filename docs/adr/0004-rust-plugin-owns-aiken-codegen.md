# Rust plugin library owns Aiken validator codegen

**Status:** superseded by [ADR-0007 (two-axis Aiken codegen)](0007-two-axis-aiken-codegen.md). The core conclusion holds — codegen is Rust, not Go — but ADR-0007 splits ownership across two axes: the inner-system plugin owns only Layer 2, while Layer 1 belongs to the outer backend, with a Composer stitching them. The "plugin owns the whole template" framing below is outdated.

Aiken validator generation is the responsibility of each Rust plugin crate, not the Go gnark prover binary.

**Context.** A generated Aiken validator has two layers: a generic BLS12-381 proof verification layer (outer VK embedded as a constant, pairing check, IC accumulation) and a system-specific layer that depends intimately on the inner proof system. The system-specific layer includes: which of the `MAX_INPUTS` slots carry real data and which must be checked as zero (e.g., SP1 pads slots 2-4); the `VKHash` constant computed from the inner VK; and — critically — the journal authentication chain that derives the raw application outputs from the outer public inputs.

Journal authentication is not generic. For RISC Zero it is roughly four SHA-256 calls following the `tagged_struct` protocol (`SHA256(SHA256(tag) ‖ children ‖ u32s_LE ‖ count_u16_LE)`), with tag digests baked as constants. For SP1 it is one SHA-256 call (`SHA256(public_values_bytes) == inputs[1]`). Both use only the SHA-256 builtin present on Cardano. This logic is inner-system knowledge — the Go gnark binary has no concept of it.

**Decision.** Each plugin module (`zkwrap-risc0`, `zkwrap-sp1`, …) exposes a codegen function that, given the outer VK bytes (produced by the prover binary after trusted setup) and the inner system config (`n_real`, `system_id`), emits a ready-to-compile Aiken module. The outer VK bytes are embedded in the plugin crate as a deployment constant (`include_bytes!`) after the trusted setup ceremony; callers do not pass them at runtime.

The Go gnark prover binary (`zkwrap-gnark`) is a pure prover: it reads a canonical inner proof from disk and writes `outer_proof.bin` and `outer_vk.bin`. It emits no Aiken code.

**Rejected alternative.** Placing codegen in the Go binary was initially considered for locality (the Go binary already holds the outer VK). Rejected because: (1) the system-specific Aiken logic is far larger than the outer-VK embedding, (2) the Go binary would need to know inner-system details it has no other reason to know, (3) plugin authors would need to modify Go code to add a new inner system, breaking the Rust-native plugin interface.

**Consequences.**

- Plugin crates each ship an Aiken template for their inner system. The template is parameterised by `n_real`, `VKHash`, and the embedded outer VK points.
- A `zkwrap-sp1` host program can call `sp1_plugin::gen_aiken_validator(outer_vk_bytes, &config)` to get the Aiken source; similarly for `zkwrap-risc0`.
- Adding a new inner proof system requires: (a) a new Rust plugin crate, (b) a new Aiken template — no changes to the Go prover binary.
- The Go binary output (`outer_proof.bin`, `outer_vk.bin`) is fully canonical; the outer VK format is shared across all plugins.
- The trusted setup ceremony produces `outer_vk.bin`; this file is then embedded into each plugin crate via `include_bytes!` at publish time, analogous to how SP1 embeds its `groth16_vk.bin`.
