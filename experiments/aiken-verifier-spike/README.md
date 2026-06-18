# Aiken Verifier Spike

A single-file Aiken verifier for the `zkwrap-gnark` Groth16/BLS12-381 outer wrapper.
Implements the on-chain side of [`docs/adr/0006-pedersen-commitment-check-on-cardano.md`](../../docs/adr/0006-pedersen-commitment-check-on-cardano.md)
against one hard-coded outer-VK + outer-proof fixture.

This is exploratory code. It is not parameterised, not generated, and intentionally
keeps the entire pipeline visible in one file (`validators/spike.ak`). Phase 3 step 2
will lift the constants and helpers into a Rust template inside `zkwrap-risc0`.

## What it verifies

Two public entry points:

```
// Outer layer (generic) — takes a pre-computed public-input vector.
verify(
  pi_a, pi_b, pi_c,                                  // outer Groth16 proof points (compressed)
  commitment, commitment_uncompressed, commitment_pok, // Pedersen commitment + PoK
  inner_vk_hash, inputs                              // public inputs (Int form, length = MAX_INPUTS)
)

// Inner layer (RISC Zero) — reconstructs the public inputs from raw journal bytes.
verify_risc0(
  pi_a, pi_b, pi_c,
  commitment, commitment_uncompressed, commitment_pok,
  inner_vk_hash,
  journal_bytes                                       // raw RISC Zero guest output
)
```

**The outer layer** performs five steps:

1. Bind `commitment_uncompressed` (96 bytes, gnark `RawBytes` layout) to the
   `commitment` compressed encoding by reconstructing the y-sign flag from
   `2*y > q` and comparing byte-for-byte.
2. Derive `commit_fr = ExpandMsgXmd_SHA256(commitment_uncompressed, "bsb22-commitment", 48) mod r`.
3. Pedersen PoK pairing check: `e(commitment, g_sigma_neg) * e(commitment_pok, g) == 1`.
4. Groth16 IC accumulation including the implicit `commit_fr` slot and the bare
   `commitment` term: `vk_x = IC[0] + IC[1]*vkhash + Σ IC[i+2]*inputs[i] + IC[10]*commit_fr + commitment`.
5. Standard Groth16 pairing equation against `vk_x`.

**The inner layer** binds the raw guest output (`journal_bytes`) to the public inputs the
outer proof commits to. It reconstructs `claim_digest` via the RISC Zero `tagged_struct`
chain (three SHA-256 calls) and combines with hardcoded version constants from
`risc0-circuit-recursion 4.0.4`:

```
journal_digest   = SHA256(journal_bytes)
output_digest    = SHA256(TAG_OUTPUT || journal_digest || ZERO_32 || u16_LE(2))
claim_digest     = SHA256(TAG_CLAIM  || ZERO_32       || pre_state || post_state ||
                          output_digest || u32_LE(0) || u32_LE(0) || u16_LE(4))

inputs = [
  split_digest(control_root).low,                     // baked: inputs[0]
  split_digest(control_root).high,                    // baked: inputs[1]
  to_int_LE(claim_digest[0..16]),                     // derived from journal: inputs[2]
  to_int_LE(claim_digest[16..32]),                    // derived from journal: inputs[3]
  to_int_LE(bn254_control_id),                        // baked: inputs[4]
  0, 0, 0,                                            // MAX_INPUTS=8 padding
]
```

`(low, high) of split_digest` corresponds to `to_int_LE` of the two 16-byte halves of
the original digest — the byte-reverse in the RISC Zero spec collapses to a little-endian
read.

The fixed `pre_state_digest`, `post_state_digest`, `input_digest`, `assumptions_digest`,
and exit-code bytes are pre-computed from the receipt for this specific guest image; in
the production codegen path (Phase 3 step 3) they become parameters of the RISC Zero
plugin's template.

## Inline tests

| Test | Purpose |
|---|---|
| `commit_fr_matches_gnark` | The pure SHA-256 hash-to-Fr path agrees with gnark's `fr.Hash`. |
| `compress_binding_matches` | Reconstructed compressed encoding equals the fixture commitment. |
| `verify_valid_proof` | The outer layer accepts the real Phase 2 outer proof with literal inputs. |
| `verify_tampered_inner_vk_hash` *(must fail)* | Bumped `inner_vk_hash` makes verification reject. |
| `verify_tampered_input` *(must fail)* | Bit-flipped `inputs[0]` makes verification reject. |
| `claim_digest_chain_matches` | The three-SHA-256 chain produces the receipt's recorded `claim_digest`. |
| `risc0_inputs_match_fixture` | The inner layer's reconstructed inputs vector equals the proof's public inputs. |
| `verify_risc0_valid_proof` | End-to-end: journal bytes → reconstructed inputs → the outer layer accepts. |
| `verify_risc0_tampered_journal` *(must fail)* | Flipping the journal's first byte breaks the chain. |
| `verify_batched_valid_proof` | Random-batched single-`final_verify` path accepts the same proof. |
| `verify_batched_tampered_input` *(must fail)* | Bit-flipped `inputs[0]` rejected by the batched path. |
| `verify_batched_risc0_valid_proof` | Inner layer + random-batched outer layer end-to-end. |
| `verify_batched_risc0_tampered_journal` *(must fail)* | Tampered journal rejected by the batched path. |

## Running

```bash
cd experiments/aiken-verifier-spike
aiken check
```

`aiken check` compiles the validator and executes all `test ...` blocks. Memory
and CPU execution units are reported per test in the output.

## Regenerating the fixture

The hard-coded constants come from `fixtures/groth16-setup/outer_vk.json`
and `fixtures/outer-proofs/risc0-groth16-outer-proof.json` (MAX_INPUTS = 8,
RISC Zero canonical inner). To regenerate:

```bash
cd zkwrap-gnark
go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark
/tmp/zkwrap-gnark unsafe-setup --max-inputs 8 --out ../fixtures/groth16-setup
/tmp/zkwrap-gnark prove \
  --inner ../fixtures/canonical-inner/risc0-hello-world \
  --setup ../fixtures/groth16-setup \
  --out ../fixtures/outer-proofs/risc0-groth16-outer-proof.json
```

`commitment_uncompressed` is `proof.Commitments[0].Marshal()` from gnark — i.e. the
raw uncompressed G1 affine bytes. A short Go helper that computes it from the
compressed bytes lives at `/tmp/commit_fr_check/main.go` and could be folded into
`zkwrap-gnark prove` later (as a redeemer-side artifact) when the Rust plugin work
of Phase 3 step 2 starts.

## Known scope limits

- **Single fixture.** Constants are baked in; no parameterisation. That comes in
  Phase 3 step 2 (Rust string template).
- **Infinity case unhandled.** A `commitment` at infinity fails the binding check
  (since the spike reconstructs only the regular-point compressed form). The
  wrapper circuit should never emit an infinity commitment in practice, but
  production codegen should explicitly reject or branch.
- **`public_and_commitment_committed = [[]]` only.** The verifier assumes no
  committed wires beyond the commitment point itself. If gnark ever changes the
  commitment shape, ADR-0006 and this verifier need to be revised in tandem.
