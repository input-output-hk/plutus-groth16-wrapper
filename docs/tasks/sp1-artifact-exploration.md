# Task: SP1 Groth16/BN254 artifact exploration

**Phase:** 1 (Source proof compatibility exploration)
**Status:** Not started
**Blocks:** wrapper canonical witness schema, SP1 plugin (Phase 5)

## Context

Phase 1 of [implementation-plan.md](../implementation-plan.md) requires us to lock the MVP wrapper input/output schema based on what real proof artifacts from the first target systems actually look like. This task covers the SP1 side. The parallel RISC Zero task is in [risc0-artifact-exploration.md](risc0-artifact-exploration.md).

SP1 also emits a Groth16/BN254 proof at the end of its proving pipeline (after STARK → SNARK wrapping). The exploration goal is identical to the RISC Zero one: get a real artifact, document its structure, and confirm the conversion path into gnark witness types — before any wrapper or plugin code is written. The proposal flags this as part of Risk #2 in [initial-proposal.md](../initial-proposal.md).

## Scope

In:
- Generate one real SP1 Groth16/BN254 proof for a trivial program (Fibonacci or similar; SP1's example programs are fine).
- Inspect and document the on-disk / on-wire artifact format.
- Document the SP1 public values commitment scheme and any binding to the program (vkey hash, committed public values).
- Sketch the conversion from SP1 artifacts to gnark witness types.

Out:
- Implementing the plugin (deferred to Phase 5).
- Choosing the in-circuit hash function (decided in Phase 2 with both explorations in hand).
- RISC Zero — separate task.

## Deliverables

1. A real SP1 proof artifact set committed under a small fixture path (proof, VK, public values). Same size guidance as the RISC Zero task.
2. A research note at `docs/research/sp1-artifact-format.md` covering:
   - SP1 version explored, proving mode (local vs network), and any feature flags or proof modes (`Compressed`, `Groth16`, `Plonk` — we want Groth16 specifically).
   - Inner proof system and curve (expected: Groth16/BN254) — confirmed against the on-disk artifact.
   - Proof byte layout: G1/G2 point encoding, compression, endianness, ordering.
   - Verification key format and how the SP1 program vkey relates to the Groth16 VK.
   - Public input count and field encoding as seen by the Groth16 verifier (expected: 1–2 public inputs, typically a hash of the committed public values plus possibly the vkey hash — confirm).
   - Public-values commitment scheme: what hash, what preimage, how it ends up as a BN254 field element.
   - Conversion recipe: SP1 artifacts → gnark `groth16_bn254.VerifyingKey`, `groth16_bn254.Proof`, and the BN254 field element(s) for the public input(s).
   - Any quirks specific to SP1's STARK → SNARK wrapping (committed values vs raw output, vkey commitments, version bumps).
3. A short summary entry to feed the Phase 1 final schema document — bullet points listing the constraints this exploration imposes on the canonical wrapper witness shape, plus any divergence from the RISC Zero shape.

## Acceptance criteria

- [ ] An SP1 Groth16/BN254 proof verifies off-chain using a stock SP1 verifier.
- [ ] The same proof is parsed by a small Go script using `gnark-crypto` / `gnark` types into a `(VK, proof, public_input)` triple, and gnark's BN254 Groth16 verifier accepts it standalone (no wrapper yet).
- [ ] `docs/research/sp1-artifact-format.md` exists and answers every bullet in Deliverable 2 with concrete observed values, not speculation from external docs.
- [ ] Any divergence from RISC Zero's shape (different number of public inputs, different commitment scheme, different curve points orientation) is explicitly called out and bubbled up to the Phase 1 schema decision.

## Open questions to track

- Which SP1 version are we targeting? SP1 is moving fast; pin a specific release for the MVP.
- How many public inputs does SP1's Groth16 verifier accept? If it's more than one, the wrapper's "single hash public input" convention will need either an extra plugin-side compression step or a wrapper variant.
- Does the SP1 Groth16 VK depend on the program (per-program circuit) or is there a single "outer" Groth16 VK shared across SP1 programs? This drastically changes how `VKHash` should be interpreted on-chain.

## References

- [implementation-plan.md](../implementation-plan.md) — Phase 1 and Phase 5
- [initial-proposal.md](../initial-proposal.md) — Risk #2, Risk #5
- [tasks/risc0-artifact-exploration.md](risc0-artifact-exploration.md) — sister task; keep the deliverable shapes aligned so the final schema can compare them side-by-side
