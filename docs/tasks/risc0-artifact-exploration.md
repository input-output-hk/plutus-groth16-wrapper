# Task: RISC Zero Groth16/BN254 artifact exploration

**Phase:** 1 (Source proof compatibility exploration)
**Status:** Not started
**Blocks:** wrapper canonical witness schema, RISC Zero plugin (Phase 4)

## Context

Phase 1 of [implementation-plan.md](../implementation-plan.md) requires us to lock the MVP wrapper input/output schema based on what real proof artifacts from the first target systems actually look like. This task covers the RISC Zero side. The parallel SP1 task is in [sp1-artifact-exploration.md](sp1-artifact-exploration.md).

The goal is to remove guesswork from the wrapper circuit and the RISC Zero plugin: we should not implement either without a real `(VK, proof, public inputs)` triple in hand and a documented schema for converting it into gnark witness types. The proposal flags RISC Zero/SP1 format compatibility as Risk #2 in [initial-proposal.md](../initial-proposal.md) — this task closes that risk for RISC Zero.

## Scope

In:
- Generate one real RISC Zero Groth16/BN254 proof for a trivial guest program (SHA preimage or Fibonacci-style; whatever is fastest to produce). Bonsai or local proving is fine.
- Inspect and document the on-disk / on-wire artifact format.
- Document the journal commitment scheme and any RISC Zero–specific binding (image ID, claim, receipt structure).
- Sketch the conversion from RISC Zero artifacts to gnark witness types.

Out:
- Implementing the plugin (deferred to Phase 4).
- Choosing the in-circuit hash function (decided in Phase 2 with both explorations in hand).
- SP1 — separate task.

## Deliverables

1. A real RISC Zero proof artifact set committed under a small fixture path (proof, VK, public inputs/journal). Keep it small enough for git; if the proof bundle is large, commit only the parts needed to reconstruct it and document how to regenerate the rest.
2. A research note at `docs/research/risc0-artifact-format.md` covering:
   - RISC Zero version(s) explored, proving mode (local vs Bonsai), and any feature flags.
   - Inner proof system and curve (expected: Groth16/BN254) — confirmed against the on-disk artifact, not just docs.
   - Proof byte layout: G1/G2 point encoding, compression, endianness, ordering.
   - Verification key format and any versioning rules (image ID vs Groth16 VK).
   - Public input count and field encoding as seen by the Groth16 verifier (expected: 1 public input = journal commitment).
   - Journal/public-values hash function and how the journal binds to the receipt claim and image ID.
   - Conversion recipe: RISC Zero artifacts → gnark `groth16_bn254.VerifyingKey`, `groth16_bn254.Proof`, and the BN254 field element representing the public input.
   - Any quirks (multiple receipt formats across versions, control IDs, post-state digests, etc.).
3. A short summary entry to feed the Phase 1 final schema document — bullet points listing the constraints this exploration imposes on the canonical wrapper witness shape.

## Acceptance criteria

- [ ] A RISC Zero Groth16/BN254 proof verifies off-chain using a stock RISC Zero verifier (sanity check that the artifact is genuine).
- [ ] The same proof is parsed by a small Go script using `gnark-crypto` / `gnark` types into a `(VK, proof, public_input)` triple, and gnark's BN254 Groth16 verifier accepts it standalone (no wrapper yet).
- [ ] `docs/research/risc0-artifact-format.md` exists and answers every bullet in Deliverable 2 with concrete observed values, not speculation from external docs.
- [ ] Open questions about binding (journal ↔ image ID ↔ public input) are explicitly listed if they cannot be resolved during this task — they then become inputs to the Phase 4 plugin design.

## Open questions to track

- Which RISC Zero version(s) are we targeting? Format has shifted across releases; a single pinned version for the MVP is preferable.
- Does the RISC Zero Groth16 wrapper produce exactly one BN254 public input, or are there additional commitments we need to account for?
- What is the canonical hash from journal bytes to the BN254 field element that ends up as the public input? (Likely SHA-256 with truncation/reduction, but confirm against an actual artifact.)

## References

- [implementation-plan.md](../implementation-plan.md) — Phase 1 and Phase 4
- [initial-proposal.md](../initial-proposal.md) — Risk #2, Risk #5
- [research/gnark-recursive-verification-benchmarks.md](../research/gnark-recursive-verification-benchmarks.md) — confirms gnark types we will be converting into
