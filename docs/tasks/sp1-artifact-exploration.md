# Task: SP1 Groth16/BN254 artifact exploration

**Phase:** 1 (Source proof compatibility exploration)
**Status:** Done
**Blocks:** wrapper canonical witness schema, SP1 plugin (Phase 5)

## Context

Phase 1 of [implementation-plan.md](../implementation-plan.md) requires us to lock the MVP wrapper input/output schema based on what real proof artifacts from the first target systems actually look like. This task covers the SP1 side. The RISC Zero side is complete — see [risc0-artifact-exploration.md](risc0-artifact-exploration.md).

SP1 also emits a Groth16/BN254 proof at the end of its proving pipeline (after STARK → SNARK wrapping). The exploration goal is identical to the RISC Zero one: get a real artifact, document its structure, and confirm the conversion path into gnark witness types — before any wrapper or plugin code is written. The proposal flags this as part of Risk #2 in [initial-proposal.md](../initial-proposal.md).

**Key finding from RISC Zero work (drives this task's scope):** The outer wrapper circuit bakes the inner public input count into the R1CS at compile time via gnark's `std/recursion/groth16`. RISC Zero has 5 public inputs; SP1 is expected to have 2 (`vkey_hash` and `committed_values_digest`). If confirmed, SP1 requires its own outer circuit, its own trusted setup, and its own adapter — there is no shared wrapper circuit across inner systems. This task must pin that number against real artifacts.

## Scope

In:
- Generate one real SP1 Groth16/BN254 proof for a trivial program (use SP1's built-in example, better the same as we used for risc0). Local CPU prover (`SP1_PROVER=cpu` or via the `cpu` feature in `sp1-sdk`).
- Extract and commit all artifacts needed for downstream verification, mirroring the RISC Zero fixture layout under `experiments/sp1-hello-world/fixtures/`.
- Write a Go script that parses SP1 artifacts into gnark types and verifies them with gnark's BN254 Groth16 verifier standalone (`experiments/sp1-gnark-verifier/verify/`).
- Run the same artifacts through a BLS12-381 outer Groth16 recursive circuit, mirroring `experiments/risc0-gnark-verifier/recursive/` (`experiments/sp1-gnark-verifier/recursive/`).
- Document the artifact format and confirm public input count.

Out:
- Implementing the plugin (deferred to Phase 5).
- Choosing the in-circuit hash function (decided in Phase 2 with both explorations in hand).
- RISC Zero — complete.

## Deliverables

1. **`experiments/sp1-hello-world/`** — Rust workspace mirroring `experiments/risc0-hello-world/`:
   - Guest program: trivial factorization.
   - Host binary `src/bin/dump_groth16.rs`: proves with Groth16 mode (local CPU prover), extracts and writes fixtures, cross-checks with SP1's own verifier.
   - **`fixtures/`** — committed artifact set (keep small; omit any cached prover binaries):
     - `fixtures/README.md` — same format as RISC Zero fixtures README: file table + public input derivation

2. **`experiments/sp1-gnark-verifier/`** — Go module mirroring `experiments/risc0-gnark-verifier/`:

3. **`docs/research/sp1-artifact-format.md`** covering:
   - SP1 version pinned, proving mode (`cpu` local), Groth16 mode flag.
   - Confirmed inner proof system and curve (expected: Groth16/BN254).
   - Proof byte layout: G1/G2 point encoding, endianness, total byte count.
   - VK format: is it fixed per SP1 version (like RISC Zero) or per program? Confirm against artifact.
   - **Public input count and encoding** (confirmed from artifact, not docs). Compare to RISC Zero's 5.
   - Public-values commitment scheme: hash function, preimage, how it becomes a BN254 Fr element.
   - SP1 program vkey: what it is, how it relates to the Groth16 VK, whether it appears as a public input.
   - Conversion recipe: SP1 artifacts → gnark `groth16_bn254.VerifyingKey`, `groth16_bn254.Proof`, `[]fr.Element`.
   - Outer circuit impact: confirmed `innerNPublic` value; explicit note on whether SP1 and RISC Zero can share a wrapper circuit.
   - Any SP1-specific quirks (version pinning, proof mode flags, SDK API surface).

4. **Phase 1 schema summary** — bullet list appended to the research note (or a separate section) listing what the SP1 exploration locks in for the canonical wrapper witness shape and where it diverges from RISC Zero. This feeds directly into the Phase 1 schema lock step in the implementation plan.

## Acceptance criteria

- [ ] An SP1 Groth16/BN254 proof verifies off-chain using SP1's own verifier (cross-check in `dump_groth16.rs`).
- [ ] The same proof is parsed by `experiments/sp1-gnark-verifier/verify/main.go` and gnark's BN254 Groth16 verifier accepts it standalone.
- [ ] `experiments/sp1-gnark-verifier/recursive/main.go` generates and verifies a BLS12-381 outer proof wrapping the SP1 BN254 proof (prints `PASS`, matching the RISC Zero experiment output).
- [ ] `docs/research/sp1-artifact-format.md` exists and answers every bullet in Deliverable 3 with concrete observed values, not speculation from external docs.
- [ ] Public input count is confirmed from the actual artifact (not inferred from SP1 docs) and recorded in the manifest.
- [ ] Any divergence from RISC Zero's shape (different public input count, different commitment scheme, different byte layout) is explicitly called out and the impact on the wrapper circuit design is stated.

## Open questions to track

- **SP1 version to pin** — SP1 is moving fast; pin a specific release for the MVP. Check `sp1-sdk` crate changelog before starting.
- **Public input count** — Expected 2 (`vkey_hash`, `committed_values_digest`), but must be confirmed from the actual artifact. Record the exact count in the manifest.
- **VK structure** — Expected: one fixed Groth16 VK per SP1 version (not per program), with the program identity baked into `vkey_hash` as a public input. Confirm this against the actual VK bytes — if wrong it changes the wrapper design.
- **Proof byte layout** — Does SP1's seal follow the same 256-byte layout as RISC Zero (A:64 B:128 C:64, all big-endian)? SP1 also uses gnark internally, so this is likely yes, but confirm. If the layout differs, the `parse` package needs a different reader.
- **Public values hash** — What hash function does SP1 use to compute `committed_values_digest`? SHA-256? Poseidon? Confirm against the actual artifact by recomputing from `public_values.bin`.
- **Outer circuit reuse** — Is SP1's public input count different from RISC Zero's 5? If yes (expected), explicitly confirm that the two systems need separate outer circuits and separate trusted setups, and note this in the research doc.

## Work order

1. **Rust host** — set up `experiments/sp1-hello-world/`, write guest + `dump_groth16.rs`, run local prover, write + verify fixtures.
2. **Go standalone verifier** — `experiments/sp1-gnark-verifier/parse/` + `verify/main.go`; get `PASS` from gnark BN254 Groth16 verifier.
3. **Go recursive verifier** — `experiments/sp1-gnark-verifier/recursive/main.go`; get `PASS` from BLS12-381 outer proof.
4. **Documentation** — write `docs/research/sp1-artifact-format.md` with all confirmed values; update this task to Done.

## References

- [implementation-plan.md](../implementation-plan.md) — Phase 1 and Phase 5
- [initial-proposal.md](../initial-proposal.md) — Risk #2, Risk #5
- [tasks/risc0-artifact-exploration.md](risc0-artifact-exploration.md) — sister task; keep the deliverable shapes aligned so the final schema can compare them side-by-side
- `experiments/risc0-hello-world/` — reference implementation for the Rust fixture extraction pattern
- `experiments/risc0-gnark-verifier/` — reference implementation for the Go parse + verify + recursive pattern
