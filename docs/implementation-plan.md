# Groth16/BN Wrapper Toolkit — Implementation Plan

Step-by-step plan for delivering [initial-proposal.md](initial-proposal.md). Each phase gates on the previous one; the critical path to a meaningful demo is Phase 1 → 2 → 3.

## Phase 0 — Feasibility (DONE)

The two load-bearing assumptions are already validated:

- **gnark can verify Groth16/BN254 inside BLS12-381 in ~5s.** Benchmarked at 840,199 R1CS constraints, 5.26s prove time, 2.4 GB RAM on 20 cores. PLONK/BLS12-381 outer also benchmarked at 51.3s. See [gnark-recursive-verification-benchmarks.md](gnark-recursive-verification-benchmarks.md). Bench repo: https://github.com/dkaidalov/gnark.
- **Groth16/BLS12-381 verification fits Cardano execution budgets.** Already demonstrated by the snarkjs-Aiken pipeline. See [snarkjs-cardano-aiken-verifiers.md](snarkjs-cardano-aiken-verifiers.md).

## Phase 1 — Wrapper circuit MVP (gnark Groth16/BLS12-381)

Pick gnark Groth16/BLS12-381 as the first outer backend (fastest, best-documented; benchmarks already validate it). Defer PLONK and Halo2 to Phase 5.

1. Define the canonical inner-proof shape: `(VK, proof, public_inputs_hash)` with `public_inputs_hash` as a single BN254 field element.
2. Implement the outer circuit with public outputs `VKHash = hash(VK)` and `InputHash = public_inputs_hash`. Constraints: (a) Groth16.Verify over BN254 via emulated arithmetic, (b) hash-of-VK matches `VKHash`. Pick the in-circuit hash carefully — Poseidon over the BLS12-381 scalar field is the obvious choice; whatever inner circuits use must match.
3. Run trusted setup once. Save proving key, verification key, SRS.
4. Generate an outer proof from a hand-crafted inner Groth16/BN254 proof (trivial inner circuit). Verify off-chain with gnark.

**Exit:** end-to-end off-chain prove + verify on a synthetic inner proof, with documented prove time and proof size.

## Phase 2 — Aiken verifier generation

1. Adapt the existing snarkjs-Aiken Groth16/BLS12-381 verifier as the template.
2. Add the `VKHash` check. Decide: hardcoded constant baked at codegen (simpler, per-dApp deployments) vs read from datum/redeemer (needed for shared reference scripts).
3. Build a thin codegen tool that takes the outer VK and emits a ready-to-compile Aiken module. Template-based; don't over-engineer.
4. Deploy the generated verifier to Cardano preview testnet. Verify a real outer proof from Phase 1. Measure execution units against the per-tx budget.

**Exit:** a Phase 1 proof verifies on Cardano preview, execution units recorded.

## Phase 3 — First plugin: RISC Zero, end-to-end

This is the first real demo. Hold off on SP1 — RISC Zero will surface lessons that simplify SP1.

1. **Audit the RISC Zero output format first.** Pull a real proof, deserialize, confirm Groth16/BN254 + 1 public input that's a hash of the journal. This was originally Phase 0 work; do it here where it's actionable.
2. Generate a real RISC Zero proof for a small program (SHA preimage or Fibonacci). Bonsai or local proving — whichever is faster.
3. Build the RISC Zero plugin: parses RISC Zero's proof bundle into `(VK, proof, journal)`, computes the journal hash, emits the canonical `(VK, proof, public_inputs_hash)` triple expected by the wrapper.
4. Feed the plugin output to the Phase 1 wrapper. Generate the outer BLS12-381 proof.
5. Generate the matching Aiken verifier (Phase 2) and submit to preview testnet.

**Exit:** a transaction on preview that verifies a RISC Zero zkVM execution. Document the full pipeline (commands, files, timings) — this becomes the tutorial.

**Critical risk to resolve here:** the in-circuit hash function used to commit to inner public inputs must match what the plugin uses to compress the RISC Zero journal. RISC Zero uses SHA-256 for journal hashing; if the wrapper uses Poseidon, the plugin must either (a) re-hash with Poseidon outside the circuit and pass through, or (b) the wrapper must verify SHA-256 in-circuit (expensive). Decide before implementing the plugin.

## Phase 4 — Second plugin: SP1

Same pattern as Phase 3, applied to SP1. First step: audit SP1's output format the same way (curve, public input shape, hash function).

Most of the work should be plugin-only — wrapper circuit and verifier reuse from Phases 1–2. With two implementations in hand, this is the right point to extract a stable plugin trait/interface for third parties.

**Exit:** matching demo for SP1, plus documented plugin interface.

## Phase 5 — Alternative backends

Now that the gnark Groth16 path is end-to-end, evaluate alternatives without blocking on them.

1. **gnark PLONK/BLS12-381.** Swap the outer prover. Reuse the wrapper circuit. Use the existing snarkjs-Aiken PLONK/BLS12-381 verifier on-chain. Benchmarks already exist: 51.3s prove, 8.2 GB RAM, 2.76M PLONK gates ([gnark-recursive-verification-benchmarks.md](gnark-recursive-verification-benchmarks.md)). Confirm which PLONK variant gnark uses — affects Aiken verifier compatibility.
2. **Halo2/BLS12-381.** Real research deliverable, not a swap. Halo2 over BLS12-381 is less mature; needs its own benchmark of in-circuit BN254 Groth16 verification, plus a new Aiken verifier (doesn't exist from snarkjs-Aiken work). Parallel track; don't block other deliverables on it.
3. Pick a backend per use case based on data:
   - Trusted setup acceptable + need speed → gnark Groth16
   - Universal SRS, prove time can be slower → gnark PLONK
   - Trustless setup + Rust ecosystem fit → Halo2 (if benchmarks justify)

**Exit:** comparison table with measured numbers, recommendation per use case.

## Phase 6 — Developer tooling form factor

Defer until at least Phase 3 exists — can't design ergonomics for an unshipped pipeline.

1. From Phase 3 + 4 demos, extract the actual command sequence.
2. Prototype as a Go CLI first (closest to gnark, lowest friction). Likely commands:
   - `zkwrap setup` — one-time outer trusted setup
   - `zkwrap wrap --plugin risc0 --proof <path> --vk <path>` — produces an outer proof
   - `zkwrap gen-verifier --vk <outer-vk> --out <dir>` — emits Aiken module
3. Get feedback from one or two real users (RISC Zero or SP1 devs trying to ship to Cardano). Then decide whether an SDK or JS/TS port is worth the cost. Don't build all three speculatively.

**Exit:** working CLI that reproduces the Phase 3 demo with three commands.

## Phase 7 — Polish and demos

1. Two documented end-to-end demos: RISC Zero and SP1, both on preview testnet with reproducible scripts.
2. Tutorial: from "I have a RISC Zero program" to "verified on Cardano".
3. Decide deployment model: per-dApp script vs shared reference script. Reference script likely wins on cost, but only if `VKHash` is dynamic — connects back to a Phase 2 decision.
4. If the trusted-setup ceremony route is chosen, plan the MPC ceremony as a separate sub-project — coordination overhead, shouldn't block code delivery.

## Critical path

Phase 1 → 2 → 3 is the shortest path to a meaningful demo. Phase 4 is mostly parallel work once the plugin interface is clear. Phase 5 (alternative backends) and Phase 6 (tooling polish) are deferrable.

## Top remaining risk

Hash function compatibility between the wrapper's in-circuit hash and each plugin's journal/IO compression — flagged in Phase 3, applies again in Phase 4. Resolve per-plugin before implementing it.
