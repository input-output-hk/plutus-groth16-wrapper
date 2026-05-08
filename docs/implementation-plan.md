# Groth16/BN Wrapper Toolkit - Implementation Plan

Step-by-step plan for delivering [initial-proposal.md](initial-proposal.md). Each phase gates on the previous one; the critical path to a meaningful demo is Phase 1 -> 2 -> 3 -> 4.

> **Current phase:** Phase 0 complete (feasibility validated). Phase 1 not yet started - no source code committed.
> Update this marker whenever a phase begins or completes. Cross-check against the latest entry in [journal.md](journal.md) for in-flight work.

## Phase 0 - Feasibility (DONE)

The two load-bearing assumptions are already validated:

- **gnark can verify Groth16/BN254 inside BLS12-381 in ~5s.** Benchmarked at 840,199 R1CS constraints, 5.26s prove time, 2.4 GB RAM on 20 cores. PLONK/BLS12-381 outer also benchmarked at 51.3s. See [gnark-recursive-verification-benchmarks.md](research/gnark-recursive-verification-benchmarks.md). Bench repo: https://github.com/dkaidalov/gnark.
- **Groth16/BLS12-381 verification fits Cardano execution budgets.** Already demonstrated by the snarkjs-Aiken pipeline. See [snarkjs-cardano-aiken-verifiers.md](research/snarkjs-cardano-aiken-verifiers.md).

## Phase 1 - Source proof compatibility exploration

Before freezing the wrapper circuit and input format, explore real proof artifacts from the first target systems. This prevents late surprises around public input count, hash conventions, VK formats, byte order, or versioned verifier keys.

1. Generate one real Groth16/BN254 proof from RISC Zero and one from SP1.
2. For each source, document:
   - proof system and curve
   - proof byte layout and endianness
   - verification key format and versioning rules
   - public input count and field encoding
   - journal/public-values hash function
   - how to convert the proof, VK, and public inputs into gnark witness types; document this precisely enough to serve as the implementation spec for the Phase 4 plugin library
3. Confirm whether each source can fit one shared wrapper circuit shape.
4. Lock the MVP canonical witness format before setup. Preferred shape: secret witnesses are `(inner_VK, inner_proof, inner_public_inputs)`; public outputs are `(VKHash, InputCommitment)`. The circuit must verify the inner proof against the actual inner public inputs, then commit to those inputs.

**Exit:** documented RISC Zero and SP1 artifact schemas, plus a final MVP wrapper input/output schema.

## Phase 2 - Wrapper circuit MVP (gnark Groth16/BLS12-381)

Pick gnark Groth16/BLS12-381 as the first outer backend (fastest, best-documented; benchmarks already validate it). Defer PLONK and Halo2 to Phase 6.

1. Implement the canonical witness shape selected in Phase 1.
2. Implement the outer circuit with public outputs `VKHash = hash(VK)` and `InputCommitment = hash(inner_public_inputs)`. Constraints: (a) Groth16.Verify over BN254 via emulated arithmetic using the actual inner public inputs, (b) hash-of-VK matches `VKHash`, (c) hash/commitment of inner public inputs matches `InputCommitment`. Pick the in-circuit hash carefully - Poseidon over the BLS12-381 scalar field is the obvious starting point, but the external digest-to-field convention must match Phase 1.
3. Run trusted setup once. Save proving key, verification key, SRS.
4. Generate an outer proof from a hand-crafted inner Groth16/BN254 proof (trivial inner circuit). Verify off-chain with gnark.

**Exit:** end-to-end off-chain prove + verify on a synthetic inner proof, with documented prove time and proof size.

## Phase 3 - Aiken verifier generation

1. Adapt the existing snarkjs-Aiken Groth16/BLS12-381 verifier as the template.
2. Add the `VKHash` check. Decide: hardcoded constant baked at codegen (simpler, per-dApp deployments) vs read from datum/redeemer (needed for shared reference scripts).
3. Add a gnark-to-Aiken compatibility spike before full codegen: generate one gnark Groth16/BLS12-381 proof and make the adapted Aiken verifier pass locally, confirming serialization, point signs, IC ordering, and field encodings.
4. Build a thin codegen tool that takes the outer VK and emits a ready-to-compile Aiken module. Template-based; don't over-engineer.
5. Deploy the generated verifier to Cardano preview testnet. Verify a real outer proof from Phase 2. Measure execution units against the current per-tx budget.

**Exit:** a Phase 2 proof verifies on Cardano preview, execution units recorded.

## Phase 4 - First plugin: RISC Zero, end-to-end

This is the first real demo. Hold off on SP1 - RISC Zero will surface lessons that simplify SP1.

1. Generate a real RISC Zero proof for a small program (SHA preimage or Fibonacci). Bonsai or local proving - whichever is faster.
2. Build the RISC Zero plugin: takes a `Receipt`, validates it is a Groth16 receipt, extracts the proof bundle, computes/validates the public input commitment, and emits the canonical wrapper witness. Plugin form factor is **not yet decided** — evaluate before Phase 4 starts:
   - **Rust library crate** (`risc0-zkwrap`): host programs import it directly, mirroring `risc0-ethereum` ergonomics. Study `risc0-ethereum` as the reference. Requires solving the Go/Rust boundary for the gnark proving step (subprocess or bundled binary — both add distribution complexity; see Phase 7 note).
   - **Standalone CLI tool**: simpler to ship initially; host programs call it as a separate step. Less ergonomic but avoids the language boundary problem.
   - Decide based on Phase 4 experience and user feedback.
3. Feed the plugin output to the Phase 2 wrapper (gnark, Go). Generate the outer BLS12-381 proof.
4. Generate the matching Aiken verifier (Phase 3) and submit to preview testnet.

**Exit:** a transaction on preview that verifies a RISC Zero zkVM execution. Document the full pipeline (commands, files, timings) - this becomes the tutorial.

**Critical risk to re-check here:** the RISC Zero plugin must not merely hash the journal off-chain; it must preserve the binding between the RISC Zero receipt claim, journal, image ID, and the public inputs verified inside the wrapper.

## Phase 5 - Second plugin: SP1

Same pattern as Phase 4, applied to SP1. The artifact exploration is already done in Phase 1, so this phase should mainly implement and test the SP1 adapter.

Most of the work should be plugin-only - wrapper circuit and verifier reuse from Phases 2-3. With two implementations in hand, this is the right point to extract a stable plugin trait/interface for third parties.

**Exit:** matching demo for SP1, plus documented plugin interface.

## Phase 6 - Alternative backends

Now that the gnark Groth16 path is end-to-end, evaluate alternatives without blocking on them.

1. **gnark PLONK/BLS12-381.** Swap the outer prover. Reuse the wrapper circuit. Use the existing snarkjs-Aiken PLONK/BLS12-381 verifier on-chain. Benchmarks already exist: 51.3s prove, 8.2 GB RAM, 2.76M PLONK gates ([gnark-recursive-verification-benchmarks.md](research/gnark-recursive-verification-benchmarks.md)). Confirm which PLONK variant gnark uses - affects Aiken verifier compatibility.
2. **Halo2/BLS12-381.** Real research deliverable, not a swap. Halo2 over BLS12-381 is less mature; needs its own benchmark of in-circuit BN254 Groth16 verification, plus a new Aiken verifier (doesn't exist from snarkjs-Aiken work). Parallel track; don't block other deliverables on it.
3. Pick a backend per use case based on data:
   - Trusted setup acceptable + need speed -> gnark Groth16
   - Universal SRS, prove time can be slower -> gnark PLONK
   - Trustless setup + Rust ecosystem fit -> Halo2 (if benchmarks justify)

**Exit:** comparison table with measured numbers, recommendation per use case.

## Phase 7 - Developer tooling form factor

Defer until at least Phase 4 exists - can't design ergonomics for an unshipped pipeline.

1. From Phase 4 + 5 demos, extract the actual command sequence.
2. Prototype as a Go CLI first (closest to gnark, lowest friction). Likely commands:
   - `zkwrap setup` - one-time outer trusted setup
   - `zkwrap wrap --plugin risc0 --proof <path> --vk <path>` - produces an outer proof
   - `zkwrap gen-verifier --vk <outer-vk> --out <dir>` - emits Aiken module
   - **Alternative form factor:** the gnark circuit and proving logic must stay in Go (gnark is a Go DSL), but the user-facing CLI could be a Rust binary that calls a compiled Go gnark binary as a subprocess over a JSON stdio protocol. Evaluate after Phase 4 exists — if Rust is preferred for distribution, ergonomics, or Cardano ecosystem fit, the two-binary model is straightforward.
3. Get feedback from one or two real users (RISC Zero or SP1 devs trying to ship to Cardano). Then decide whether an SDK or JS/TS port is worth the cost. Don't build all three speculatively.

**Exit:** working CLI that reproduces the Phase 4 demo with three commands.

## Phase 8 - Polish and demos

1. Two documented end-to-end demos: RISC Zero and SP1, both on preview testnet with reproducible scripts.
2. Tutorial: from "I have a RISC Zero program" to "verified on Cardano".
3. Decide deployment model: per-dApp script vs shared reference script. Reference script likely wins on cost, but only if `VKHash` is dynamic - connects back to a Phase 3 decision.
4. If the trusted-setup ceremony route is chosen, plan the MPC ceremony as a separate sub-project - coordination overhead, shouldn't block code delivery.

## Critical path

Phase 1 -> 2 -> 3 -> 4 is the shortest path to a meaningful demo. Phase 5 is mostly parallel work once the plugin interface is clear. Phase 6 (alternative backends) and Phase 7 (tooling polish) are deferrable.

## Top remaining risk

Hash function compatibility between the wrapper's in-circuit hash and each plugin's journal/IO compression - resolved structurally in Phase 1, then re-checked during Phases 4 and 5 against real end-to-end proofs.
