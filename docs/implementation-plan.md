# Groth16/BN Wrapper Toolkit - Implementation Plan

Step-by-step plan for delivering [initial-proposal.md](initial-proposal.md). Each phase gates on the previous one; the critical path to a meaningful demo is Phase 1 -> 2 -> 3 -> 4.

> **Current phase:** Phase 2 complete. Phase 3 next. See [journal.md](journal.md) for latest status.
> Update this marker whenever a phase begins or completes.

## Phase 0 - Feasibility (DONE)

The two load-bearing assumptions are already validated:

- **gnark can verify Groth16/BN254 inside BLS12-381 in ~5s.** Benchmarked at 840,199 R1CS constraints, 5.26s prove time, 2.4 GB RAM on 20 cores. PLONK/BLS12-381 outer also benchmarked at 51.3s. See [gnark-recursive-verification-benchmarks.md](research/gnark-recursive-verification-benchmarks.md). Bench repo: https://github.com/dkaidalov/gnark.
- **Groth16/BLS12-381 verification fits Cardano execution budgets.** Already demonstrated by the snarkjs-Aiken pipeline. See [snarkjs-cardano-aiken-verifiers.md](research/snarkjs-cardano-aiken-verifiers.md).

## Phase 1 - Source proof compatibility exploration (DONE)

Before freezing the wrapper circuit and input format, explore real proof artifacts from the first target systems. This prevents late surprises around public input count, hash conventions, VK formats, byte order, or versioned verifier keys.

**RISC Zero — done:**
- Generated a real Groth16/BN254 proof (RISC Zero zkVM 3.0.5, local CPU proving).
- Verified fixtures end-to-end with gnark BN254 Groth16 verifier and BLS12-381 recursive wrappers (Groth16 and PLONK outer). See `experiments/risc0-gnark-verifier/`.
- Documented artifact format: `docs/research/risc0-artifact-format.md`.

**SP1 — done:**
- Generated a real Groth16/BN254 proof (SP1 v3.4.0, local CPU proving, `native-gnark` feature).
- Verified fixtures end-to-end with gnark BN254 Groth16 verifier and BLS12-381 recursive wrappers (Groth16 and PLONK outer). See `experiments/sp1-gnark-verifier/`.
- Documented artifact format: `docs/research/sp1-artifact-format.md`.

**Schema lock — done:**
- Compared RISC Zero (5 inputs) and SP1 (2 inputs) artifact shapes. Key divergences: input count, VK format (JSON vs binary), public input encoding (hex vs decimal).
- Decided: universal wrapper circuit with configurable `MAX_INPUTS` constant; excess inputs padded to zero; Aiken validator per inner system checks the padded slots. See `docs/adr/0002-universal-wrapper-circuit.md`.
- Decided: inner public inputs exposed as direct outer public signals `[VKHash, input_0..input_{MAX-1}]`, no hash commitment. See `docs/adr/0001-direct-outer-public-signals.md`.
- Canonical inner proof format locked: `docs/schemas/canonical-inner-proof.md`.
- File-based boundary between Rust plugin and Go prover: `docs/adr/0003-file-based-plugin-prover-boundary.md`.
- Domain language captured: `CONTEXT.md`.

**Exit criteria met:** both proofs verified in gnark standalone, witness schema locked.

## Phase 2 - Wrapper circuit MVP (gnark Groth16/BLS12-381) (DONE)

Pick gnark Groth16/BLS12-381 as the first outer backend (fastest, best-documented; benchmarks already validate it). Defer PLONK and Halo2 to Phase 6.

**Outer circuit public inputs design** (settled in Phase 1 schema lock):
- Public signals: `[VKHash, input_0, ..., input_{MAX_INPUTS-1}]`
- `VKHash` = in-circuit Poseidon hash (over BLS12-381 Fr) of the inner VK field elements. Hash function choice is gnark-only — the Aiken validator never recomputes it, it only checks `proof_signal[0] == hardcoded_constant`. Poseidon is the right choice: native BLS12-381 field operations, cheapest in-circuit.
- `input_0..input_{MAX_INPUTS-1}` = inner public inputs wired through directly as outer public signals, padded with zero for unused slots
- Inner VK and inner proof remain private witnesses

**Steps:**
1. Benchmark the outer circuit constraint count for several `MAX_INPUTS` values (5, 8, 16). Record prove time and RAM. Pick `MAX_INPUTS` and commit it — this value is fixed for the trusted setup lifetime. Add the chosen value to `docs/adr/0002-universal-wrapper-circuit.md`.
2. Extend the existing `OuterCircuit` struct to add public inputs: wire `VKHash` and `input_0..input_{MAX_INPUTS-1}` as `frontend.Variable` with `gnark:",public"`. Add constraints: (a) Groth16.Verify over BN254 (already working from Phase 1 experiments), (b) in-circuit hash of inner VK bytes matches `VKHash`, (c) inner public inputs are passed through to the public signal slots with zero-padding for unused slots.
3. Run trusted setup once with the final `MAX_INPUTS`. Save proving key, verification key, SRS to `wrapper/gnark-groth16/`.
4. Generate an outer proof from a real RISC Zero or SP1 inner proof (Phase 1 fixtures). Verify off-chain with gnark. Confirm `VKHash` and all five input slots appear correctly in the outer proof's public witness.

**Exit:** end-to-end off-chain prove + verify against a real Phase 1 inner proof, with documented prove time, proof size, and `MAX_INPUTS` value recorded in the ADR.

## Phase 3 - Aiken validator generation

Aiken codegen lives in each Rust plugin crate, not in the Go prover binary. See ADR-0004.

Each generated Aiken validator has two layers:
- **Layer 1 (generic):** BLS12-381 Groth16 verification — outer VK points embedded as constants, pairing check, IC accumulation over the outer public inputs `[VKHash, input_0..input_{MAX-1}]`, plus the Pedersen commitment check (Bowe–Gabizon) the recursive wrapper requires: one extra pairing equation `e(commitment_pok, g) == e(commitment, g_sigma_neg)` and one SHA-256 hash-to-Fr that folds the commitment into the public inputs. See `docs/schemas/outer-proof-artifacts.md` for the exact fields.
- **Layer 2 (system-specific):** `VKHash` constant check; excess-zero slot enforcement (e.g., SP1 checks `input_2..input_4 == 0`); journal authentication chain so the validator can verify raw application outputs from the outer public inputs without trusting off-chain code.

Journal auth per system:
- **RISC Zero:** ~4 SHA-256 calls following `tagged_struct` (`SHA256(SHA256(tag) ‖ children ‖ u32s_LE ‖ count_LE)`). Tag digests (`"risc0.ReceiptClaim"`, `"risc0.Output"`) are constants baked into the Aiken module. Result matches `inputs[2,3]` via split_digest. All SHA-256 — Cardano native builtin.
- **SP1:** 1 SHA-256 call: `SHA256(public_values_bytes) == inputs[1]`.

**Steps:**
1. Compatibility spike in `experiments/aiken-verifier-spike/`: generate one gnark Groth16/BLS12-381 outer proof (Phase 2 artifacts) and hand-write an Aiken verifier for it. Starting point: copy + adapt the snarkjs-Aiken generic BLS12-381 Groth16 verifier (see `docs/research/snarkjs-cardano-aiken-verifiers.md`). Add the Pedersen-commitment check and the IC layout for `[VKHash, inputs..., commit_fr]`. Confirm serialization, point signs, IC ordering, field encodings, and execution units on preview.
2. Build the Layer 1 Aiken template (generic BLS12-381 verifier). Parameterised by: outer VK points, `MAX_INPUTS`, commitment-keys.
3. Build Layer 2 for RISC Zero in `zkwrap-risc0`: `VKHash` constant, `n_real = 5` (no excess zero-checks), journal auth chain from `tagged_struct`.
4. Expose `gen_aiken_validator(outer_vk_bytes: &[u8], config: &InnerSystemConfig) -> String` in `zkwrap-risc0`. Embed `outer_vk.bin` from Phase 2 trusted setup via `include_bytes!`.
5. Aiken testing. Verify with Aiken unit tests a real Phase 2 outer proof. Measure execution units.

**Exit:** a Phase 2 proof verifies on Cardano preview with journal auth, execution units recorded.

## Phase 4 - First plugin: RISC Zero, end-to-end

This is the first real demo. Hold off on SP1 - RISC Zero will surface lessons that simplify SP1.

1. Generate a real RISC Zero proof for a small program (SHA preimage or Fibonacci). Bonsai or local proving - whichever is faster.
2. Build the RISC Zero plugin (`zkwrap-risc0`, Rust library crate): takes a `Receipt`, validates it is a Groth16 receipt, extracts the proof bundle, validates the public inputs against the receipt claim, and writes the canonical inner proof directory to disk. Also exposes `gen_aiken_validator` (see Phase 3). Host programs import the crate directly, mirroring `risc0-ethereum` ergonomics. The Go/Rust language boundary is handled by the file-based IPC convention (ADR-0003): the Rust plugin writes files, the Go prover binary reads them.
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
