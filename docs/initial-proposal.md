# Proposal: Groth16/BN ZK Wrapper Toolkit for Cardano

## Problem

Cardano's ZK ecosystem is isolated from the rest of the blockchain industry. Most external ZK systems (RISC Zero, SP1, Ethereum tooling) produce Groth16/BN254 proofs, but Cardano only natively supports BLS12-381 operations via CIP-0381. This curve mismatch means those ZK systems cannot be used directly on Cardano.

Today, a developer who wants to verify a RISC Zero or SP1 proof on Cardano has no practical path to do so. This blocks cross-chain bridges, ZK coprocessors, and any dApp that wants to leverage the mature zkVM ecosystem.

## Proposed Solution

Build a **Groth16/BN Wrapper Toolkit** — a set of tools that converts Groth16/BN254 proofs into BLS12-381-based proofs verifiable on Cardano, and generates Aiken verifier code for on-chain verification.

The toolkit has three layers:

1. **Wrapper circuit** — an off-chain recursive proof that re-proves a Groth16/BN254 statement over BLS12-381
2. **Plugin system** — adapters for specific proof sources (RISC Zero, SP1, circom, etc.)
3. **Developer tooling** — easy-to-use tools for wrapping proofs and generating Aiken verifiers (form factor TBD — CLI, SDK, or similar; research needed, inspired by snarkjs ergonomics)

### Architecture

```
External ZK Systems
====================
  RISC0      ---> Plugin: risc0-adapter    --+
  SP1        ---> Plugin: sp1-adapter      --+
  circom     ---> Plugin: circom-adapter   --+
  Custom     ---> Plugin: user-defined     --+
                                              |
                              +---------------v--------------+
                              |        Wrapper Core           |
                              |                               |
                              |  Input: Groth16/BN254 proof   |
                              |         + verification key    |
                              |         + public inputs       |
                              |                               |
                              |  Process:                     |
                              |    1. Verify inner proof      |
                              |    2. Hash VK -> VKHash       |
                              |    3. Hash inputs -> InputHash|
                              |                               |
                              |  Backend:           |
                              |    - gnark Groth16/BLS12-381  |
                              |    - gnark PLONK/BLS12-381    |
                              |    - Halo2/BLS12-381          |
                              |                               |
                              |  Output: BLS12-381 proof      |
                              |    Public: VKHash, InputHash  |
                              +---------------+--------------+
                                              |
                              +---------------v--------------+
                              |    Cardano On-Chain            |
                              |                                |
                              |  Generated Aiken verifier:     |
                              |    - BLS12-381 proof verify    |
                              |    - VKHash check              |
                              |                                |
                              |  Deployed per-dApp or as       |
                              |  shared reference script       |
                              +--------------------------------+
```

### Plugin System

Each external proof source has different output formats (proof serialization, public input layout, number of commitments). The plugin system normalizes these differences:

A plugin is responsible for:
1. Parsing the proof source's native output format into a canonical Groth16/BN254 representation
2. Handling any source-specific public input compression (e.g., RISC Zero's journal hashing)
3. Providing metadata so the wrapper core can validate compatibility

Built-in plugins for the initial release: **RISC Zero** and **SP1**. The plugin interface is public so third parties (or future work) can add adapters for circom, Ethereum contract proofs, etc.

### Wrapper Core

The wrapper circuit is compiled and set up once. It accepts any Groth16/BN254 proof with a fixed public input shape (1 hash) and re-proves it over BLS12-381.

**Outer circuit design:**

- Public inputs: `VKHash = hash(inner_VK)`, `InputHash = hash(inner_public_inputs)`
- Secret witnesses: inner VK, inner proof, inner public inputs
- Constraints: (1) Groth16.Verify(inner), (2) InputHash check


**Public input compression convention (can be relaxed):** inner circuits should hash all real public inputs into a single field element. This keeps the wrapper circuit fixed — one setup covers all inner circuits regardless of their complexity.

**Outer proving backend options (possibly pluggable - to be further evaluated):**

| Backend | Prove time | Pros | Cons |
|---|---|---|---|
| gnark Groth16/BLS12-381 | ~5s (20 cores) | Fast proving, small proof, benchmarked | Trusted setup required |
| gnark PLONK/BLS12-381 | ~50s (20 cores) | Universal setup, benchmarked | 10x slower proving, larger proofs |
| Halo2/BLS12-381 | TBD (not yet benchmarked) | Universal setup, Rust ecosystem | Needs benchmarking, potentially larger proofs |

The wrapper core should abstract over the proving backend so multiple options can coexist. **gnark Groth16** is the most proven starting point; **PLONK** and **Halo2** are attractive for avoiding trusted setup and should be evaluated as an alternative.

### On-Chain Verifier Generation

The toolkit generates Aiken verifier code matched to the chosen outer proving backend. Existing work from the snarkjs-Aiken integration (Groth16/BLS12-381, PLONK/BLS12-381 Aiken verifiers) can be adapted and extended. The generated verifier uses CIP-0381 builtins (millerLoop, finalVerify, G1 scalar mul) and can be deployed per-dApp or as a shared reference script, depending on the use case.

### Developer Tooling

The exact form factor for developer tooling is an open research question. The goal is snarkjs-level ergonomics: a developer should be able to wrap a proof and generate an Aiken verifier with minimal steps. Options to investigate include a CLI tool, a language-specific SDK, or a combination. This will be determined during the research phase.

## Deliverables

| # | Deliverable | Description |
|---|---|---|
| 1 | Wrapper circuit (gnark, halo2, or other) | Groth16/BN254 → BLS12-381-based recursive verifier with VKHash + InputHash public outputs. Groth16, PLONK, or Halo2 as outer backend |
| 2 | RISC Zero plugin | Adapter parsing RISC Zero's Groth16/BN254 output into wrapper input |
| 3 | SP1 plugin | Adapter parsing SP1's Groth16/BN254 output into wrapper input |
| 4 | Aiken verifier generation | Generate Aiken on-chain verifier code for the wrapped proof (adapt from snarkjs-Aiken work) |
| 5 | Halo2 backend investigation | Evaluate Halo2/BLS12-381 as alternative wrapper backend, benchmark, compare with gnark options |
| 6 | Wrapper tooling | Investigate best form factor for developer-facing tools (CLI, SDK, language choice), prototype |
| 7 | End-to-end demos | RISC Zero → Cardano and SP1 → Cardano working examples with documentation |

## Expected Impact

- **Unblocks the entire zkVM ecosystem for Cardano.** Any proof system that outputs Groth16/BN254 (the de facto industry standard) becomes Cardano-compatible through the wrapper.
- **Enables cross-chain ZK bridges.** Ethereum state proofs, RISC Zero Bonsai proofs, SP1 proofs — all can be verified on Cardano, enabling trustless bridges and interoperability.
- **Lowers the barrier for ZK development on Cardano.** Easy-to-use tooling means developers don't need to understand recursive proof internals or CIP-0381 builtins directly.
- **Extensible via plugins.** New proof sources can be added without modifying the core wrapper.

## Risks and Open Questions

1. **Cardano execution budget.** BLS12-381 proof verification requires multiple pairing operations and G1 scalar multiplications. Must confirm this fits within per-transaction execution limits. CIP-0133 (MSM optimization) could significantly help if adopted. This is especially relevant for Halo2-based wrapper. Also not clear which version of PLONK is used in gnark and how efficient the Aiken verifier for it will be.

2. **RISC Zero / SP1 proof format compatibility.** Must verify that the Groth16/BN254 output from these systems matches what the wrapper expects: number of public inputs, commitment scheme, proof serialization format. Both systems should compress to 1 public input (journal/IO hash), which aligns with the wrapper design.

3. **Trusted setup.** The gnark Groth16 backend requires a per-circuit trusted setup. Options: (a) run an MPC ceremony, (b) use the PLONK backend (universal SRS, no per-circuit setup), (c) use Halo2 (universal SRS).

4. **Outer backend selection.** The trade-off between proving speed (Groth16 ~5s vs PLONK ~50s), setup requirements, and proof size needs to be evaluated in context of real-world usage patterns. Halo2 benchmarks are needed to complete the comparison.

5. **Inner circuit public input convention.** The wrapper requires inner circuits to compress all public inputs into a single hash. Investigate if RISC Zero and SP1 already do this (see journal hash / IO hash). The plugin system may handle both compressed and multi-input cases, potentially requiring multiple wrapper circuit configurations.

6. **Tooling form factor.** The best language and interface for the developer tooling is TBD. Go (native gnark integration), Rust (Halo2, ecosystem fit), JS/TS (web developer reach) are all candidates. Needs prototyping and user feedback.

## Success Criteria

1. A developer can take a RISC Zero or SP1 proof, wrap it, and verify it on Cardano with minimal tooling friction
2. End-to-end latency (proof wrapping + tx submission) under 60 seconds
3. On-chain verification fits within Cardano execution budgets
4. At least 2 working end-to-end demos (RISC Zero → Cardano, SP1 → Cardano)
