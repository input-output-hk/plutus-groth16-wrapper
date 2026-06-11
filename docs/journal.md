# Project Journal

Chronological working notes for the Groth16/BN wrapper toolkit.

Use this file for day-to-day progress, experiment notes, open questions, links to artifacts, and short summaries of what changed. It is intentionally more verbose and informal than `docs/decisions/`.

Use `docs/decisions/` when a choice should become durable project policy. If a journal entry leads to a durable decision, add a decision record and link it from the journal entry.

## Entry Format

```md
## YYYY-MM-DD - Short Title

Possible sub-sections (not mandatory, see what fit better for particular entry):
- Context:
- Work done:
- Findings:
- Open questions:
- Links:
```
Always add new journal entries at the top.

## 2026-06-11 — Phase 4: RISC Zero `canonicalize` + shared `fixtures/` reorg

**`canonicalize` — the plugin's serializer half.** Added `zkwrap_risc0::canonicalize`:
native RISC Zero `Receipt` → canonical inner-proof bundle, I/O-free, with a
`Canonicalized::write_to` that persists `vk.bin`/`proof.bin`/`public_inputs.bin`/`meta.json`.
It `verify`s the receipt against `image_id` first, takes the 256-byte seal as the proof,
decodes the fixed risc0 Groth16 VK through ark into the canonical layout, and rebuilds the
5 BN254 public inputs (split-digest of `control_root` and `claim_digest`, plus
`Fr(reverse(bn254_control_id))`). The per-guest `codegen` section rides alongside as a field
of `Canonicalized`, *not* inside `CanonicalInnerProof` — the latter stays the pure,
system-agnostic crypto contract (ADR-0007). An oracle test canonicalizes the committed
hello-world receipt and asserts byte-equality with both the committed bundle and the Go
`gen-testdata` output. The risc0 stack is an unconditional dep (Linux-only C++ kernels;
tests run under WSL).

**Shared `fixtures/` reorg.** `zkwrap-gnark/testdata/` had quietly become a cross-language
fixture store — read by both Go and Rust, and reached into from `experiments/` by the new
`canonicalize` test. Lifted it to a repo-root `fixtures/` tree organized by domain
(`risc0-hello-world/`, `canonical-inner/`, `groth16-setup/`, `groth16-outer-proof.json`) and
copied the risc0 raw artifacts in so the shipped crates stop reaching into `experiments/`.
Repointed every Go/Rust reader and the `gen-testdata` defaults, moved the gitignore rule, and
fixed a stale `dump_vectors_test` output path. The Poseidon2 KAT vectors stay embedded in
`zkwrap-core` (compile-time unit-test oracle, not a runtime fixture). Verified: full Rust
workspace + Go green (incl. the 239 s setup→prove→verify integration); `gen-testdata`
reproduces the bundle byte-for-byte.

Links:
- `zkwrap-rs/zkwrap-risc0/src/canonicalize.rs`, `fixtures/README.md`
- `docs/schemas/canonical-inner-proof.md`, ADR-0007

## 2026-06-10 — Prover invocation model (preliminary ADR-0008)

Wrote a **preliminary** ADR-0008 to capture a constraint before it bites: loading the ~1 GB
proving key from disk dominates wall-clock (~40 s, vs ~7 s for proving itself), so a
long-lived prover *service* is the likely target. The sketch keeps a transport-neutral
serialization (the canonical inner bundle) behind a `Prover` abstraction — `CliProver` now,
`ServiceProver` (RPC/HTTP) later — so the disk-bound path can be swapped without touching
callers. Flagged explicitly as provisional (the `zkwrap-prover` driver-crate placement and the
service protocol are open). This is what shaped `canonicalize` into an I/O-free core plus a thin
`write_to`, so a host can wrap in-memory without staging to disk.

## 2026-06-02 — Rust `InnerVKHash` cross-check

Added a pure-Rust Poseidon2-MD/BLS12-381 + `InnerVKHash` reimplementation in
`zkwrap-core` (`poseidon2.rs`, `vk_hash.rs`), matching gnark-crypto limb-for-limb;
round-trips to `0c42ca6b…bbe8e6ca` on the real RISC Zero fixture. Vectors are dumped from
the gnark reference (`go test ./internal/circuit -run TestDumpVKHashVectors -dump-vectors`)
into `testdata/inner_vk_hash_vectors.json`.

Decided it is **cross-check only, not the codegen path**: Aiken codegen reads `inner_vk_hash`
straight from the gnark prover output (`outer_proof.json`), so gnark stays the single source
of truth and we avoid a second production hash impl that must agree forever. The Rust twin
exists to catch a *silent `gnark-crypto` Poseidon2 change*. This resolves ADR-0005's deferred
"Rust vs Go helper" question (ADR-0005 updated).

## 2026-06-01 — Verifier CPU Optimization Attempts

Tried two CPU optimizations on the spike verifier; kept one, dropped one.

**Kept — zero-input IC skip.** `compute_vk_x` now elides the `uncompress + scalar_mul + add` for any public-input slot whose scalar is 0 (sound: `0·P = O`). RISC Zero's `n_real = 5` always leaves 3 zero-padded slots under `MAX_INPUTS = 8`. Saved **390 M CPU** (4.28 B → 3.89 B), i.e. ~130 M per IC term. Note: data-dependent — a proof filling all 8 slots gets no benefit, so worst-case budget is still ~4.28 B.

**Dropped — random-batched pairing.** Folding the Pedersen PoK and Groth16 checks into one `final_verify` via a Fiat-Shamir scalar saved only **170 M** (3.89 B → 3.72 B): one `final_verify` (~430 M) is mostly offset by the two added `g1_scalar_mul`s (~260 M) needed to scale `commitment` and `pok` by `r`. Hashing less in the challenge can't help — the hash is ~5 M (noise), and soundness requires `r` to bind all prover-chosen values (`A, B, C, commitment, pok`), so the transcript can't shrink. Not worth the harder soundness story (RO + Schwartz–Zippel) for ~4.5%. Plain `verify` stays the lead — it mirrors gnark `verify.go` 1:1.

**Cost-model finding:** `bls12_381_g1_scalar_mul` has ~constant CPU (~130 M) regardless of scalar bit-length — truncating `r` to 128 bits changed nothing. The pairing floor is 6 miller loops; `e(α,β)` can't be precomputed (no GT constant/literal in Plutus V3).

## 2026-06-01 — Phase 3 Step 1: Aiken Verifier Spike

Work done:
- Hand-wrote a single-file Aiken verifier (`experiments/aiken-verifier-spike/validators/spike.ak`) that verifies one real Phase 2 outer proof end-to-end against `MAX_INPUTS = 8` with the RISC Zero canonical inner fixture.
- Pinned the Bowe–Gabizon Pedersen-commitment-on-Cardano algorithm in **ADR-0006**: PoK pairing equation, ExpandMsgXmd-SHA256 hash-to-Fr for the implicit folded public input, and the binding strategy that ties the redeemer-supplied 96-byte uncompressed commitment to its 48-byte compressed form (via `2·y > q` y-sign reconstruction).
- Both layers from ADR-0004 in one file:
  - **Layer 1** (generic): Groth16 + Bowe–Gabizon — IC accumulation over `[InnerVKHash, inputs…, commit_fr]` plus the bare-commitment fold-in, Pedersen PoK pairing, Groth16 pairing.
  - **Layer 2** (RISC Zero): reconstructs `claim_digest` from `journal_bytes` via the `tagged_struct` chain (3 SHA-256s), assembles the 5 RISC Zero public inputs from version constants + split-digest, then delegates to Layer 1.
- Nine inline tests cover hash-to-Fr, compressed-uncompressed binding, full verifier (positive + two tampered), claim-digest reconstruction, input vector, end-to-end via `verify_risc0` (positive + tampered journal).

Findings:
- **End-to-end verification fits comfortably in the Plutus V3 budget.** Layer 1 `verify` costs **4.28 B CPU** / **52.53 K mem** — ~43% of the 10 B mainnet CPU budget, ~0.4% of the 14 M mem budget.
- **Layer 2 is essentially free on top of Layer 1.** Full `verify_risc0` is **4.28 B CPU** / **62.89 K mem** — same CPU within rounding because the Groth16 pairing dominates; +10 K mem and +8.6 M CPU for the journal-side work in isolation (`claim_digest_chain_matches` + `risc0_inputs_match_fixture`).

Open questions:
- **Codegen.** The spike is single-fixture; Phase 3 step 2 lifts it into a Rust string template inside `zkwrap-risc0` with parameterised constants (outer VK points, IC, commitment keys, MAX_INPUTS, `InnerVKHash`, RISC Zero version constants, plus per-guest pre/post state digests for Layer 2).

Links:
- ADR-0006 (Pedersen check spec): `docs/adr/0006-pedersen-commitment-check-on-cardano.md`
- Spike: `experiments/aiken-verifier-spike/`

## 2026-05-29 - Phase 2 Complete: `zkwrap-gnark` Binary

Work done:
- Lifted the recursive Groth16/BLS12-381 wrapper from the experiment into the `zkwrap-gnark` binary. Three subcommands per ADR-0004: `unsafe-setup`, `prove`, `verify`.
- End-to-end smoke test runs `unsafe-setup → prove → verify` against the RISC Zero Phase 1 fixture inside `go test`.
- Extended `docs/schemas/outer-proof-artifacts.md` with the commitment fields the recursive verifier requires (`commitment_keys`, `public_and_commitment_committed`, `proof.commitments`, `proof.commitment_pok`).

Phase 2 exit criteria met: end-to-end off-chain prove + verify works against a real Phase 1 inner proof.

Links:
- ADR-0004: `docs/adr/0004-gnark-prover-cli.md`
- Outer artifact schema: `docs/schemas/outer-proof-artifacts.md`
- Binary entrypoint: `zkwrap-gnark/cmd/zkwrap-gnark/main.go`

## 2026-05-26 - Phase 2 Step 1: MAX_INPUTS Benchmark and Poseidon Choice

Work done:
- Extended the RISC Zero recursive experiment into a parameterised production-shaped wrapper circuit (Poseidon2-MD `InnerVKHash`, outer public inputs `[InnerVKHash, input_0..input_{MAX-1}]`).
- Benchmarked three `MAX_INPUTS` candidates against the RISC Zero Phase 1 fixture, end-to-end prove + verify.
- Locked `MAX_INPUTS = 8` into ADR-0002 with the benchmark table and marginal-cost analysis.
- Resolved the off-circuit Poseidon choice: Poseidon2 over BLS12-381 Fr with gnark-crypto default parameters, Merkle-Damgård chaining. Captured in new ADR-0005.

Findings:
- Inner Groth16 verification in `std/recursion/groth16` requires `WithCompleteArithmetic` once IC slots are padded with `(0,0)` and zero scalars — without it the prover hits "no modular inverse" during witness solving.
- After refactor the wrapper circuit is now universal in `n_real`: it has no compile-time awareness of how many slots are real for a given inner system. The Aiken validator carries the excess-zero check, per ADR-0002.
- Inner-witness scalars are derived in-circuit directly from the outer public inputs (single source of truth), with bit decomposition that admits a small `[BN254_Fr_mod, 2^254)` gap caught by the Aiken layer.

Links: `docs/adr/0002-universal-wrapper-circuit.md`, `docs/adr/0005-poseidon2-bls12381-for-inner-vk-hash.md`, `experiments/risc0-gnark-verifier/recursive/main.go`.

## 2026-05-21 - risc0-ethereum Architecture Review

Reviewed `../risc0-ethereum/` for spec cross-validation and on-chain design patterns.
Full notes: `docs/research/risc0-ethereum-architecture.md`.

- All serialization specs confirmed (no corrections needed).
- Three-layer generation model (snarkJS VK + generated constants + static glue) mirrors ADR-0004.
- Complete V5.0 test vector in `contracts/test/TestReceiptV5_0.sol` — useful integration fixture.
- `RiscZeroSetVerifier` documents a Merkle batching pattern worth noting for Phase 3+ scaling.

## 2026-05-21 - Phase 1 Complete: Schema Lock and Architecture

Phase 1 (schema lock) is done. Phase 2 begins.

Work done:
- Locked canonical inner proof format (`docs/schemas/canonical-inner-proof.md`) — byte-level contract between Rust plugin and Go prover binary.
- Documented RISC Zero artifact format including journal authentication hash chain (`docs/research/risc0-artifact-format.md`).
- Written four ADRs and domain glossary (`CONTEXT.md`).

Key decisions:
- **ADR-0001:** Expose inner public inputs directly as `[VKHash, input_0..input_{MAX-1}]` — no `InputCommitment`. Soundness from the BLS12-381 proof; no on-chain hash recomputation needed.
- **ADR-0002:** Single wrapper circuit with fixed `MAX_INPUTS`. Unused IC slots padded to identity; Aiken validator checks excess slots are zero.
- **ADR-0003:** File-based boundary between Rust plugin and Go prover (CGO rejected).
- **ADR-0004:** Rust plugin crates own Aiken codegen. Generated validator has two layers: generic BLS12-381 verification + system-specific journal auth and zero-checks. Go binary is a pure prover only.

Finding: RISC Zero journal auth is feasible on Cardano — ~4 SHA-256 calls via `tagged_struct`, all using the Cardano native SHA-256 builtin. Tag digests baked as constants at codegen time. SP1 equivalent is 1 SHA-256 call.

Note: the 2026-05-14 finding ("universal circuit infeasible") was wrong — `MAX_INPUTS` with IC padding solves it.

## 2026-05-19 - PLONK Outer Wrapping for SP1 and RISC Zero

Work done:
- Added `experiments/sp1-gnark-verifier/recursive_plonk/` — wraps the SP1 BN254 Groth16 inner
  proof in a BLS12-381 PLONK outer proof using `gnark/backend/plonk` + `frontend/cs/scs`.
- Added `experiments/risc0-gnark-verifier/recursive_plonk/` — same approach for the RISC Zero

Findings:
- PLONK wrapping takes ~1 minute to create a proof, roughly
  10× slower than the Groth16 outer (~5s).
- Key advantage over Groth16 outer: PLONK uses a universal KZG SRS that is circuit-independent.
  Groth16 requires a fresh trusted setup per circuit (i.e. per inner proof system / innerNPublic
  count); PLONK does not — the same SRS covers any circuit up to the supported size bound.
- Circuit definition is identical in both cases: the outer circuit verifies an emulated BN254
  Groth16 proof regardless of whether the outer system is Groth16 or PLONK.

## 2026-05-18 - SP1 Groth16 Artifact Extraction and gnark Verification

Work done:
- Implemented `experiments/sp1-hello-world/` — proves `multiply(17, 23)` with SP1 v3.4.0
  (`native-gnark` feature, no Docker) and writes Groth16/BN254 fixtures to `fixtures/`.
- Implemented `experiments/sp1-gnark-verifier/` — standalone BN254 verifier and BLS12-381
  recursive wrapper, mirroring the RISC Zero verifier structure.
- Documented artifact format in `docs/research/sp1-artifact-format.md`.

Findings:
- SP1 has **2 public inputs** (`vkey_hash`, `committed_values_digest`) vs RISC Zero's 5.
- A universal outer circuit covering both is feasible: compile with `innerNPublic = 5`, pad SP1's IC with identity points, enforce extra inputs as zero off-circuit. See `docs/research/sp1-artifact-format.md §9`.

## 2026-05-14 - Recursive gnark Verification of RISC Zero Proof

Work done:
- Implemented `experiments/risc0-gnark-verifier/` — Go module with a RISC Zero BN254 Groth16 proof verified inside a BLS12-381 Groth16 outer circuit using `gnark/std/recursion/groth16`. ~5s prove time.

Findings:
- A universal wrapper circuit shared across different inner proof systems (RISC Zero, SP1, etc.) is likely infeasible. The outer circuit's R1CS encodes the inner VK structure — specifically number of public inputs — at compile time. If RISC Zero and SP1 have different numbers of public inputs, they require different outer circuits and therefore different trusted setups. There is no structural workaround: each inner proof system needs its own wrapper circuit and its own setup ceremony.

## 2026-05-12 - RISC Zero Groth16 Fixture Extraction

Work done:
- Implemented `experiments/risc0-hello-world/src/bin/dump_groth16.rs` — proves a sample computation with `ProverOpts::groth16()` and extracts all data needed for downstream BN254 Groth16 verification:
  - `seal.bin` — raw Groth16 proof (A, B, C elliptic curve points)
  - `vk.json` — verifying key in snarkjs-compatible JSON format
  - `public_inputs.json` — 5 BN254 Fr field elements passed to the verifier
  - `claim_digest.bin` — hash of the execution result (proof-specific)
  - `control_root.bin` / `bn254_control_id.bin` — RISC Zero circuit version identifiers (fixed per risc0 release)
  - `journal.bin` / `image_id.bin` — guest output and program identity
- Added a self-verification cross-check: reads fixtures back and runs `risc0_groth16::Verifier` to confirm encoding is correct.
- Documented fixture roles and public input derivation in `fixtures/README.md`.

Findings:
- VK is system-wide (not per guest program) — fixed for a given risc0 release.
- `control_root` and `bn254_control_id` are enforced as public inputs by the Groth16 circuit itself, binding the proof to a specific RISC Zero version.

Insight — wrapper plugin as a library:
- The risc0 plugin could be a Rust library crate that host programs import directly, rather than a standalone CLI tool. The library would extract proof artifacts in the format expected by the gnark BLS wrapper and write them to disk (or return them in-memory). This would significantly reduce developer friction — no separate tool invocation, no format mismatch, just a function call inside the existing host program.
- Exact artifact formats (binary vs JSON, file layout) are not decided yet and should be pinned once the gnark side is understood.

## 2026-05-04 - LLM Development Workflow Setup

Context:
- The project is still in the planning and feasibility stage, before implementation has started.
- We wanted the repository to be easier for LLM agents and humans to navigate consistently across sessions.

Work done:
- Added `AGENTS.md` as the main project instruction file for LLM-driven development.
- Added `CLAUDE.md` as a thin redirect to `AGENTS.md`, keeping one source of truth for agent instructions.
- Organized `docs/` around separate purposes: `research/`, `decisions/`, `schemas/`, `tasks/`, and this journal.
- Updated `docs/implementation-plan.md` so the compatibility audit is Phase 1 and links point to the current `docs/research/` paths.

Findings:
- `docs/journal.md` is useful as chronological working memory: progress notes, experiments, observations, and open questions.
- `docs/decisions/` should be reserved for durable architecture decisions that future work should treat as settled.
- `docs/schemas/` should hold precise data contracts for proof artifacts, wrapper witnesses, plugin outputs, and redeemers.
- `docs/tasks/` should hold bounded implementation briefs with deliverables and acceptance criteria.

Open questions:
- Exact external dependency workspace layout is still undecided, though a sibling directory such as `../groth16-wrapper-deps/` looks preferable to vendoring RISC Zero and SP1 into this repository.
- A dependency lock/notes format should be added once real RISC Zero and SP1 artifact audits begin.

