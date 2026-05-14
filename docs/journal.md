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

