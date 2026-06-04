# Project Instructions

This repository builds a Groth16/BN254 wrapper toolkit for Cardano.

Many external ZK systems, including RISC Zero and SP1, emit Groth16 proofs over BN254. Cardano Plutus V3 supports BLS12-381 operations through CIP-0381, but not BN254 pairings directly. The project goal is to re-prove an external Groth16/BN254 statement inside a BLS12-381-friendly wrapper proof off-chain, then generate an Aiken verifier that can check the wrapped proof on Cardano.

## Repository Structure

- `README.md` - short project overview.
- `docs/initial-proposal.md` - original project proposal and motivation.
- `docs/implementation-plan.md` - phased implementation roadmap. It is not set-in-stone and can be modified as more explorations are done.
- `docs/research/` - feasibility studies and exploratory notes. These are evidence and background, not necessarily final specs.
- `docs/adr/` - architecture decision records. Each ADR captures the current decided position on a choice. ADRs are not set-in-stone; they can be revisited and superseded as new findings emerge.
- `docs/schemas/` - precise data format specs: wrapper witness shape, public inputs, plugin outputs, redeemers, byte order, point encodings, hash preimages, and validation rules.
- `docs/tasks/` - small implementation briefs or tickets with context, deliverables, and acceptance criteria.
- `docs/journal.md` - chronological project log for day-to-day progress, observations, experiments, and links to related tasks or decisions.

## Important Background Documents

- `docs/research/gnark-recursive-verification-benchmarks.md` - benchmark evidence that gnark can verify Groth16/BN254 inside BLS12-381 in practical time.
- `docs/research/snarkjs-cardano-aiken-verifiers.md` - feasibility notes for Groth16, PLONK, and FFLONK Aiken verifiers over BLS12-381.

## Engineering Priorities

1. Preserve cryptographic soundness over convenience.
2. Prefer small reproducible milestones over broad abstractions.
3. Keep serialization choices explicit: byte order, compressed point format, scalar modulus, hash preimages, domain tags, and digest-to-field mapping. Record every such choice as a spec under `docs/schemas/` *before* code references it - never let a wire format live only in source.
4. Every verifier or conversion path should eventually have positive tests and tamper-negative tests.
5. Prefer existing project patterns and documented decisions over inventing new conventions.

## Development Guidance

- Use Aiken for generated Cardano validators.
- Keep generated artifacts, large external repositories, proving keys, and bulky proof outputs out of git unless there is a specific fixture reason to commit them.
- When adding docs, distinguish between:
  - `docs/research/` for exploratory findings
  - `docs/schemas/` for precise data contracts
  - `docs/adr/` for architecture decisions (revisitable as findings evolve)
  - `docs/journal.md` for chronological working notes

## Before Making Changes

Read, in order:

1. `docs/initial-proposal.md` - **start here.** Goals, problem framing, and constraints.
2. `docs/implementation-plan.md` - phased roadmap. Check the **Current phase** marker at the top to know what scope is in bounds.
3. `docs/journal.md` - **most recent entry first**, for the freshest signal on what is in flight, what was just decided, and any open questions.
4. Any relevant files under `docs/research/`, `docs/schemas/`, or `docs/adr/`.

## Do NOT Auto-Write These

The following files are **only edited when the user explicitly asks for it**. Do not append to them as a side-effect of completing other work:

- `docs/journal.md` - append a journal entry only when asked.
- `docs/adr/` - create, modify, or supersede an ADR only when asked, even for architecture-affecting changes. If a change feels architecture-affecting - or new findings call an existing ADR into question - surface that to the user and propose adding or revisiting an ADR; do not write or rewrite one unprompted.

The implementation plan's **Current phase** marker is the one exception: keep it accurate as phases begin and complete, without waiting to be asked.
