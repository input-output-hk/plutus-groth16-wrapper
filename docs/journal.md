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
