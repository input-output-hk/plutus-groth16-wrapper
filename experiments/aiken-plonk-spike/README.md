# aiken-plonk-spike — on-chain gnark PLONK verifier feasibility spike

**Throwaway de-risking spike** for the PLONK outer backend
(`docs/tmp/plonk-integration-plan.md`, Step 0). It answers the load-bearing
question: *can a gnark PLONK/BLS12-381 proof — with its BSB22 commitment and
SHA-256 Fiat-Shamir transcript — be verified on Cardano within Plutus V3
execution limits?*

**Answer: yes.** A hand-written Aiken verifier reproduces gnark's verification
exactly and `aiken check`s green at **4.82 B cpu / 3.05 M mem** (limits: 10 B /
14 M), comparable to the snarkjs PLONK Aiken verifier (~4.7 B / 3.0 M).

## Layout

- `export/` — Go: builds a minimal PLONK/BLS12-381 circuit with the **production
  proof shape** (9 public inputs `[InnerVKHash, input_0..7]` + one `api.Commit`,
  forcing a single BSB22 commitment), proves it, and serializes VK + proof to
  `artifacts/{outer_vk,outer_proof}.json`. A tiny circuit is deliberate: the
  on-chain unknowns depend on proof *shape*, not on what the circuit computes,
  so this proves in seconds instead of the multi-minute real recursion.
- `refverify/` — Go: a **deterministic reference verifier** reading the JSON
  artifacts. Reproduces gnark's verification using only SHA-256 + BLS12-381 ops,
  PASSes the valid proof, REJECTs a tampered one, and dumps golden vectors
  (every challenge + intermediate) to `artifacts/golden.json`.
- `gen-fixture/` — Go: emits `aiken/lib/plonk_spike/fixtures.ak` (baked VK/proof/
  golden constants) from the artifacts.
- `aiken/` — the hand-written Aiken verifier (`lib/plonk_spike/verifier.ak`),
  checked stage-by-stage against the golden vectors.

## Reproduce

```sh
cd export      && go run . ../artifacts && cd ..
cd .           && go run ./refverify ./artifacts          # PASS + tamper REJECT, writes golden.json
go run ./gen-fixture ./artifacts ./aiken/lib/plonk_spike/fixtures.ak
cd aiken       && aiken check                              # 4 tests pass
```

(`aiken check` error output needs a TTY — run under `script -qec "aiken check" out.txt` if errors look blank.)

## Key findings (validated)

- **Port target is gnark's PLONK *Solidity* verifier, not the Go one.** Go's
  `kzg.BatchVerifyMultiPoints` folds with a *random* λ (not reproducible
  on-chain); the deterministic path derives the two-opening batch scalar by
  SHA-256. A valid proof verifies under any λ, so this stays sound.
- **Transcript = SHA-256** over **uncompressed** G1 points (`Marshal()` =
  uncompressed); challenges `gamma→beta→alpha→zeta`, each
  `H(label ‖ prev_raw ‖ bindings…)`, reduced mod r for arithmetic.
- **BSB22 commitment** folds into PI via RFC-9380 `expand_message_xmd`(SHA-256),
  DST `"BSB22-Plonk"` — the same `expand_msg_xmd_48` the Groth16 spike uses,
  only the DST differs.
- **`gamma_kzg` must match gnark exactly** (the prover's batched-opening quotient
  is bound to it) — so it hashes the **uncompressed** linearized-poly digest,
  which is computed on-chain. The verifier gets those bytes from the proof and
  binds them via `compress(computed) == compress(provided)` (the Groth16 spike's
  commitment trick).
- **Batch inversion is mandatory for budget.** `scalar.div`/`recip` each cost one
  ~255-bit modular exponentiation. The naive per-public-input inversion blew the
  budget (10.54 B cpu / 20.76 M mem); Montgomery batch inversion (one modexp)
  cut it to 4.82 B / 3.05 M.
