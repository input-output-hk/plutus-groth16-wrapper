# plutus-groth16-wrapper

[![CI](https://github.com/input-output-hk/plutus-groth16-wrapper/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/input-output-hk/plutus-groth16-wrapper/actions/workflows/ci.yml)
[![Security](https://github.com/input-output-hk/plutus-groth16-wrapper/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/input-output-hk/plutus-groth16-wrapper/actions/workflows/security.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains prototype implementations.** This code is provided "as is" for research and educational purposes 
> only. It has not been thoroughly tested and audited and is not intended for production use. By using this code, you 
> acknowledge and accept all associated risks, and our company disclaims any liability for damages or losses.

A toolkit for verifying **Groth16/BN254** proofs on **Cardano**. Most of the external ZK ecosystem (RISC Zero, SP1, circom, Ethereum tooling) produces proofs over BN254, but Cardano natively supports only BLS12-381 via [CIP-0381](https://cips.cardano.org/cip/CIP-0381). This curve mismatch leaves Cardano cut off from the broader zkVM ecosystem — there is no practical path today to verify a RISC Zero or SP1 proof on-chain.

This project closes that gap. It re-proves a Groth16/BN254 statement inside a BLS12-381–friendly circuit off-chain, and generates a matching [Aiken](https://aiken-lang.org/) verifier that runs as a Plutus V3 script. 

## Architecture

A proof's journey from an inner Groth16/BN254-based system to Cardano — three off-chain stages, one on-chain:

```
  inner proof        Groth16/BN254 · RISC Zero, SP1, …
     │  canonicalize  (convert Groth16/bn artifacts into canonical representation)
     ▼
  canonical proof    vk · proof · inputs · meta.json    (system-agnostic)
     │  recursive wrapping (wrap into BLS12-381-based proof verifiable on Cardano)
     ▼
  outer proof        Groth16/PLONK over BLS12-381
     │  gen-verifier (generate Aiken verifier)
     ▼
  Aiken validator    Plutus V3    ──submit──▶   Cardano
```

Because Plutus V3 has BLS12-381 support (CIP-0381) but not BN254, the BN254 proof is **re-proved inside a BLS12-381 wrapper** off-chain; the script verifies that wrapper proof. Its public inputs are `[InnerVKHash, input₀ … input₇]`, so the on-chain check reduces to *"a pinned inner VK accepted these inputs."*

The validator is not hand-written per system — it is **composed from two independent axes**, so the `{systems} × {engines}` matrix is assembled from `m + n` pluggable fragments, not `m × n` validators:

```
  inner system  →  Groth16/BN254 proof       outer engine  (BLS12-381, on-chain-verifiable)
  ─────────────────────────────────────      ───────────────────────────────────────────────
  RISC Zero · SP1 · circom · …                gnark Groth16 · gnark PLONK · …
                  │                               │
             inner layer                     outer layer
                  └───────────────┬───────────────┘
                                  ▼
            generated Aiken validator (Plutus V3)  ──▶  Cardano
```

- **Inner layer** — the zkVM-specific scaffolding (e.g. RISC Zero's journal-authentication chain), keyed by `system_id`; knows nothing of the outer proof.
- **Outer layer** — the proving-engine verifier baked with its trusted setup, keyed by the outer backend; generic across inner systems.

## How to use

**Supported** — inner systems: RISC Zero (`zkwrap-risc0`), SP1 (`zkwrap-sp1`); outer engines: gnark Groth16/BLS12-381, gnark PLONK/BLS12-381.

**1. One-time trusted setup** (per outer engine; fixes `MAX_INPUTS`):

```sh
zkwrap-gnark unsafe-setup --backend groth16 --max-inputs 8 --out setup/
```

**2. Wrap the proof and generate the verifier.** Both steps run either **in-process** from your host program (Rust) or as **standalone CLI** commands over artifacts on disk — the wrapper proof is produced by the gnark binary either way.

In-process, where you already run the zkVM prover (this is what the example does):

```rust
let receipt = prover.prove_with_opts(env, ELF, &ProverOpts::groth16())?.receipt;
let canonical = zkwrap_risc0::canonicalize(&receipt, IMAGE_ID)?;       // native receipt → canonical
let outer = GnarkCliProver::new(gnark_bin, "setup/")                   // wrap (drives `zkwrap-gnark`)
    .prove::<Groth16OuterProof>(&canonical.proof)?;
zkwrap_risc0::build_validator(&Risc0ValidatorRequest {                 // generate the Aiken project
    receipt: &receipt, canonical: &canonical, outer_proof: &outer,
    outer_vk_json: &vk_json, project_name: "zkwrap/risc0_groth16",
})?.write_to("verifier/")?;
```

Or as CLI steps, over a bundle from `canonicalize(...).write_to("out/canonical")` (with the receipt saved alongside as `out/receipt.json`):

```sh
zkwrap-gnark prove        --inner out/canonical --setup setup/ --out out/outer_proof.json
zkwrap-risc0 gen-verifier --canonical out/canonical --receipt out/receipt.json \
                          --outer-proof out/outer_proof.json --setup setup/ --out verifier/ --check
```

Either way the result is a ready-to-`aiken build` Plutus V3 project with a real positive/tamper test suite (`--check` runs `aiken check`). `zkwrap-sp1` is identical, with `--public-values <file>` in place of `--receipt`.

See [`examples/`](examples/) for a runnable end-to-end examples for Risc0 and SP1 wrapped proofs.

## Repository map

| Path | Role |
|---|---|
| `zkwrap-gnark/` (Go) | Outer prover binary (`unsafe-setup`, `prove`, `verify`) — wraps a canonical inner proof into a BLS12-381 outer proof via gnark (Groth16 or PLONK). |
| `zkwrap-rs/zkwrap-core` (Rust) | Codegen engine: the Composer, the `OuterCodegen`/`InnerCodegen` traits, the gnark Groth16 **and** PLONK outer backends (artifacts + Aiken templates + VK-hash cross-check), and the canonical inner-proof / bundle types. |
| `zkwrap-rs/zkwrap-risc0`, `zkwrap-sp1` | Per-system plugins: `canonicalize` (native receipt → canonical proof) + inner-layer Aiken codegen + the `gen-verifier` CLI. |
| `zkwrap-rs/zkwrap-prover` (Rust) | Off-chain prover driver: a `Prover` trait + `GnarkCliProver`, which spawns `zkwrap-gnark prove`. |
| `examples/{risc0,sp1}-aiken-{groth16,plonk}/` | **Runnable end-to-end demos** across the system × backend matrix; `risc0-aiken-groth16` is the tutorial. Each goes from a guest to a green `aiken check`. |
| `fixtures/` | Committed test fixtures: trusted setups, canonical inner proofs, outer proofs, and per-system source artifacts. |
| `docs/` | `adr/` decisions · `schemas/` data contracts. |
| `experiments/` | Exploratory spikes (e.g. the hand-written Aiken verifier the generator was lifted from). |

## License

Copyright 2026 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License
