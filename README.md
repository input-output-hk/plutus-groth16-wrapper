# plutus-groth16-wrapper

A toolkit for verifying **Groth16/BN254** proofs on **Cardano**. Most of the external ZK ecosystem (RISC Zero, SP1, circom, Ethereum tooling) produces proofs over BN254, but Cardano natively supports only BLS12-381 via [CIP-0381](https://cips.cardano.org/cip/CIP-0381). This curve mismatch leaves Cardano cut off from the broader zkVM ecosystem — there is no practical path today to verify a RISC Zero or SP1 proof on-chain.

This project closes that gap. It re-proves a Groth16/BN254 statement inside a BLS12-381–friendly circuit off-chain, and generates a matching [Aiken](https://aiken-lang.org/) verifier that runs as a Plutus V3 script. The intent is snarkjs-level ergonomics: a developer with a Groth16/BN254 proof should be able to wrap it and verify it on Cardano with minimal tooling friction.

> **Status:** early implementation. Architecture and tooling form factor are still being worked out. See [docs/initial-proposal.md](docs/initial-proposal.md) for the full proposal and [docs/implementation-plan.md](docs/implementation-plan.md) for the phased roadmap.
