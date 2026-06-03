# plutus-groth16-wrapper

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains prototype implementations.** This code is provided "as is" for research and educational purposes 
> only. It has not been thoroughly tested and audited and is not intended for production use. By using this code, you 
> acknowledge and accept all associated risks, and our company disclaims any liability for damages or losses.

A toolkit for verifying **Groth16/BN254** proofs on **Cardano**. Most of the external ZK ecosystem (RISC Zero, SP1, circom, Ethereum tooling) produces proofs over BN254, but Cardano natively supports only BLS12-381 via [CIP-0381](https://cips.cardano.org/cip/CIP-0381). This curve mismatch leaves Cardano cut off from the broader zkVM ecosystem — there is no practical path today to verify a RISC Zero or SP1 proof on-chain.

This project closes that gap. It re-proves a Groth16/BN254 statement inside a BLS12-381–friendly circuit off-chain, and generates a matching [Aiken](https://aiken-lang.org/) verifier that runs as a Plutus V3 script. The intent is snarkjs-level ergonomics: a developer with a Groth16/BN254 proof should be able to wrap it and verify it on Cardano with minimal tooling friction.

> **Status:** early implementation. Architecture and tooling form factor are still being worked out. See [docs/initial-proposal.md](docs/initial-proposal.md) for the full proposal and [docs/implementation-plan.md](docs/implementation-plan.md) for the phased roadmap.

## License

Copyright 2026 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License
