# Universal wrapper circuit with configurable MAX_INPUTS

A single wrapper circuit is compiled with a hardcoded `MAX_INPUTS` constant rather than one circuit per inner proof system. Systems with fewer real inputs (e.g., SP1 with 2 vs RISC Zero with 5) pad their canonical inner proof with zero-valued inputs up to `MAX_INPUTS`. The Aiken validator for each inner system enforces that the excess slots equal zero.

The alternative (a separate circuit and trusted setup ceremony per inner proof system) was rejected because it multiplies ceremony overhead with every new inner system added. A single ceremony is far more practical to organise and audit.

`MAX_INPUTS = 8`. Chosen after benchmarking the production-shaped wrapper circuit at three candidates against the RISC Zero Phase 1 fixture (gnark v0.14.0, BLS12-381 Groth16 outer, 16-core WSL2 Linux, no GPU acceleration):

| `MAX_INPUTS` | constraints | compile | setup    | prove   | verify | peak RSS |
|-------------:|------------:|--------:|---------:|--------:|-------:|---------:|
| 5            | 1,209,228   | 4.5s    | 3m34s    | 9.8s    | 2.3ms  | 3.88 GiB |
| 8            | 1,348,442   | 5.4s    | 3m53s    | 10.4s   | 2.4ms  | 4.12 GiB |
| 16           | 1,719,681   | 6.7s    | 4m41s    | 11.7s   | 2.1ms  | 4.14 GiB |

Each added slot costs ~46K constraints (~0.25s prove time), dominated by the IC scalar multiplication in the inner Groth16 verifier's MSM, which runs under `WithCompleteArithmetic` so the padded `(0,0)` IC entries and zero inner-witness scalars are handled correctly.

`MAX_INPUTS = 8` is the chosen point on the cost curve: enough to cover both Phase 1 fixtures (RISC Zero `n_real = 5`, SP1 `n_real = 2`) with a small amount of headroom, while staying ~11% above the minimum constraint cost. `MAX_INPUTS = 16` would have added ~510K constraints and ~2s of prove time for slack we cannot point at a specific consuming system, and `MAX_INPUTS = 5` left no room at all for any system with more than five public outputs.

The benchmark experiment lives at `experiments/risc0-gnark-verifier/recursive/`. The off-circuit `InnerVKHash` is computed with the Poseidon2/BLS12-381 parameters in [ADR-0005](0005-poseidon2-bls12381-for-inner-vk-hash.md).

**Soundness note:** for inner systems that pad with zeros, the Aiken validator must explicitly check that the padded input slots equal zero. This check cannot be omitted: if the inner VK is a private witness (as it is in the current gnark `std/recursion/groth16` design), an adversary could supply a padded VK with non-identity IC points for the zero-input slots and pass the pairing check with arbitrary values in those slots.
