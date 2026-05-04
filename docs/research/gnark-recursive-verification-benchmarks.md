# gnark Recursive ZK-SNARK Verification Benchmarks

## Overview

[gnark](https://github.com/Consensys/gnark) is a Go library for building ZK-SNARK circuits. It supports multiple proof systems (Groth16, PLONK) and curves (BN254, BLS12-381, BLS12-377, BW6-761). It provides the full toolkit for recursive proof verification: emulated (non-native) field arithmetic, in-circuit elliptic curve operations, and in-circuit pairing checks.

Benchmark code: https://github.com/dkaidalov/gnark

## Benchmark Setup

- All benchmarks verify a trivial inner Groth16 proof (P*Q=N) inside an outer circuit
- Tamper tests confirmed all verifications are real (corrupted witness is rejected by the prover)
- Run on 20 CPU cores, Windows
- gnark v0.11.x (go 1.25.7, gnark-crypto v0.19.3)

## Results

| Metric | Groth16/BN254 -> Groth16/BLS12-381 | Groth16/BLS12-381 -> Groth16/BN254 | Groth16/BN254 -> PLONK/BLS12-381 |
|---|---|---|---|
| Outer constraints | 840,199 (R1CS) | 1,148,218 (R1CS) | 2,759,676 (PLONK gates) |
| Setup time | 1m 49s | 1m 37s | 1m 43s |
| **Prove time** | **5.26s** | **4.76s** | **51.3s** |
| Verify time | <1ms | <1ms | 7ms |
| Peak RAM | 2.4 GB | 3.3 GB | 8.2 GB |
| Tamper test | PASS | PASS | PASS |

Also benchmarked but omitted from table for clarity:
- Groth16/BN254 -> Groth16/BN254: 840,199 constraints, 2.78s prove, 2.1 GB RAM
- Groth16/BN254 -> PLONK/BN254: 2,759,676 constraints, 41.3s prove, 7.3 GB RAM

## Key Findings

### 1. Groth16 outer is 10-18x faster than PLONK outer

Groth16 proving requires only 3 MSMs + 1 FFT. PLONK has multiple polynomial commitment rounds, coset FFTs, and permutation arguments. For a fixed circuit (like a recursive verifier), Groth16's per-circuit trusted setup is not a significant drawback.

### 2. PLONK gate count != R1CS constraint count

The 3.3x ratio (2.76M PLONK gates vs 840K R1CS constraints) is a structural difference in arithmetization. An R1CS row `(sum_a) * (sum_b) = (sum_c)` can multiply two full linear combinations in one constraint. A PLONK gate `qL*a + qR*b + qM*a*b + qO*c + qC = 0` has fixed fan-in, so operations that Groth16 encodes in 1 row often need 2-4 PLONK gates.

### 3. BLS12-381 pairing is 37% larger than BN254 pairing in-circuit

1,148,218 vs 840,199 R1CS constraints. BLS12-381 has a larger base field (381-bit -> 6 limbs vs BN254's 4 limbs) and a longer Miller loop, leading to more emulated arithmetic operations.

### 4. Same inner curve -> same constraint count regardless of outer curve

The circuit structure is determined by the emulated pairing (which inner curve is being verified), not by the native field it runs on. The native field only affects prover performance (larger field elements = slower MSM/FFT).

### 5. All scenarios are practical

Even the slowest scenario (PLONK/BLS12-381) finishes proving in under 1 minute. The Groth16 scenarios complete in ~5 seconds, making them viable for real-time applications.

## How to Run

```bash
cd gnark
go run ./cmd/recursive_bench/
```

The benchmark automatically:
1. Creates an inner Groth16/BN254 proof
2. Compiles the outer recursive verifier circuit
3. Runs trusted setup
4. Proves the outer circuit
5. Verifies the outer proof
6. Runs a tamper test (corrupts inner witness, confirms prover rejects)

Flags can be added to select scenario (BN254->BN254, BN254->BLS12-381, BLS12-381->BN254, PLONK variants).

## Technical Notes

- gnark requires Go 1.25+ (`go.mod` specifies 1.25.7)
- `go test` (and `go run`) compile with full optimizations by default — there is no `--release` flag in Go
- GPU acceleration available via `-tags=icicle` (requires NVIDIA GPU + Icicle library)
- The `test.IsSolved()` function (used in gnark's own tests) only checks constraint satisfaction, it does NOT run full Setup+Prove+Verify
- gnark's `Example_emulated` function lacks an `// Output:` comment, so `go test -run Example_emulated` silently skips it
