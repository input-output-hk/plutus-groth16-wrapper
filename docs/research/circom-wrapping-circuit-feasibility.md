# Circom as an Alternative Wrapping Circuit Backend

## Question

Can Circom replace gnark as the backend for wrapping a Groth16/BN254 proof inside a BLS12-381-compatible circuit, so the outer proof can be verified on Cardano via CIP-0381?

## RISC Zero's Circom Usage — Not a Precedent

RISC Zero uses Circom for STARK verification, not cross-curve Groth16 wrapping. Its `stark_verify.circom` (1.6M generated lines) encodes a Baby Bear STARK verifier as R1CS, which is then proven as a Groth16/BN254 proof. The flow is:

```
RISC-V program → STARK (Baby Bear field) → [stark_verify.circom: Baby Bear STARK verifier] → Groth16/BN254
```

This does not involve cross-curve pairing in Circom. The circuit outputs 4 BN254 Fr elements packing the claim digest and control root — no BLS12-381 is involved.

## Why Baby Bear in BN254 Does Not Require Foreign-Field Arithmetic

Baby Bear prime: `p = 2^31 - 2^27 + 1 ≈ 2^31`
BN254 scalar field: `r ≈ 2^254`

Since `p_babybear << r_bn254`, Baby Bear field elements fit natively as BN254 field elements. Multiplication stays well within range:

```
a * b  where a, b < 2^31  →  a * b < 2^62  →  fits in BN254 Fr (~2^254)
```

Modular reduction uses range checks only — no limb decomposition. This is why the STARK verifier in Circom is tractable despite its size.

## Why BN254 Groth16 Verification in BLS12-381 Requires Foreign-Field Arithmetic

BN254 base field Fp: `≈ 2^254`
BLS12-381 scalar field Fr: `≈ 2^255`

These primes are of similar magnitude. Multiplying two BN254 Fp elements inside a BLS12-381-native circuit overflows:

```
a * b  where a, b < BN254_Fp ≈ 2^254  →  a * b ≈ 2^508  →  does NOT fit in BLS12-381 Fr
```

All BN254 Fp arithmetic must be emulated via big-integer limb decomposition — the same problem `circom-pairing` solves in the opposite direction.

## Closest Existing Library: circom-pairing (0xPARC)

[`yi-sun/circom-pairing`](https://github.com/yi-sun/circom-pairing) implements BLS12-381 pairing inside a BN254-native Circom circuit (the reverse direction — useful for verifying BLS signatures on Ethereum). It uses 5×51-bit or 6×43-bit limb decomposition for BLS12-381 Fp arithmetic.

### Benchmarks (rapidsnark, AWS r5.8xlarge: 32-core Xeon 3.1 GHz, 256 GB RAM)

| Circuit | Constraints | Witness gen | Prove time | Proving key size |
|---|---|---|---|---|
| Optimal Ate pairing | 11.4M | 1 min | 52 s | 6.5 GB |
| Full BLS sig verify | 19.2M | 2.6 min | ~2 min | 12 GB |
| Tate pairing | 24.7M | 2.5 min | ~2 min | 15 GB |

Setup costs on the same machine: circuit compilation 1.9–4.2 h, trusted setup key generation 32–97 min.

ChainSafe independently measured ~112 s for a full BLS verify circuit on equivalent hardware.

### Security Status

The library is explicitly not audited and not intended for production. Veridise found a critical bug: `BigLessThan` output signals in `CoreVerifyPubkeyG1` were instantiated but never constrained, potentially allowing signature forgery without detection.

## No Existing Circom Circuit for BN254-in-BLS12-381

There is no public Circom circuit that verifies BN254 pairing operations inside a BLS12-381-native circuit. Building one would require implementing BN254 Fp foreign-field arithmetic from scratch — a research effort comparable in scope to building `circom-pairing` itself. The constraint count would be in the same order of magnitude (estimated 15–25M+ for the pairing alone).

## snarkjs Recursion Story

snarkjs has no native proof-of-proof mechanism. PSE's `maze` CLI aggregates PLONK proofs via a Halo2 aggregation circuit, but required 214 GB RAM and over an hour for 50 proofs. Using snarkjs JS prover (not rapidsnark) for a 10–20M constraint circuit adds another 5–10× slowdown over the numbers above.

## Comparison with gnark

| | circom-pairing (BLS12-381-in-BN254) | gnark emulated (BLS12-381-in-BN254) |
|---|---|---|
| Constraints (single pairing) | 11.4M | 2.09M (~5.5× fewer) |
| Prove time | 52 s on 32-core server | 7.4 s on MacBook M1 |
| Proving key | 6.5 GB | ~1.2 GB (estimated) |
| Hardware required | 256 GB RAM server | Consumer laptop |
| Production readiness | Not audited, known bugs | Active library, tested |

The BN254-in-BLS12-381 direction (what this project needs) has no circom implementation to compare against, but the same structural analysis applies: gnark's dedicated `emulated.Field` layer is significantly more constraint-efficient than Circom's hand-rolled big-integer arithmetic.

## Key Findings

1. **RISC Zero is not a precedent for cross-curve Circom**: its Circom circuit verifies a Baby Bear STARK (a small-field computation), not a BN254 pairing. Baby Bear arithmetic in BN254 Circom requires no foreign-field emulation.

2. **BN254 Groth16 verification in BLS12-381 Circom requires foreign-field arithmetic**: the two primes are of similar magnitude (~2^254 vs ~2^255), so BN254 Fp multiplication overflows BLS12-381 Fr.

3. **No such circuit exists publicly**: the `circom-pairing` library covers the reverse direction only (BLS12-381-in-BN254). Building BN254-in-BLS12-381 would be a new research project.

4. **circom-pairing constraint overhead is ~5.5× gnark**: 11.4M vs 2.09M constraints for a single pairing, translating to 52 s on a 32-core server vs 7.4 s on a laptop. Proving keys are multi-gigabyte, requiring server-class RAM.

5. **Circom is not a viable alternative to gnark for this project**: no existing library, higher constraint overhead, no BLS12-381 Groth16 proving backend in snarkjs, and known security issues in the closest analog.
