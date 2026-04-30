# snarkjs Cardano Aiken Verifiers

## Overview

Extended [iden3/snarkjs](https://github.com/iden3/snarkjs) (via fork [dkaidalov/snarkjs](https://github.com/dkaidalov/snarkjs)) to generate **Cardano Plutus V3 smart contract verifiers** written in **Aiken** for three proof systems: Groth16, PLONK, and FFLONK — all targeting the **BLS12-381** curve natively supported by Cardano (CIP-0381).

The result is a complete off-chain → on-chain pipeline:
1. **Prove** (off-chain, in Node.js using snarkjs)
2. **Export** a self-contained Aiken verifier module from a `.zkey` file
3. **Deploy** the verifier as a Plutus V3 smart contract
4. **Submit** proofs as transaction redeemer data

---

## Background

### snarkjs and circom

**circom** is a domain-specific language for writing arithmetic circuits (ZK programs). A circuit in circom compiles to an R1CS constraint system and a WASM witness calculator.

**snarkjs** is the JavaScript companion tool for circom. It handles:
- Powers-of-Tau ceremony (universal SRS generation)
- Circuit-specific setup (generates proving key `.zkey` and verification key)
- Proof generation from a witness
- Verification (JavaScript-side)
- Export of verifiers to target languages (Solidity, and now Aiken)

Proof systems supported by snarkjs:
| System | Type | Setup | Proof size |
|--------|------|-------|------------|
| Groth16 | SNARK | Circuit-specific | Small (3 G1 + 1 G2) |
| PLONK | SNARK | Universal | Medium (9 G1 + 6 Fr) |
| FFLONK | SNARK | Universal | Compact (4 G1 + 15 Fr) |

### Cardano / Plutus V3 and BLS12-381

CIP-0381 added native BLS12-381 operations to Plutus V3 as built-in functions:
- `bls12_381_g1_uncompress` / `bls12_381_g2_uncompress` — decompress points
- `bls12_381_g1_scalar_mul`, `bls12_381_g1_add` — G1 arithmetic
- `bls12_381_miller_loop`, `bls12_381_final_verify` — pairing check
- `keccak_256`, `integer_to_bytearray`, `bytearray_to_integer` — hashing and serialization

This makes it possible to implement SNARK verification directly in a Plutus smart contract.

### Aiken

Aiken is Cardano's native smart contract language (syntax similar to Gleam/Rust). Key gotchas discovered during implementation:
- **No `<>` for ByteArray concatenation** — `<>` is parsed as `<` then `>` (comparison operators). Must use `builtin.append_bytearray()`.
- **No trailing commas in single-argument function calls** — `f(x,)` is a syntax error.
- **Aiken compiler output invisible in Git Bash on Windows** — must use PowerShell or native terminal to see error messages.

---

## Architecture

```
circom circuit
      |
      v
 snarkjs setup
      |
      v
  circuit.zkey  ───────────────────────────────────────────────┐
      |                                                          |
      v                                                          v
 snarkjs prove                                    snarkjs exportAikenVerifier
(off-chain, Node.js)                                     (EJS template)
      |                                                          |
      v                                                          v
  proof.json                                        validators/xxx_verifier.ak
      |                                                          |
      v                                                          v
 snarkjs exportAikenCallData                        aiken check (compile + test)
      |                                                          |
      v                                                          v
  redeemer JSON                                      deploy to Cardano mainnet
      |                                                          |
      └──────────────────────────────────────────────────────────┘
                    submit tx with proof as redeemer
```

---

## Implementation

### Compressed Point Transcript

All three Aiken verifiers use a **compressed-point Keccak-256 Fiat-Shamir transcript** (`src/Keccak256TranscriptCompressed.js`). This uses 48-byte Zcash/BLST-format compressed G1 points instead of 96-byte uncompressed points.

The reason: Plutus V3 builtins only accept and return **compressed** points — smart contracts cannot operate on uncompressed points directly. So the off-chain challenge derivation in snarkjs must mirror the on-chain computation and use the same compressed representation.

This transcript is used automatically for BLS12-381 curves in both `plonk_prove.js` and `plonk_verify.js` (and similarly for FFLONK). The original `Keccak256Transcript` (using uncompressed points) is still used for BN128/BN254.

---

### Groth16 Verifier

**Files:**
- `src/zkey_export_aikenverifier.js` — reads Groth16 zkey, renders template
- `src/groth16_exportaikencalldata.js` — exports proof as compressed JSON
- `templates/verifier_groth16.ak.ejs` — Aiken verifier template
- `cli.js` commands: `zkeav` (verifier), `zkeac` (calldata)

**Verification algorithm:**
Groth16 uses 3 pairings:
```
e(A, B) == e(vk_alpha, vk_beta) * e(vk_gamma_abc[0] + sum(pi_i * vk_gamma_abc[i+1]), vk_gamma) * e(C, vk_delta)
```

**Proof structure:** `{A: G1, B: G2, C: G1}` + public signals

**VK structure:** `{alpha: G1, beta: G2, gamma: G2, delta: G2, IC: [G1]}` (one IC point per public input + 1)

---

### PLONK Verifier

**Files:**
- `src/plonk_exportaikenverifier.js` — reads PLONK zkey, precomputes `vk_bytes`, renders template
- `src/plonk_exportaikencalldata.js` — exports proof as compressed JSON
- `templates/verifier_plonk.ak.ejs` (~451 lines) — Aiken verifier template
- `cli.js` commands: `zkeapv` (verifier), `zkeapc` (calldata)

**Fiat-Shamir transcript rounds:**
```
beta, gamma  = H(vk_bytes || public_signals || A || B || C)
alpha        = H(beta || gamma || Z)
xi           = H(alpha || T1 || T2 || T3)
v1..v5       = H(xi || Wxi)
u            = H(Wxi || Wxiw)
```

**Verification:** Single pairing check using KZG polynomial commitment opening.

**Proof structure:** `{A, B, C, Z, T1, T2, T3, Wxi, Wxiw: G1, eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw: Fr}`

**VK structure:** 8 G1 selector/permutation commitments `(Qm, Ql, Qr, Qo, Qc, S1, S2, S3)` + `X_2: G2`

**`vk_bytes` optimization:** The 8 VK G1 points are concatenated into a single hex literal at export time (in the JS exporter) rather than concatenated at runtime in the smart contract. This avoids a chain of `builtin.append_bytearray` calls for a constant value.

---

### FFLONK Verifier

FFLONK ("Fast PLONK") is more complex but produces smaller proofs and faster verification. The implementation required the largest template (~829 lines).

**Files:**
- `src/fflonk_exportaikenverifier.js` — reads FFLONK zkey, extracts roots of unity and VK
- `src/fflonk_exportaikencalldata.js` — exports proof as compressed JSON
- `templates/verifier_fflonk.ak.ejs` (~829 lines) — Aiken verifier template
- `cli.js` commands: `zkeafv` (verifier), `zkeafc` (calldata)

**Key fix — curve-agnostic root of unity computation:**
The original snarkjs FFLONK setup hardcoded BN128-specific values for `w3` (primitive 3rd root of unity) and `wr`. This was generalized to work with any curve:
```javascript
// Works for any curve where p-1 is divisible by 3
const exponent = (Fr.p - 1n) / 3n;
let w3 = Fr.exp(Fr.e(7), exponent);
```

**Fiat-Shamir transcript rounds:**
```
beta, gamma  = H(C0 || public_inputs || C1)
xi_seed      = H(gamma || C2)
xi           = xi_seed^24     // evaluation point
y            = H(xi_seed || evals...)
```

**Evaluation root groups:**
FFLONK evaluates polynomials at 18 points organized in 3 groups:
- `h0w8[0..7]` = xi_seed^3 * w8^i (8 roots, for S0 Lagrange)
- `h1w4[0..3]` = xi_seed^6 * w4^i (4 roots, for S1 Lagrange)
- `h2w3[0..2]` = xi_seed^8 * w3^i (3 roots, for S2 group 1)
- `h3w3[0..2]` = xi_seed^8 * wr * w3^i (3 roots, for S2 group 2)

**Montgomery batch inversion:** 18 field inversions (for Lagrange denominators) are reduced to 1 inversion + ~50 multiplications using Montgomery's trick. Critical for on-chain efficiency.

**Final pairing check:**
```
e(A1, G2_gen) == e(W2, X_2)
where:
  A1 = (F - E - J) + y*W2
  F  = C0 + q1*C1 + q2*C2
  E  = G1_gen * (r0 + q1*r1 + q2*r2)
  J  = W1 * mulH0
```

**Proof structure:** `{C1, C2, W1, W2: G1, eval_ql, eval_qr, eval_qm, eval_qo, eval_qc, eval_s1, eval_s2, eval_s3, eval_a, eval_b, eval_c, eval_z, eval_zw, eval_t1w, eval_t2w: Fr}`

**VK structure:** `{C0: G1, X_2: G2}` plus domain parameters and precomputed roots of unity

---

## Comparison

| | Groth16 | PLONK | FFLONK |
|--|---------|-------|--------|
| **Setup** | Circuit-specific | Universal | Universal |
| **G1 proof points** | 3 | 9 | 4 |
| **G2 proof points** | 1 | 0 | 0 |
| **Fr evaluations** | 0 | 6 | 15 |
| **VK G1 points** | n+1 (n = public inputs) | 8 | 1 |
| **Pairings** | 3 | 1 | 1 |
| **Template lines** | ~250 | ~451 | ~829 |
| **On-chain mem** | ~2M | ~3M | ~4M |
| **On-chain cpu** | ~3.5B | ~4.7B | ~6B |
| **Transcript** | None (no Fiat-Shamir) | Keccak-256 compressed | Keccak-256 compressed |

---

## Testing

Each proof system has:
- **Unit tests** in `test/aiken.test.js` — verifier export structure, VK embedding, proof embedding, round-trip verification
- **Test fixtures** in `test/{protocol}_bls12381/` — circuit, zkey, proof, public signals, verification key
- **Integration test** in `smart_contract_tests/aiken/test/aiken_{protocol}_verifier.test.js` — generates the verifier and runs `aiken check` which compiles and executes embedded inline tests

Inline tests embedded in each verifier:
```
test verify_valid_proof()       // must pass
test verify_invalid_proof() fail // must fail (tampered public signal)
```

Resource consumption (Aiken inline tests, BLS12-381):
| Verifier | Memory | CPU |
|----------|--------|-----|
| Groth16 | ~2.8M | ~3.5B |
| PLONK | ~3.0M | ~4.7B |
| FFLONK | ~4.0M | ~6.0B |

All are within Plutus V3 script execution limits.

The Aiken project for integration tests is at `smart_contract_tests/aiken/` (project name: `snarkjs/aiken_verifiers`, Plutus V3, compiler 1.1.19, stdlib v2.2.0).

---

## CLI Commands

```bash
# Groth16
snarkjs zkey export aikenverifier circuit.zkey verifier.ak
snarkjs zkey export aikencalldata public.json proof.json

# PLONK
snarkjs zkey export aikenplonkverifier circuit.zkey verifier.ak
snarkjs zkey export aikenplonkcalldata public.json proof.json

# FFLONK
snarkjs zkey export aikenfflonkverifier circuit.zkey verifier.ak
snarkjs zkey export aikenfflonkcalldata public.json proof.json
```

Short aliases: `zkeav`, `zkeac`, `zkeapv`, `zkeapc`, `zkeafv`, `zkeafc`

---

## Repository

- **Fork**: `dkaidalov/snarkjs` (based on `iden3/snarkjs`)
- **Merged PRs**:
  - Groth16 Aiken verifier (sessions 1–3)
  - PLONK BLS12-381 Aiken verifier
  - FFLONK BLS12-381 Aiken verifier
- **Branch**: `master`
- **Aiken version**: v1.1.19

---

## Relation to Other Research

This implementation is a concrete realization of the on-chain verifier component described in [Universal ZK Wrapper for Cardano](universal-zk-wrapper-for-cardano.md). That document describes wrapping BN254 proofs from zkVMs into BLS12-381 Groth16 proofs for Cardano. The Groth16 Aiken verifier produced here is exactly the on-chain component of that pipeline.

PLONK and FFLONK verifiers extend this by allowing **native** circom/snarkjs circuits on BLS12-381 without a proof wrapping step — at the cost of a larger verifier and slightly higher on-chain resources.
