# Pedersen-Commitment Check On Cardano (Bowe–Gabizon)

The recursive Groth16/BLS12-381 wrapper unavoidably emits one Pedersen commitment per
proof (Bowe–Gabizon, [eprint 2022/1072](https://eprint.iacr.org/2022/1072)) because
gnark's emulated-BN254 rangechecks need a Fiat-Shamir challenge from a commitment.
The Aiken verifier must reproduce three pieces of the gnark verifier verbatim:

1. The implicit folded public input `commit_fr` derived from `proof.commitments[0]`.
2. The Pedersen proof-of-knowledge pairing equation.
3. The way `commit_fr` and the commitment point are mixed into the Groth16 IC accumulation.

All three are transcribed from
`backend/groth16/bls12-381/verify.go` and
`ecc/bls12-381/fr/pedersen/pedersen.go` in gnark-crypto. The wrapper's setup uses
**one** commitment key with **`public_and_commitment_committed = [[]]`** — i.e. no
private wires are committed beyond the implicit `commit_fr` itself — so the algorithm
collapses considerably from the general form. This ADR pins **only** that one-commitment,
empty-committed-wires shape; if the gnark wrapper circuit ever changes the commitment
shape, the verifier and this ADR must be revisited together.

## On-chain inputs (per outer proof)

| Field | Source | Bytes | Notes |
|---|---|---|---|
| `commitment` | `outer_proof.json` `proof.commitments[0]` | 48 (compressed G1) | Cardano `bls12_381_g1_uncompress` accepts this directly. |
| `commitment_uncompressed` | Reconstructed off-chain from `commitment` | 96 (uncompressed G1) | The exact `proof.Commitments[i].Marshal()` output gnark hashes. **Carried alongside the proof** because Plutus has no `g1_to_uncompressed_bytes` builtin. |
| `commitment_pok` | `outer_proof.json` `proof.commitment_pok` | 48 (compressed G1) | |

The `commitment_uncompressed` field is part of the on-chain redeemer (or hard-baked into
the test fixture for the spike). The validator binds it to `commitment` so a malicious
prover cannot freely choose what gets hashed — see *Binding* below.

## 1. `commit_fr` derivation

```
H        = ExpandMsgXmd_SHA256
DST      = "bsb22-commitment"          (16 ASCII bytes, no NUL terminator)
L        = 48                          (gnark constant for BLS12-381 Fr: L = 16 + 32)
msg      = commitment_uncompressed     (exactly 96 bytes, gnark RawBytes layout)
prf      = H(msg, DST, L)              (48-byte pseudo-random output)
commit_fr = bigEndian(prf) mod r       (reduce the 48-byte big-endian integer mod r)
```

where `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`
(BLS12-381 Fr modulus, 255 bits).

`ExpandMsgXmd_SHA256` is RFC 9380 §5.3.1 with SHA-256 as the inner hash. For `L = 48`
the function does exactly two SHA-256 invocations:

```
b0 = SHA256( zero_pad(64) ‖ msg ‖ I2OSP(L, 2) ‖ I2OSP(0, 1) ‖ DST ‖ I2OSP(len(DST), 1) )
b1 = SHA256( b0 ‖ I2OSP(1, 1) ‖ DST ‖ I2OSP(len(DST), 1) )
b2 = SHA256( (b0 XOR b1) ‖ I2OSP(2, 1) ‖ DST ‖ I2OSP(len(DST), 1) )
prf = (b1 ‖ b2)[0..48]   # 48-byte output, first two SHA-256 blocks of the expander
```

`zero_pad(64)` is 64 zero bytes (SHA-256 block size). For our fixed `DST` and `L`,
all the framing bytes (`I2OSP(L, 2) = 00 30`, `I2OSP(0, 1) = 00`, `I2OSP(1, 1) = 01`,
`I2OSP(2, 1) = 02`, `I2OSP(len(DST), 1) = 10`) are constants and can be embedded
as a single byte string at codegen time.

The reduction `bigEndian(prf) mod r` is a single integer division. Plutus
`bytearray_to_integer (#big-endian) prf` returns the integer; `%` reduces it mod `r`.

## 2. Binding `commitment_uncompressed` to `commitment`

`commitment_uncompressed` is 96 bytes in **gnark RawBytes layout**:

```
bytes[0..48]  = x  (big-endian, top 3 bits are metadata)
bytes[48..96] = y  (big-endian)
```

For a non-infinity uncompressed point the metadata bits are `000`. For an infinity
uncompressed point they are `010` (`0x40`). The remaining 381 bits of `bytes[0..48]`
are the x-coordinate, big-endian.

The compressed encoding of the *same* point is 48 bytes whose top 3 bits encode
`(compression=1, infinity, y-sign)`:

| Top 3 bits | Hex prefix | Meaning |
|---|---|---|
| `100` | `0x80` | Compressed, finite, y is lexicographically smallest. |
| `101` | `0xa0` | Compressed, finite, y is lexicographically largest. |
| `110` | `0xc0` | Compressed point at infinity (remaining bytes must be zero). |

The y-sign is **largest** iff `y > q - y`, i.e. `2*y > q`, where
`q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`
(BLS12-381 Fp modulus, 381 bits).

The validator reconstructs the compressed encoding from `commitment_uncompressed` and
asserts byte-equality with `commitment`. Algorithm (assuming a finite point):

```
x_word_0  = byte 0 of commitment_uncompressed                 # contains top 3 = 000
x_msb     = (x_word_0 AND 0x1F)                                # strip metadata, keep top 5 bits of x
y_int     = bytearray_to_integer(commitment_uncompressed[48..96], big-endian)
flag      = if 2 * y_int > q then 0xa0 else 0x80
expected  = cons_bytearray(flag OR x_msb, commitment_uncompressed[1..48])
assert expected == commitment
```

Subgroup membership and on-curve membership of the input point are enforced by
Cardano's `bls12_381_g1_uncompress` builtin on `commitment` (it rejects malformed
points). Combined with the binding above, that guarantees `commitment_uncompressed`
encodes the same on-curve, in-subgroup point as `commitment`.

The infinity case (`prefix = 0x40` on uncompressed, `0xc0` on compressed) is rejected
by the validator: a commitment at infinity means the prover committed to zero, which
indicates a malformed wrapper proof. This keeps the binding logic single-branch.

## 3. Pedersen PoK pairing equation

With one commitment and one PoK, gnark-crypto's `pedersen.BatchVerifyMultiVk`
collapses to the same equation as `pedersen.VerifyingKey.Verify`:

```
e(commitment, g_sigma_neg) * e(commitment_pok, g) == 1_GT
```

In Aiken this is a single two-element pairing check:

```aiken
let lhs = bls12_381_miller_loop(commitment_g1, g_sigma_neg_g2)
let rhs = bls12_381_miller_loop(commitment_pok_g1, g_g2)
bls12_381_final_verify(lhs, rhs_inv)   // or equivalent product == 1_GT formulation
```

`g` and `g_sigma_neg` are taken from `outer_vk.json` `commitment_keys[0]` and embedded
as constants at codegen time.

The Fiat-Shamir combination coefficient `fr.Hash(commitmentsSerialized, "G16-BSB22", 1)`
in `verify.go` is **not** used in the single-commitment case: it appears only as a
linear-combination factor for `i >= 1` in the batch (`pedersen.go:255-260`). For
`len(vk) == 1` no factor is applied and the challenge value is irrelevant. The
validator therefore does not need to recompute it.

## 4. Groth16 IC accumulation with `commit_fr`

The wrapper's outer VK has `len(IC) = max_inputs + 2 + 1 = 11` (for `MAX_INPUTS = 8`).
The public input vector consumed by `groth16.Verify` is

```
publicWitness = [InnerVKHash, inputs[0..7], commit_fr]   # length 10
```

and gnark computes (`verify.go` lines 100-108):

```
vk_x = IC[0] + Σ_{i=0..9} IC[i+1] * publicWitness[i]
vk_x = vk_x + commitment        # commitment point added directly, not via IC[10]
```

The final Groth16 check is the standard 4-pairing equation:

```
e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
```

The commitment point being mixed in *after* IC accumulation (the extra `+ commitment`)
is the Bowe-Gabizon binding — it is what forces the prover to use the exact same
commitment in both the Pedersen check and the Groth16 check.

## Validator flow

```
verify(pi_a, pi_b, pi_c,
       commitment, commitment_uncompressed, commitment_pok,
       public_inputs):                           // public_inputs = [vkhash, input_0..input_7]

  1. Bind:                 reconstructed_compressed == commitment    (Section 2)
  2. commit_fr           := ExpandMsgXmd_SHA256(commitment_uncompressed) mod r   (Section 1)
  3. Pedersen PoK check:   e(commitment, g_sigma_neg) * e(commitment_pok, g) == 1   (Section 3)
  4. extended_inputs     := [vkhash, input_0..input_7, commit_fr]
  5. vk_x                := IC[0] + Σ IC[i+1] * extended_inputs[i] + commitment    (Section 4)
  6. Groth16 pairing:      e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
```

All on-chain primitives are Plutus V3 builtins: `bls12_381_g1_uncompress`,
`bls12_381_g2_uncompress`, `bls12_381_g1_scalar_mul`, `bls12_381_g1_add`,
`bls12_381_miller_loop`, `bls12_381_mul_miller_loop_result`, `bls12_381_final_verify`,
`sha2_256`, `bytearray_to_integer`, `slice_bytearray`, `cons_bytearray`,
`append_bytearray`.

## What this ADR does **not** cover

- **Multiple commitments or non-empty `public_and_commitment_committed`.** The gnark
  wrapper in this repo emits exactly one commitment with no committed wires; if that
  ever changes the algorithm in Section 1 extends to include those wires in the
  hash preimage and Section 3 starts using the linear-combination coefficient.
  Re-read `verify.go` and revise this ADR before the verifier changes.
- **Codegen.** The constants `g`, `g_sigma_neg`, and the IC array are baked at codegen
  time per outer VK (ADR-0004); this ADR specifies what the code *does*, not how the
  template is parameterised.
- **The off-chain helper that produces `commitment_uncompressed`.** It is one line of
  gnark-crypto: `proof.Commitments[0].Marshal()`. The wrapper plugin (Phase 4) is the
  natural place for it.

## References

- gnark `backend/groth16/bls12-381/verify.go`
- gnark-crypto `ecc/bls12-381/fr/pedersen/pedersen.go` (`Verify`, `BatchVerifyMultiVk`)
- gnark-crypto `field/hash/hashutils.go` (`ExpandMsgXmd`)
- gnark `constraint/commitment.go` (`CommitmentDst = "bsb22-commitment"`)
- gnark-crypto `ecc/bls12-381/marshal.go` (`G1Affine.RawBytes`, `Bytes`)
- RFC 9380 §5.3.1 (`expand_message_xmd`)
- Bowe–Gabizon, [eprint 2022/1072](https://eprint.iacr.org/2022/1072)
- [`docs/schemas/outer-proof-artifacts.md`](../schemas/outer-proof-artifacts.md)
- [`docs/adr/0004-gnark-prover-cli.md`](0004-gnark-prover-cli.md)
- [`docs/adr/0004-rust-plugin-owns-aiken-codegen.md`](0004-rust-plugin-owns-aiken-codegen.md)
