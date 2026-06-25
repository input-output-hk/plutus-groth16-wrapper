// gnark Groth16/BLS12-381 outer wrapper verifier in Aiken.
//
// Implements the on-chain side of `docs/adr/0006-pedersen-commitment-check-on-cardano.md`
// against a single hard-coded outer-VK + outer-proof fixture produced by
// `zkwrap-gnark` at MAX_INPUTS = 8 with the RISC Zero canonical inner proof.
//
// Two verifier layers:
//   * `verify`        — outer layer: generic Groth16/BLS12-381 + Bowe–Gabizon binding.
//   * `verify_risc0`  — inner layer: reconstruct the 5 RISC Zero public inputs from
//                       `journal_bytes` + version constants, then delegate to the outer layer.
//
// Soundness gap: this spike treats the point-at-infinity case for `commitment` as
// out-of-band (validator fails on it). Production codegen must either handle infinity
// explicitly or document why the wrapper circuit can never produce it.

use aiken/builtin
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray

// =====================================================================
// Field moduli for BLS12-381
// =====================================================================
// Fr (scalar field) modulus is handled inside `scalar.from_bytes` (stdlib v3.0.0).

// Fp (base field) modulus — not in stdlib; needed for the y-sign reconstruction.
const q_modulus: Int =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

// =====================================================================
// ExpandMsgXmd_SHA256 constants for DST = "bsb22-commitment", L = 48
// =====================================================================

// DST_prime = "bsb22-commitment" (16 ASCII bytes) || I2OSP(16, 1) = 0x10
const dst_prime: ByteArray = #"62736232322d636f6d6d69746d656e7410"

// l_i_b_str (I2OSP(48, 2)) || I2OSP(0, 1) = 0x00 0x30 0x00
const l_i_b_zero: ByteArray = #"003000"

// Z_pad: 64 zero bytes (one SHA-256 block).
const z_pad: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// =====================================================================
// Outer VK constants (gnark Groth16/BLS12-381, MAX_INPUTS = 8)
// Source: zkwrap-gnark/testdata/groth16-setup/outer_vk.json
// =====================================================================

const vk_alpha_g1: ByteArray =
  #"b0a27b5ce1e9e0fb9b1e0930686f8f3b8198c17927f23ea4925baf618661e699ace14793be2cc7b8df30b3478351bec6"

const vk_beta_g2: ByteArray =
  #"905d5c50a06dec78f686c893de5c7429aab20c940920a87753b09d7abb4d02b59d051e78d5497f0f0325b0b052b0013c11694f19dcce996f1cd059441adb4eb60a518bc0f1adb3c64ef90f4f6c68b60796b3a1a0614daac11a46465df06c6faf"

const vk_gamma_g2: ByteArray =
  #"853c35ce370d727351b36099ee7b8a04b2845e5264616adbdfb40fd2026a270f74b61e24642333aac371e480798df7ce0aea07f10ed71b4a115f2b1cad8d22c0ff94ed70c3358c46704c160958edb623d4d54a6e183d8587507f674a8f2ae14b"

const vk_delta_g2: ByteArray =
  #"b16c1dfbe711cf117d21e99b97d4f90fa5883ab0616acff8bde0582beb548675031938f1d8e1cfdf82070273e01697c519ffc0cd75c1f438e0fde041907bc47e8270b76daa9331e118c27b768b5d30b336d971852a1f9e3f0c789f87656229d8"

// IC array (11 entries: 1 constant + 1 vk-hash + 8 input + 1 commit-fr).
const ic_0: ByteArray =
  #"83141fac2a1f5e7bb7e19b087bd505ae7a576676a430e61b901cd2b48ac80247042b72af3cf0800fdf7ea7f4e0031dfa"

const ic_1: ByteArray =
  #"b602f4e6ad22f5e9fa969f6508ee486f6fd414d46961d3643eb73077f42487f27aa120c14a516819cd6fee019e0a0919"

const ic_2: ByteArray =
  #"87c97d72cb62fb36cf153d3e7acedb30ec2be288ed880ffbe1dcf5f6601e2ae70d52916cdcb2e1302bc5167a411c517f"

const ic_3: ByteArray =
  #"83e47ffd1e9ecad3e18cd2f16cbe9d3801b00106315d670afd22d2fc23e878bbe20bb1744a7f98a7d994f41960bfddc9"

const ic_4: ByteArray =
  #"a3a2a86ba764ddd7a182ad1ecc75fc039ade36c7e39b7afc68174db632e9c1037ef94c3909fcf8b2139f178efb1b0edd"

const ic_5: ByteArray =
  #"95ee93351865789f5ea89c60260a0878e168a89d07e9eb7a1689e9af6073b6dcfd68134d9700b13aa597e3c1797ff3a7"

const ic_6: ByteArray =
  #"b3798cb09229bacb1bdd3fea2066c57e0c00e8ea102e7342f24337c7b4ff1ad02f2e1611b58f7efaafacb0f8186fbe89"

const ic_7: ByteArray =
  #"b0d8a0ef236589c5771b3513bb63bd7d79e935bde7ca898746572b8460fdf148886dff7d53d48bd9cd27cc13bd216bf8"

const ic_8: ByteArray =
  #"99fdf89a1b3fce68be6eea732401825a373e110e792e885dd91fbd3b65db3e88fc3b1e4d69abdb4bc978afcef8dec36a"

const ic_9: ByteArray =
  #"b1d4d175a82fe54f350b9c10f44a97b483b6acce311caa6d625fd91ab0ff695a45479129d5c78046f2524665c460ecaf"

const ic_10: ByteArray =
  #"b4735b66c0f8613d4b58e2b55417f8ce7131345751ce89a137b014498c4aa6dbf593bc62f66f5186604edefc69747352"

// Pedersen commitment-key (one entry).
const ck_g: ByteArray =
  #"b8d2c3409d4459d9cd542f769fc05b9d64eb0488426c2131f8fcb35dd777d5a1e27cf9b4f6b3b71039a4b28c376fbcff18d6d4b914605b7e16ac2bd8526227455f4cf9aec4216ddf27607e6d7f1885f3182b3cb6d3917070ec3b91d2dff57e00"

const ck_g_sigma_neg: ByteArray =
  #"a293e6ccd6fad9ddc0e188d26dfaa1782c16b4f2419a32c623844342bd60be7d18ab11b3375e88b113498204ed45e0150cbdaaed4adbba75e150c80f7352d77702652107cfa92848a4dcbbe67fb376d0d07db2fbc653dd564d9dc2926d273e9a"

// =====================================================================
// ExpandMsgXmd_SHA256(msg, "bsb22-commitment", L = 48)
// RFC 9380 §5.3.1
// =====================================================================

fn expand_msg_xmd_48(msg: ByteArray) -> ByteArray {
  let b0_msg =
    z_pad
      |> builtin.append_bytearray(msg)
      |> builtin.append_bytearray(l_i_b_zero)
      |> builtin.append_bytearray(dst_prime)
  let b0 = builtin.sha2_256(b0_msg)

  let b1_msg =
    b0
      |> builtin.append_bytearray(#"01")
      |> builtin.append_bytearray(dst_prime)
  let b1 = builtin.sha2_256(b1_msg)

  let b2_msg =
    bytearray.xor_bytes(b0, b1, False)
      |> builtin.append_bytearray(#"02")
      |> builtin.append_bytearray(dst_prime)
  let b2 = builtin.sha2_256(b2_msg)

  // Output = (b1 || b2)[0..48] = b1 || b2[0..16]
  builtin.append_bytearray(b1, bytearray.take(b2, 16))
}

fn hash_to_fr(uncompressed_g1: ByteArray) -> Int {
  uncompressed_g1
    |> expand_msg_xmd_48
    |> scalar.from_bytes
    |> scalar.to_int
}

// =====================================================================
// Compressed ↔ uncompressed G1 binding
// =====================================================================

// Reconstruct the canonical 48-byte compressed encoding of a non-infinity
// G1 point from its 96-byte gnark RawBytes encoding (x_be || y_be, top 3
// bits of byte 0 are 0b000 for a finite point).
fn compress_from_uncompressed(uncompressed: ByteArray) -> ByteArray {
  let y_int = bytearray.to_int_big_endian(bytearray.slice(uncompressed, 48, 95))
  let sign_flag =
    if 2 * y_int > q_modulus {
      0xa0
    } else {
      0x80
    }
  // x byte 0 has top 3 bits = 000 (uncompressed-regular). Mask them with AND 0x1F
  // (= mod 32) and OR-in the sign+compression flag, then keep x bytes 1..47 verbatim.
  let head = sign_flag + bytearray.at(uncompressed, 0) % 32
  builtin.cons_bytearray(head, bytearray.slice(uncompressed, 1, 47))
}

// =====================================================================
// Groth16 IC accumulation
// =====================================================================

// Returns vk_x = IC[0]
//              + IC[1] * inner_vk_hash
//              + Σ_{i=0..7} IC[i+2] * inputs[i]
//              + IC[10] * commit_fr
//              + commitment
fn compute_vk_x(
  inner_vk_hash: Int,
  inputs: List<Int>,
  commit_fr: Int,
  commitment_g1: G1Element,
) -> G1Element {
  let acc = add_term(builtin.bls12_381_g1_uncompress(ic_0), inner_vk_hash, ic_1)

  // TODO: use MSM builtin when it's available in Aiken
  expect [i0, i1, i2, i3, i4, i5, i6, i7] = inputs
  let acc = add_term(acc, i0, ic_2)
  let acc = add_term(acc, i1, ic_3)
  let acc = add_term(acc, i2, ic_4)
  let acc = add_term(acc, i3, ic_5)
  let acc = add_term(acc, i4, ic_6)
  let acc = add_term(acc, i5, ic_7)
  let acc = add_term(acc, i6, ic_8)
  let acc = add_term(acc, i7, ic_9)

  let acc = add_term(acc, commit_fr, ic_10)

  builtin.bls12_381_g1_add(acc, commitment_g1)
}

fn add_term(acc: G1Element, scalar: Int, ic_point: ByteArray) -> G1Element {
  if scalar == 0 {
    acc
  } else {
    builtin.bls12_381_g1_add(
      acc,
      builtin.bls12_381_g1_scalar_mul(
        scalar,
        builtin.bls12_381_g1_uncompress(ic_point),
      ),
    )
  }
}

// =====================================================================
// Outer-wrapper verifier
// =====================================================================

pub fn verify(
  pi_a: ByteArray,
  pi_b: ByteArray,
  pi_c: ByteArray,
  commitment: ByteArray,
  commitment_uncompressed: ByteArray,
  commitment_pok: ByteArray,
  inner_vk_hash: Int,
  inputs: List<Int>,
) -> Bool {
  // (1) Bind uncompressed bytes to the compressed point.
  expect compress_from_uncompressed(commitment_uncompressed) == commitment

  // (2) Derive commit_fr.
  let commit_fr = hash_to_fr(commitment_uncompressed)

  // (3) Pedersen PoK pairing check:
  //     e(commitment, g_sigma_neg) * e(commitment_pok, g) == 1_GT
  //     <=> e(commitment, g_sigma_neg) == e(-commitment_pok, g)
  let commitment_g1 = builtin.bls12_381_g1_uncompress(commitment)
  let pok_g1 = builtin.bls12_381_g1_uncompress(commitment_pok)
  let g_g2 = builtin.bls12_381_g2_uncompress(ck_g)
  let g_sigma_neg_g2 = builtin.bls12_381_g2_uncompress(ck_g_sigma_neg)
  let pok_lhs = builtin.bls12_381_miller_loop(commitment_g1, g_sigma_neg_g2)
  let pok_rhs =
    builtin.bls12_381_miller_loop(builtin.bls12_381_g1_neg(pok_g1), g_g2)
  expect builtin.bls12_381_final_verify(pok_lhs, pok_rhs)

  // (4) Groth16 IC accumulation.
  let vk_x = compute_vk_x(inner_vk_hash, inputs, commit_fr, commitment_g1)

  // (5) Groth16 pairing check:
  //     e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
  let a = builtin.bls12_381_g1_uncompress(pi_a)
  let b = builtin.bls12_381_g2_uncompress(pi_b)
  let c = builtin.bls12_381_g1_uncompress(pi_c)
  let alpha = builtin.bls12_381_g1_uncompress(vk_alpha_g1)
  let beta = builtin.bls12_381_g2_uncompress(vk_beta_g2)
  let gamma = builtin.bls12_381_g2_uncompress(vk_gamma_g2)
  let delta = builtin.bls12_381_g2_uncompress(vk_delta_g2)
  let lhs = builtin.bls12_381_miller_loop(a, b)
  let rhs =
    builtin.bls12_381_mul_miller_loop_result(
      builtin.bls12_381_miller_loop(alpha, beta),
      builtin.bls12_381_mul_miller_loop_result(
        builtin.bls12_381_miller_loop(vk_x, gamma),
        builtin.bls12_381_miller_loop(c, delta),
      ),
    )
  builtin.bls12_381_final_verify(lhs, rhs)
}

// =====================================================================
// Inner layer — RISC Zero journal authentication chain
// (see docs/research/risc0-artifact-format.md §6, §6a)
//
// Reconstructs claim_digest on-chain from journal_bytes using the
// RISC Zero `tagged_struct` hash convention. Three SHA-256 calls.
// Constants baked from the receipt for one specific guest image
// (risc0-circuit-recursion 4.0.4, multiply(17, 23) program).
// =====================================================================

// SHA256("risc0.Output")
const tag_output_digest: ByteArray =
  #"77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"

// SHA256("risc0.ReceiptClaim")
const tag_claim_digest: ByteArray =
  #"cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"

// pre.digest = tagged_struct("risc0.SystemState", &[merkle_root], &[pc])
// For the multiply guest image, this is the `image_id` from manifest.json.
const pre_state_digest: ByteArray =
  #"2bc2287e688aaf25754b3c5ab4f1b027e4dd0d51a2c05dc4e53e06961d89005a"

// post.digest = SystemState { pc: 0, merkle_root: ZERO }.digest()
const post_state_digest: ByteArray =
  #"a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2"

// input.Pruned([0;8]).digest() = Digest::ZERO (Input is uninhabited; receipt always carries pruned-zero).
const input_digest: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// Empty Assumptions list digest = ZERO (tagged_iter rfolds from Digest::ZERO).
const assumptions_digest: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// ExitCode::Halted(0).into_pair() = (0, 0). Two u32 LE = 8 zero bytes.
const sys_user_exit_le: ByteArray = #"0000000000000000"

// tagged_struct count suffixes (u16 LE).
const count_two_le: ByteArray = #"0200"
const count_four_le: ByteArray = #"0400"

// Version constants baked from risc0-circuit-recursion 4.0.4.
// inputs[0,1] are split_digest(control_root); inputs[4] is LE-int of bn254_control_id.
// Reading 16 bytes as little-endian is equivalent to reversing and reading big-endian.
const fx_expected_input_0: Int =
  0x41af18736dc9d7921c859fc95ac84da5

const fx_expected_input_1: Int =
  0x561f8c992a424deb37ccdf4e19c0e7db

const fx_expected_input_4: Int =
  0x04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0

fn compute_claim_digest_from_journal(journal_bytes: ByteArray) -> ByteArray {
  let journal_digest = builtin.sha2_256(journal_bytes)

  // Output = tagged_struct("risc0.Output", [journal_digest, ZERO], [])
  let output_preimage =
    tag_output_digest
      |> builtin.append_bytearray(journal_digest)
      |> builtin.append_bytearray(assumptions_digest)
      |> builtin.append_bytearray(count_two_le)
  let output_digest = builtin.sha2_256(output_preimage)

  // ReceiptClaim = tagged_struct("risc0.ReceiptClaim",
  //   [input, pre, post, output], [sys_exit_u32, user_exit_u32])
  let claim_preimage =
    tag_claim_digest
      |> builtin.append_bytearray(input_digest)
      |> builtin.append_bytearray(pre_state_digest)
      |> builtin.append_bytearray(post_state_digest)
      |> builtin.append_bytearray(output_digest)
      |> builtin.append_bytearray(sys_user_exit_le)
      |> builtin.append_bytearray(count_four_le)
  builtin.sha2_256(claim_preimage)
}

// RISC Zero split_digest convention: reverse bytes, split at 16, low half first.
// Equivalently, the 32-byte SHA-256 output read as two little-endian 16-byte halves.
fn risc0_inputs_from_journal(journal_bytes: ByteArray) -> List<Int> {
  let claim_digest = compute_claim_digest_from_journal(journal_bytes)
  let input_2 = bytearray.to_int_little_endian(bytearray.take(claim_digest, 16))
  let input_3 = bytearray.to_int_little_endian(bytearray.drop(claim_digest, 16))
  [
    fx_expected_input_0,
    fx_expected_input_1,
    input_2,
    input_3,
    fx_expected_input_4,
    0, 0, 0,
  ]
}

pub fn verify_risc0(
  pi_a: ByteArray,
  pi_b: ByteArray,
  pi_c: ByteArray,
  commitment: ByteArray,
  commitment_uncompressed: ByteArray,
  commitment_pok: ByteArray,
  inner_vk_hash: Int,
  journal_bytes: ByteArray,
) -> Bool {
  verify(
    pi_a,
    pi_b,
    pi_c,
    commitment,
    commitment_uncompressed,
    commitment_pok,
    inner_vk_hash,
    risc0_inputs_from_journal(journal_bytes),
  )
}

// =====================================================================
// Random-batched outer-wrapper verifier (single final_verify)
// =====================================================================
//
// Folds the Pedersen PoK pairing check and the Groth16 pairing check into
// one `bls12_381_final_verify` via a Fiat-Shamir random scalar `r`, saving
// one `final_exp` at the cost of two G1 scalar-muls + one SHA-256.
//
// Soundness (Fiat-Shamir + Schwartz–Zippel in a prime-order pairing group):
//   Let X = e(commitment, g_sigma_neg) * e(commitment_pok, g)       (Pedersen)
//   Let Y = e(A,B) / [e(α,β) * e(vk_x, γ) * e(C, δ)]                 (Groth16)
// The two original checks are X = 1 ∧ Y = 1. The combined check is
//   X^r · Y = 1
// modelling SHA-256 as a random oracle, an adversary that picks (X, Y) ≠ (1, 1)
// passes only when r is the unique discrete log r = log_X(Y⁻¹) — probability
// 1/r_modulus per attempted proof. Bound: ~255-bit security.
//
// Per-call cost trade vs the two-final_verify path:
//   saved:  one `bls12_381_final_verify` (one final_exp + equality check)
//   added:  one `sha2_256` over ~288 bytes
//           two `bls12_381_g1_scalar_mul` (Fr * G1)
//
// `bls12_381_g1_scalar_mul` cost scales linearly in the scalar's bit length
// (windowed double-and-add). Empirically the dominant overhead is the
// scalar-muls, not the hash, so we truncate the Fiat-Shamir output to 128
// bits — 128-bit soundness slack is standard for randomized batched
// pairing checks (e.g. arkworks / gnark) and halves the scalar-mul cost
// vs the natural 255-bit Fr. Resulting r in [0, 2^128) is always < field_prime,
// so no reduction step is needed.
// 
// BENCHMARKS: verify_batched provides only small improvement of CPU (3.72B vs 3.89B)
// for a meaningfully harder soundness story (random-oracle + Schwartz–Zippel argument) 
// So it's better to avoid batching.


fn batch_challenge(
  pi_a: ByteArray,
  pi_b: ByteArray,
  pi_c: ByteArray,
  commitment: ByteArray,
  commitment_pok: ByteArray,
) -> Int {
  pi_a
    |> builtin.append_bytearray(pi_b)
    |> builtin.append_bytearray(pi_c)
    |> builtin.append_bytearray(commitment)
    |> builtin.append_bytearray(commitment_pok)
    |> builtin.sha2_256
    |> bytearray.take(16)
    |> bytearray.to_int_big_endian
}

pub fn verify_batched(
  pi_a: ByteArray,
  pi_b: ByteArray,
  pi_c: ByteArray,
  commitment: ByteArray,
  commitment_uncompressed: ByteArray,
  commitment_pok: ByteArray,
  inner_vk_hash: Int,
  inputs: List<Int>,
) -> Bool {
  // (1) Bind uncompressed bytes to the compressed point.
  expect compress_from_uncompressed(commitment_uncompressed) == commitment

  // (2) Derive commit_fr.
  let commit_fr = hash_to_fr(commitment_uncompressed)

  // (3) Fiat-Shamir batch challenge over the prover's free choices.
  let r = batch_challenge(pi_a, pi_b, pi_c, commitment, commitment_pok)

  // (4) Groth16 IC accumulation.
  let commitment_g1 = builtin.bls12_381_g1_uncompress(commitment)
  let pok_g1 = builtin.bls12_381_g1_uncompress(commitment_pok)
  let vk_x = compute_vk_x(inner_vk_hash, inputs, commit_fr, commitment_g1)

  // (5) Scale Pedersen-side points in G1 (bilinearity: e(P,Q)^r = e(r·P, Q)).
  let r_commitment = builtin.bls12_381_g1_scalar_mul(r, commitment_g1)
  let r_pok = builtin.bls12_381_g1_scalar_mul(r, pok_g1)

  // (6) Combined pairing check:
  //     e(A, B) · e(r·commitment, g_sigma_neg) · e(r·pok, g)
  //         == e(α, β) · e(vk_x, γ) · e(C, δ)
  let a = builtin.bls12_381_g1_uncompress(pi_a)
  let b = builtin.bls12_381_g2_uncompress(pi_b)
  let c = builtin.bls12_381_g1_uncompress(pi_c)
  let alpha = builtin.bls12_381_g1_uncompress(vk_alpha_g1)
  let beta = builtin.bls12_381_g2_uncompress(vk_beta_g2)
  let gamma = builtin.bls12_381_g2_uncompress(vk_gamma_g2)
  let delta = builtin.bls12_381_g2_uncompress(vk_delta_g2)
  let g_g2 = builtin.bls12_381_g2_uncompress(ck_g)
  let g_sigma_neg_g2 = builtin.bls12_381_g2_uncompress(ck_g_sigma_neg)

  let lhs =
    builtin.bls12_381_mul_miller_loop_result(
      builtin.bls12_381_miller_loop(a, b),
      builtin.bls12_381_mul_miller_loop_result(
        builtin.bls12_381_miller_loop(r_commitment, g_sigma_neg_g2),
        builtin.bls12_381_miller_loop(r_pok, g_g2),
      ),
    )
  let rhs =
    builtin.bls12_381_mul_miller_loop_result(
      builtin.bls12_381_miller_loop(alpha, beta),
      builtin.bls12_381_mul_miller_loop_result(
        builtin.bls12_381_miller_loop(vk_x, gamma),
        builtin.bls12_381_miller_loop(c, delta),
      ),
    )
  builtin.bls12_381_final_verify(lhs, rhs)
}

pub fn verify_batched_risc0(
  pi_a: ByteArray,
  pi_b: ByteArray,
  pi_c: ByteArray,
  commitment: ByteArray,
  commitment_uncompressed: ByteArray,
  commitment_pok: ByteArray,
  inner_vk_hash: Int,
  journal_bytes: ByteArray,
) -> Bool {
  verify_batched(
    pi_a,
    pi_b,
    pi_c,
    commitment,
    commitment_uncompressed,
    commitment_pok,
    inner_vk_hash,
    risc0_inputs_from_journal(journal_bytes),
  )
}

// =====================================================================
// Fixture (single valid outer proof against the constants above)
// Source: zkwrap-gnark/testdata/groth16-outer-proof.json
// =====================================================================

const fx_pi_a: ByteArray =
  #"8ad0c2c6b3fc5cbf7f680d5fee40a3c7b75ace51993165f5871b005eac19b2ddf850a4b4a69044d3a24861a0a639eff3"

const fx_pi_b: ByteArray =
  #"a08997782cd356c1fb62ce825e6617dd005732aea6193e0dbc30f095a135b66670193af4c6bf60a27aa8a414acc0a8750e5a0b500f56ff45d3fa27f8e226f386b0d0164f23aa5936188d2eb8d58fbab3b203d1b48e501164dd4b0bba7eecc98c"

const fx_pi_c: ByteArray =
  #"93a5c2dc5adc536ec6ac35917ba349f387c2b402aabd6d332ce43b3dd4595d9d5635d067e52f5815e8c868c7fd64a499"

const fx_commitment: ByteArray =
  #"a82fa3134bc25666c7a42336409323186f0e920d92b7b56f35dfd89555624e4a23fe016711a3aa49ad8fdf6354382bb5"

// Off-chain reconstruction of `proof.Commitments[0].Marshal()` (gnark RawBytes).
// Top 3 bits of byte 0 are 0b000 (uncompressed-regular flag).
const fx_commitment_uncompressed: ByteArray =
  #"082fa3134bc25666c7a42336409323186f0e920d92b7b56f35dfd89555624e4a23fe016711a3aa49ad8fdf6354382bb5116ccd1de858164be8c500e11cc7ae929575911438a947eca4ab0392a9ba1f0fbeb8d2d56d4c76ce758f615511d53f1a"

const fx_commitment_pok: ByteArray =
  #"989a34c6686c5736c7d6ffc0f6cdc6a0deec921d98cb9ba0f952004984bc91941692ed18d43a409787c9223da380a94d"

const fx_inner_vk_hash: Int =
  0x0c42ca6b6e6c574b5b21c90360bed01945966b844fb47b5430d0d801bbe8e6ca

// Raw guest output for the multiply(17, 23) program: u64 LE = 391.
// Source: experiments/risc0-hello-world/fixtures/journal.bin
const fx_journal_bytes: ByteArray = #"8701000000000000"

// claim_digest reconstructed from fx_journal_bytes + version constants.
// Source: experiments/risc0-hello-world/fixtures/claim_digest.bin
const fx_expected_claim_digest: ByteArray =
  #"7cad906649785c4893e576973582aaff214f5ad2344e4f7ef575e3c6fc1ba432"

const fx_inputs: List<Int> =
  [
    0x0000000000000000000000000000000041af18736dc9d7921c859fc95ac84da5,
    0x00000000000000000000000000000000561f8c992a424deb37ccdf4e19c0e7db,
    0x00000000000000000000000000000000ffaa82359776e593485c78496690ad7c,
    0x0000000000000000000000000000000032a41bfcc6e375f57e4f4e34d25a4f21,
    0x04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0,
    0, 0, 0,
  ]

// =====================================================================
// Inline tests
// =====================================================================

test commit_fr_matches_gnark() {
  hash_to_fr(fx_commitment_uncompressed) ==
    0x6385ca90542285a400c194342aaab4263f8b62b55282a58b9e6b482218462dc8
}

test compress_binding_matches() {
  compress_from_uncompressed(fx_commitment_uncompressed) == fx_commitment
}

test verify_valid_proof() {
  verify(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    fx_inputs,
  )
}

test verify_tampered_inner_vk_hash() fail {
  verify(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash + 1,
    fx_inputs,
  )
}

test verify_tampered_input() fail {
  verify(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    [
      0x0000000000000000000000000000000041af18736dc9d7921c859fc95ac84da6,
      0x00000000000000000000000000000000561f8c992a424deb37ccdf4e19c0e7db,
      0x00000000000000000000000000000000ffaa82359776e593485c78496690ad7c,
      0x0000000000000000000000000000000032a41bfcc6e375f57e4f4e34d25a4f21,
      0x04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0,
      0, 0, 0,
    ],
  )
}

// Inner-layer tests: claim_digest reconstruction + end-to-end RISC Zero verification.

test claim_digest_chain_matches() {
  compute_claim_digest_from_journal(fx_journal_bytes) == fx_expected_claim_digest
}

test risc0_inputs_match_fixture() {
  risc0_inputs_from_journal(fx_journal_bytes) == fx_inputs
}

test verify_risc0_valid_proof() {
  verify_risc0(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    fx_journal_bytes,
  )
}

test verify_risc0_tampered_journal() fail {
  // Flip the low byte of the journal — multiply result 391 → 390.
  verify_risc0(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    #"8601000000000000",
  )
}

// Random-batched verifier tests (single final_verify path).

test verify_batched_valid_proof() {
  verify_batched(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    fx_inputs,
  )
}

test verify_batched_tampered_input() fail {
  verify_batched(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    [
      0x0000000000000000000000000000000041af18736dc9d7921c859fc95ac84da6,
      0x00000000000000000000000000000000561f8c992a424deb37ccdf4e19c0e7db,
      0x00000000000000000000000000000000ffaa82359776e593485c78496690ad7c,
      0x0000000000000000000000000000000032a41bfcc6e375f57e4f4e34d25a4f21,
      0x04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0,
      0, 0, 0,
    ],
  )
}

test verify_batched_risc0_valid_proof() {
  verify_batched_risc0(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    fx_journal_bytes,
  )
}

test verify_batched_risc0_tampered_journal() fail {
  verify_batched_risc0(
    fx_pi_a,
    fx_pi_b,
    fx_pi_c,
    fx_commitment,
    fx_commitment_uncompressed,
    fx_commitment_pok,
    fx_inner_vk_hash,
    #"8601000000000000",
  )
}
