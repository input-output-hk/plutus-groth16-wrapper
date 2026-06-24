// Hand-written Aiken verifier for a gnark PLONK/BLS12-381 outer-wrapper proof.
//
// THROWAWAY de-risking spike (docs/tmp/plonk-integration-plan.md, Step 0).
// Mirrors the deterministic reference verifier in ../../refverify and is checked
// stage-by-stage against its golden vectors. Proves that a gnark PLONK proof
// (SHA-256 Fiat-Shamir transcript + BSB22 commitment + single folded KZG
// pairing) verifies on-chain with only Plutus V3 builtins.
//
// Divergence from gnark's Go verifier (same as refverify): the final two-opening
// KZG batch uses a SHA-256-derived λ instead of gnark's random one (not
// reproducible on-chain). A valid proof verifies under any λ, so it stays sound.
//
// All field inversions are batched (Montgomery's trick): one modular
// exponentiation instead of one per public input.

use aiken/builtin
use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar}
use aiken/primitive/bytearray
use plonk_spike/fixtures as fx

type S =
  State<Scalar>

// =====================================================================
// Field / curve constants
// =====================================================================

// Fp (base field) modulus — for compressed-point reconstruction.
const q_modulus: Int =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

// Fiat-Shamir challenge labels (ASCII).
const lbl_gamma: ByteArray = #"67616d6d61"
const lbl_beta: ByteArray = #"62657461"
const lbl_alpha: ByteArray = #"616c706861"
const lbl_zeta: ByteArray = #"7a657461"

// RFC-9380 ExpandMsgXmd_SHA256 constants, DST = "BSB22-Plonk", L = 48.
// DST_prime = "BSB22-Plonk" (11 bytes) || I2OSP(11,1)=0x0b
const dst_prime: ByteArray = #"42534232322d506c6f6e6b0b"

const l_i_b_zero: ByteArray = #"003000"

const z_pad: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// =====================================================================
// Small helpers
// =====================================================================

fn concat(parts: List<ByteArray>) -> ByteArray {
  list.foldl(parts, #"", fn(p, acc) { builtin.append_bytearray(acc, p) })
}

fn sha256(b: ByteArray) -> ByteArray {
  builtin.sha2_256(b)
}

// A Fiat-Shamir challenge: raw 32-byte SHA-256 output H(label || bindings...).
// The raw bytes (not reduced) are fed into the next challenge.
fn fs_challenge(label: ByteArray, bindings: List<ByteArray>) -> ByteArray {
  sha256(concat([label, ..bindings]))
}

fn to_scalar(raw: ByteArray) -> S {
  scalar.from_bytes(raw)
}

fn g1(compressed: ByteArray) -> G1Element {
  builtin.bls12_381_g1_uncompress(compressed)
}

// p * s
fn smul(p: G1Element, s: S) -> G1Element {
  builtin.bls12_381_g1_scalar_mul(scalar.to_int(s), p)
}

fn gadd(a: G1Element, b: G1Element) -> G1Element {
  builtin.bls12_381_g1_add(a, b)
}

fn one() -> S {
  scalar.from_int(1)
}

// Montgomery batch inversion: [x0..xₙ] -> [1/x0..1/xₙ] with ONE recip.
fn batch_invert(xs: List<S>) -> List<S> {
  // forward: prefixes_rev = [∏_{<n-1}, …, x0, 1], total = ∏ all
  let (prefixes_rev, total) =
    list.foldl(
      xs,
      ([], one()),
      fn(x, acc) {
        let (ps, run) = acc
        ([run, ..ps], scalar.mul(run, x))
      },
    )
  expect Some(inv_total) = scalar.recip(total)
  // backward over reversed xs aligned with prefixes_rev
  let pairs = list.zip(list.reverse(xs), prefixes_rev)
  let (invs, _) =
    list.foldl(
      pairs,
      ([], inv_total),
      fn(pair, acc) {
        let (out, inv_run) = acc
        let (x, p) = pair
        ([scalar.mul(inv_run, p), ..out], scalar.mul(inv_run, x))
      },
    )
  invs
}

// [g^0, g^1, …, g^(n-1)]
fn powers(g: S, n: Int) -> List<S> {
  do_powers(g, one(), n)
}

fn do_powers(g: S, cur: S, n: Int) -> List<S> {
  if n == 0 {
    []
  } else {
    [cur, ..do_powers(g, scalar.mul(cur, g), n - 1)]
  }
}

// Reconstruct the 48-byte compressed encoding of a non-infinity G1 point from
// its 96-byte gnark RawBytes (x_be || y_be). Same trick as the Groth16 spike.
fn compress_from_uncompressed(u: ByteArray) -> ByteArray {
  let y_int = bytearray.to_int_big_endian(bytearray.slice(u, 48, 95))
  let sign_flag =
    if 2 * y_int > q_modulus {
      0xa0
    } else {
      0x80
    }
  let head = sign_flag + bytearray.at(u, 0) % 32
  builtin.cons_bytearray(head, bytearray.slice(u, 1, 47))
}

// RFC-9380 ExpandMsgXmd_SHA256(msg, "BSB22-Plonk", 48).
fn expand_msg_xmd_48(msg: ByteArray) -> ByteArray {
  let b0 =
    sha256(
      z_pad
        |> builtin.append_bytearray(msg)
        |> builtin.append_bytearray(l_i_b_zero)
        |> builtin.append_bytearray(dst_prime),
    )
  let b1 =
    sha256(
      b0
        |> builtin.append_bytearray(#"01")
        |> builtin.append_bytearray(dst_prime),
    )
  let b2 =
    sha256(
      bytearray.xor_bytes(b0, b1, False)
        |> builtin.append_bytearray(#"02")
        |> builtin.append_bytearray(dst_prime),
    )
  builtin.append_bytearray(b1, bytearray.take(b2, 16))
}

// hashedCmt = fr.Hash(uncompressed_bsb22, "BSB22-Plonk", 1)
fn hash_commitment(uncompressed: ByteArray) -> S {
  uncompressed |> expand_msg_xmd_48 |> scalar.from_bytes
}

fn claimed(i: Int) -> ByteArray {
  expect Some(v) = list.at(fx.claimed_values, i)
  v
}

// =====================================================================
// Transcript: gamma, beta, alpha, zeta
// =====================================================================

fn transcript(public_inputs: List<ByteArray>) -> (S, S, S, S) {
  let gamma_raw =
    fs_challenge(
      lbl_gamma,
      [
        fx.s0_u, fx.s1_u, fx.s2_u, fx.ql_u, fx.qr_u, fx.qm_u, fx.qo_u, fx.qk_u,
        fx.qcp0_u,
        ..list.concat(public_inputs, [fx.lro0_u, fx.lro1_u, fx.lro2_u])
      ],
    )
  let beta_raw = fs_challenge(lbl_beta, [gamma_raw])
  let alpha_raw = fs_challenge(lbl_alpha, [beta_raw, fx.bsb0_u, fx.z_u])
  let zeta_raw = fs_challenge(lbl_zeta, [alpha_raw, fx.h0_u, fx.h1_u, fx.h2_u])
  (
    to_scalar(gamma_raw),
    to_scalar(beta_raw),
    to_scalar(alpha_raw),
    to_scalar(zeta_raw),
  )
}

// =====================================================================
// PI(zeta) and lagrange_zero, sharing one batch inversion
// =====================================================================

fn pi_terms(
  pis: List<ByteArray>,
  gps: List<S>,
  invs: List<S>,
  zh_size: S,
  acc: S,
) -> S {
  when (pis, gps, invs) is {
    ([pb, ..pr], [gi, ..gr], [iv, ..ir]) -> {
      let pi = scalar.from_bytes(pb)
      // zh_zeta * size_inv * gⁱ * piᵢ * 1/(ζ-gⁱ)
      let term = zh_size |> scalar.mul(gi) |> scalar.mul(pi) |> scalar.mul(iv)
      pi_terms(pr, gr, ir, zh_size, scalar.add(acc, term))
    }
    _ -> acc
  }
}

// =====================================================================
// Top-level verification
// =====================================================================

pub fn verify(public_inputs: List<ByteArray>) -> Bool {
  let (gamma, beta, alpha, zeta) = transcript(public_inputs)

  let size_inv = scalar.from_bytes(fx.vk_size_inv)
  let generator = scalar.from_bytes(fx.vk_generator)
  let coset_shift = scalar.from_bytes(fx.vk_coset_shift)
  let one = one()

  let zeta_pow_m = scalar.scale(zeta, fx.vk_size)
  let zh_zeta = scalar.sub(zeta_pow_m, one)

  // --- batch-invert every denominator at once ---
  // [ ζ-1 , ζ-g⁰ , … , ζ-g^(n-1) , ζ-w^(nb+cci) ]
  let gps = powers(generator, fx.vk_nb_public)
  let w_pow = scalar.scale(generator, fx.vk_nb_public + fx.vk_commitment_index)
  let dens =
    list.concat(
      [scalar.sub(zeta, one), ..list.map(gps, fn(gi) { scalar.sub(zeta, gi) })],
      [scalar.sub(zeta, w_pow)],
    )
  let invs = batch_invert(dens)
  expect [inv_zeta_m1, ..rest] = invs
  // rest = [ 1/(ζ-g⁰).. , 1/(ζ-w) ]
  let inv_inputs = list.take(rest, fx.vk_nb_public)
  expect Some(inv_w) = list.last(rest)

  // lagrangeZero = 1/(ζ-1) * zh_zeta * size_inv
  let lagrange_zero =
    inv_zeta_m1 |> scalar.mul(zh_zeta) |> scalar.mul(size_inv)

  // PI public-input sum
  let zh_size = scalar.mul(zh_zeta, size_inv)
  let pub_sum = pi_terms(public_inputs, gps, inv_inputs, zh_size, scalar.from_int(0))

  // BSB22 commitment contribution
  let hashed = hash_commitment(fx.bsb0_u)
  let lagrange_cmt =
    zh_zeta |> scalar.mul(w_pow) |> scalar.mul(inv_w) |> scalar.mul(size_inv)
  let pi = scalar.add(pub_sum, scalar.mul(lagrange_cmt, hashed))

  // --- linearization constant term ---
  let l = scalar.from_bytes(claimed(1))
  let r = scalar.from_bytes(claimed(2))
  let o = scalar.from_bytes(claimed(3))
  let s1 = scalar.from_bytes(claimed(4))
  let s2 = scalar.from_bytes(claimed(5))
  let zu = scalar.from_bytes(fx.zshift_val)

  let alpha_sq_l1 = lagrange_zero |> scalar.mul(alpha) |> scalar.mul(alpha)

  let t1 = beta |> scalar.mul(s1) |> scalar.add(gamma) |> scalar.add(l)
  let t2 = s2 |> scalar.mul(beta) |> scalar.add(gamma) |> scalar.add(r)
  let t3 = scalar.add(o, gamma)
  let bracket =
    t1
      |> scalar.mul(t2)
      |> scalar.mul(t3)
      |> scalar.mul(alpha)
      |> scalar.mul(zu)
  let const_lin =
    bracket |> scalar.sub(alpha_sq_l1) |> scalar.add(pi) |> scalar.neg

  let opening_lin = scalar.from_bytes(claimed(0))
  expect scalar.to_int(const_lin) == scalar.to_int(opening_lin)

  // --- linearized polynomial digest (MSM) ---
  let sv1 =
    t1
      |> scalar.mul(t2)
      |> scalar.mul(beta)
      |> scalar.mul(alpha)
      |> scalar.mul(zu)
  let a1 = beta |> scalar.mul(zeta) |> scalar.add(gamma) |> scalar.add(l)
  let a2 =
    beta
      |> scalar.mul(coset_shift)
      |> scalar.mul(zeta)
      |> scalar.add(gamma)
      |> scalar.add(r)
  let a3 =
    beta
      |> scalar.mul(coset_shift)
      |> scalar.mul(coset_shift)
      |> scalar.mul(zeta)
      |> scalar.add(o)
      |> scalar.add(gamma)
  let sv2 =
    a1 |> scalar.mul(a2) |> scalar.mul(a3) |> scalar.mul(alpha) |> scalar.neg

  let coeff_z = scalar.add(alpha_sq_l1, sv2)
  let rl = scalar.mul(l, r)

  let zeta_n2 = scalar.scale(zeta, fx.vk_size + 2)
  let zeta_n2_zh = zeta_n2 |> scalar.mul(zh_zeta) |> scalar.neg
  let zeta_n2_sq_zh =
    zeta_n2 |> scalar.mul(zeta_n2) |> scalar.mul(zh_zeta) |> scalar.neg
  let zh = scalar.neg(zh_zeta)
  let qcp_eval = scalar.from_bytes(claimed(6))

  let lin_digest =
    smul(g1(fx.bsb0_c), qcp_eval)
      |> gadd(smul(g1(fx.ql_c), l))
      |> gadd(smul(g1(fx.qr_c), r))
      |> gadd(smul(g1(fx.qm_c), rl))
      |> gadd(smul(g1(fx.qo_c), o))
      |> gadd(smul(g1(fx.qk_c), one))
      |> gadd(smul(g1(fx.s2_c), sv1))
      |> gadd(smul(g1(fx.z_c), coeff_z))
      |> gadd(smul(g1(fx.h0_c), zh))
      |> gadd(smul(g1(fx.h1_c), zeta_n2_zh))
      |> gadd(smul(g1(fx.h2_c), zeta_n2_sq_zh))

  // Bind prover-supplied uncompressed linDigest bytes to the computed point.
  expect builtin.bls12_381_g1_compress(lin_digest) == compress_from_uncompressed(
    fx.lin_digest_u,
  )

  // --- gamma_kzg (KZG fold challenge) ---
  let gamma_kzg =
    to_scalar(
      fs_challenge(
        lbl_gamma,
        [
          scalar.to_bytes(zeta),
          fx.lin_digest_u, fx.lro0_u, fx.lro1_u, fx.lro2_u, fx.s0_u, fx.s1_u,
          fx.qcp0_u,
          ..list.concat(fx.claimed_values, [fx.zshift_val])
        ],
      ),
    )

  let gk1 = gamma_kzg
  let gk2 = scalar.mul(gk1, gamma_kzg)
  let gk3 = scalar.mul(gk2, gamma_kzg)
  let gk4 = scalar.mul(gk3, gamma_kzg)
  let gk5 = scalar.mul(gk4, gamma_kzg)
  let gk6 = scalar.mul(gk5, gamma_kzg)

  let folded_digest =
    lin_digest
      |> gadd(smul(g1(fx.lro0_c), gk1))
      |> gadd(smul(g1(fx.lro1_c), gk2))
      |> gadd(smul(g1(fx.lro2_c), gk3))
      |> gadd(smul(g1(fx.s0_c), gk4))
      |> gadd(smul(g1(fx.s1_c), gk5))
      |> gadd(smul(g1(fx.qcp0_c), gk6))

  let folded_eval =
    scalar.from_bytes(claimed(0))
      |> scalar.add(scalar.mul(l, gk1))
      |> scalar.add(scalar.mul(r, gk2))
      |> scalar.add(scalar.mul(o, gk3))
      |> scalar.add(scalar.mul(s1, gk4))
      |> scalar.add(scalar.mul(s2, gk5))
      |> scalar.add(scalar.mul(qcp_eval, gk6))

  // --- deterministic two-opening batch λ ---
  let u =
    to_scalar(
      sha256(
        builtin.append_bytearray(
          builtin.bls12_381_g1_compress(folded_digest),
          fx.z_c,
        ),
      ),
    )

  let h0 = g1(fx.batched_h_c)
  let h1 = g1(fx.zshift_h_c)
  let z = g1(fx.z_c)
  let kzg_g1 = g1(fx.kzg_g1)

  // foldedQuot = H0 + u·H1
  let folded_quot = gadd(h0, smul(h1, u))

  // acc = (foldedDigest + u·Z) - (foldedEval + u·zu)·G1 + (ζ·H0 + u·ζω·H1)
  let shifted_zeta = scalar.mul(zeta, generator)
  let eval_scalar = u |> scalar.mul(zu) |> scalar.add(folded_eval)
  let acc =
    gadd(folded_digest, smul(z, u))
      |> gadd(builtin.bls12_381_g1_neg(smul(kzg_g1, eval_scalar)))
      |> gadd(smul(h0, zeta))
      |> gadd(smul(h1, scalar.mul(u, shifted_zeta)))

  // pairing: e(acc, [1]₂) == e(foldedQuot, [s]₂)
  let g2_0 = builtin.bls12_381_g2_uncompress(fx.kzg_g2_0)
  let g2_1 = builtin.bls12_381_g2_uncompress(fx.kzg_g2_1)
  let lhs = builtin.bls12_381_miller_loop(acc, g2_0)
  let rhs = builtin.bls12_381_miller_loop(folded_quot, g2_1)
  builtin.bls12_381_final_verify(lhs, rhs)
}

// =====================================================================
// Stage-by-stage golden-vector tests
// =====================================================================

test transcript_matches_golden() {
  let (gamma, beta, alpha, zeta) = transcript(fx.public_inputs)
  and {
    scalar.to_bytes(gamma) == fx.golden_gamma,
    scalar.to_bytes(beta) == fx.golden_beta,
    scalar.to_bytes(alpha) == fx.golden_alpha,
    scalar.to_bytes(zeta) == fx.golden_zeta,
  }
}

test hash_commitment_matches_golden() {
  scalar.to_bytes(hash_commitment(fx.bsb0_u)) == fx.golden_hashed_cmt0
}

test verify_valid_proof() {
  verify(fx.public_inputs)
}

// Tamper: bump the first public input. The transcript shifts, the linearization
// constant check fails. Must reject.
test verify_tampered_input() fail {
  expect [_first, ..rest] = fx.public_inputs
  verify(
    [
      #"0000000000000000000000000000000000000000000000000000000001234568",
      ..rest
    ],
  )
}
