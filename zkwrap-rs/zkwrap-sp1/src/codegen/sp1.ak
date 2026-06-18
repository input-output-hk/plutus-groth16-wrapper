// Inner layer — SP1 (v6.x) inner-system scaffolding.
//
// VENDORED VERBATIM by zkwrap-core's Composer: generic and constant-free across
// guest programs. Per-program / per-version values (sp1_program_vkey_hash,
// exit_code, vk_root) arrive as baked `Int` parameters; per-proof values
// (public_values, proof_nonce) arrive as redeemer `ByteArray`s.
//
// SP1 v6.1.0's five BN254 public inputs are:
//   inputs[0] = sp1_program_vkey_hash    — program identity, SP1's `vkey_hash` (baked)
//   inputs[1] = committed_values_digest  — derived on-chain from public_values
//   inputs[2] = exit_code                — guest exit code (baked; canonicalize rejects != 0)
//   inputs[3] = vk_root                  — recursion-VK root, version constant (baked)
//   inputs[4] = proof_nonce              — per-proof nonce (redeemer)
//
// committed_values_digest is SP1's `hash_public_inputs`: SHA-256 of the committed
// public values, with the top 3 bits of the big-endian digest masked off so it
// fits in BN254 Fr — exactly reduction modulo 2^253. See
// docs/research/sp1-artifact-format-v6.md §4.

use aiken/builtin
use aiken/primitive/bytearray

// 2^253 — masking the top 3 bits of the 32-byte SHA-256 digest equals `mod 2^253`.
const fr_fit_modulus: Int =
  0x2000000000000000000000000000000000000000000000000000000000000000

// committed_values_digest = SHA256(public_values) reduced to a BN254 Fr element
// via SP1's top-3-bits mask.
pub fn committed_values_digest(public_values: ByteArray) -> Int {
  bytearray.to_int_big_endian(builtin.sha2_256(public_values)) % fr_fit_modulus
}

// The 5 SP1 v6 public inputs, in order.
pub fn real_inputs(
  public_values: ByteArray,
  proof_nonce: ByteArray,
  sp1_program_vkey_hash: Int,
  exit_code: Int,
  vk_root: Int,
) -> List<Int> {
  [
    sp1_program_vkey_hash,
    committed_values_digest(public_values),
    exit_code,
    vk_root,
    bytearray.to_int_big_endian(proof_nonce),
  ]
}
