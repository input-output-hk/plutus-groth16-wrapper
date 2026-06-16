// Inner layer — SP1 inner-system scaffolding.
//
// VENDORED VERBATIM by zkwrap-core's Composer: generic and constant-free across
// guest programs. The per-program value (vkey_hash) arrives as a *parameter*.
//
// SP1's two BN254 public inputs are:
//   inputs[0] = vkey_hash               — the program identity (baked, passed in)
//   inputs[1] = committed_values_digest — derived on-chain from public_values
//
// committed_values_digest is SP1's `hash_bn254`: SHA-256 of the committed
// public values, with the top 3 bits of the big-endian digest masked off so it
// fits in BN254 Fr. Masking the top 3 bits of a 256-bit value is exactly
// reduction modulo 2^253. See docs/research/sp1-artifact-format.md §6.

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

// The 2 SP1 public inputs: [vkey_hash, committed_values_digest].
pub fn real_inputs(public_values: ByteArray, vkey_hash: Int) -> List<Int> {
  [vkey_hash, committed_values_digest(public_values)]
}
