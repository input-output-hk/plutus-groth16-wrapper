// Inner layer — RISC Zero inner-system scaffolding.
//
// VENDORED VERBATIM by zkwrap-core's Composer: generic and constant-free
// across guest programs. The per-guest values (image_id, post_state_digest, the
// control_root split halves, bn254_control_id) arrive as *parameters*; only the
// RISC Zero `tagged_struct` protocol tags below are baked, and those are invariant
// across every guest and deployment of a RISC Zero release.
//
// Reconstructs `claim_digest` on-chain from `journal_bytes` via the RISC Zero
// `tagged_struct` hash convention (SHA256(SHA256(tag) ‖ children ‖ u32s_LE ‖
// count_LE)), then assembles the 5 RISC Zero public inputs.

use aiken/builtin
use aiken/primitive/bytearray

// =====================================================================
// RISC Zero tagged_struct protocol constants (system-wide invariants).
// =====================================================================

// SHA256("risc0.Output")
const tag_output_digest: ByteArray =
  #"77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"

// SHA256("risc0.ReceiptClaim")
const tag_claim_digest: ByteArray =
  #"cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"

// input.Pruned([0;8]).digest() = Digest::ZERO (Input is uninhabited; the receipt
// always carries pruned-zero).
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

// =====================================================================
// claim_digest reconstruction (three SHA-256 calls).
// =====================================================================
pub fn compute_claim_digest_from_journal(
  journal_bytes: ByteArray,
  image_id: ByteArray,
  post_state_digest: ByteArray,
) -> ByteArray {
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
  // `image_id` is pre.digest (the guest's SystemState digest).
  let claim_preimage =
    tag_claim_digest
      |> builtin.append_bytearray(input_digest)
      |> builtin.append_bytearray(image_id)
      |> builtin.append_bytearray(post_state_digest)
      |> builtin.append_bytearray(output_digest)
      |> builtin.append_bytearray(sys_user_exit_le)
      |> builtin.append_bytearray(count_four_le)
  builtin.sha2_256(claim_preimage)
}

// =====================================================================
// The 5 RISC Zero public inputs.
//
// inputs[0,1] = split_digest(control_root) — baked halves passed in.
// inputs[2,3] = split_digest(claim_digest) — derived from journal_bytes.
// inputs[4]   = Fr(reverse_bytes(bn254_control_id)) — baked, passed in.
//
// RISC Zero split_digest = reverse bytes, split at 16, low half first;
// equivalently, read each 16-byte half little-endian.
// =====================================================================
pub fn real_inputs(
  journal_bytes: ByteArray,
  control_root_0: Int,
  control_root_1: Int,
  image_id: ByteArray,
  post_state_digest: ByteArray,
  bn254_control_id: Int,
) -> List<Int> {
  let claim_digest =
    compute_claim_digest_from_journal(journal_bytes, image_id, post_state_digest)
  let input_2 = bytearray.to_int_little_endian(bytearray.take(claim_digest, 16))
  let input_3 = bytearray.to_int_little_endian(bytearray.drop(claim_digest, 16))
  [control_root_0, control_root_1, input_2, input_3, bn254_control_id]
}
