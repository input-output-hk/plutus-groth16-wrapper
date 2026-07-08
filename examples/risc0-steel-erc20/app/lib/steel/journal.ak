// APP-OWNED — Steel journal decoder.
//
// The guest commits an ABI-encoded journal of six static 32-byte words:
//
//   word 0  Commitment.id        version (top 16 bits) ‖ zeros ‖ block number (low 64 bits)
//   word 1  Commitment.digest    block hash (version 0 = block-hash commitment)
//   word 2  Commitment.configID  chain-config hash (pins chain id + fork schedule)
//   word 3  token                left-padded 20-byte address
//   word 4  account              left-padded 20-byte address
//   word 5  balance              uint256, big-endian
//
// Soundness note: these bytes are the *same* `journal_bytes` the zkwrap inner
// layer hashes into the RISC Zero claim digest, so every field decoded here is
// authenticated by the proof. No validation beyond the length guard is needed —
// the guest (pinned by `image_id`) produced the encoding.

use aiken/builtin
use aiken/primitive/bytearray

pub type SteelJournal {
  version: Int,
  block_number: Int,
  block_digest: ByteArray,
  config_id: ByteArray,
  token: ByteArray,
  account: ByteArray,
  balance: Int,
}

/// Steel `CommitmentVersion.Block`: `digest` is an execution block hash
/// indexed by block number.
pub const version_block: Int = 0

pub fn decode(journal_bytes: ByteArray) -> SteelJournal {
  expect builtin.length_of_bytearray(journal_bytes) == 192
  SteelJournal {
    version: bytearray.to_int_big_endian(
      builtin.slice_bytearray(0, 2, journal_bytes),
    ),
    block_number: bytearray.to_int_big_endian(
      builtin.slice_bytearray(24, 8, journal_bytes),
    ),
    block_digest: builtin.slice_bytearray(32, 32, journal_bytes),
    config_id: builtin.slice_bytearray(64, 32, journal_bytes),
    token: builtin.slice_bytearray(108, 20, journal_bytes),
    account: builtin.slice_bytearray(140, 20, journal_bytes),
    balance: bytearray.to_int_big_endian(
      builtin.slice_bytearray(160, 32, journal_bytes),
    ),
  }
}

// =====================================================================
// Unit tests against the live fixture journal (Sepolia block 11223202).
// =====================================================================

const fixture_journal: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000ab40a24c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc19890c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d00000000000000000000000009737100d2f42a196de56ed0d1f6ff598a250e7e400000000000000000000000000000000000000000000000000016b5feec65d63"

test decode_fixture_journal() {
  let j = decode(fixture_journal)
  and {
    j.version == version_block,
    j.block_number == 11223202,
    j.block_digest == #"4c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc198",
    j.config_id == #"90c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d",
    j.token == #"aa8e23fb1079ea71e0a56f48a2aa51851d8433d0",
    j.account == #"9737100d2f42a196de56ed0d1f6ff598a250e7e4",
    j.balance == 399534748753251,
  }
}

test decode_rejects_truncated_journal() fail {
  let j = decode(builtin.slice_bytearray(0, 160, fixture_journal))
  j.version == version_block
}
