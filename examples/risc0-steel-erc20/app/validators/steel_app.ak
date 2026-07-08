// APP-OWNED — the actual showcase validator.
//
// Policy: unlock only for a proof that address `expected_account` held at
// least `min_balance` of `expected_token` on Ethereum, read at the exact block
// the datum pins.
//
// Layering:
//   [1] `verify.verify(...)` — cryptographic binding: the outer BLS12-381 proof
//       wraps the RISC Zero Groth16 proof of the Steel guest, and the claim
//       digest is recomputed from `journal_bytes`, so the journal is
//       authenticated end-to-end.
//   [2] `journal.decode(...)` — app policy over the authenticated fields.
//
// Trust-anchor caveat (see README): Cardano cannot observe Ethereum block
// hashes, so the *choice* of block is pinned via the datum
// (`expected_block_digest`), not validated against Ethereum consensus. A
// consensus proof (e.g. wrapped SP1-Helios) is possible solution for that.

use cardano/transaction.{OutputReference, Transaction, placeholder}
use steel/journal
use zkwrap/verify.{Redeemer}

// =====================================================================
// App policy constants.
// =====================================================================
/// The ERC-20 token whose balance the proof must attest (Sepolia test USDT).
const expected_token: ByteArray = #"aa8e23fb1079ea71e0a56f48a2aa51851d8433d0"

/// The Ethereum account whose balance is being proven.
const expected_account: ByteArray = #"9737100d2f42a196de56ed0d1f6ff598a250e7e4"

/// Steel chain-config hash — pins chain id + fork schedule (Sepolia).
const expected_config_id: ByteArray =
  #"90c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d"

/// Minimum balance the account must hold (raw token units).
const min_balance: Int = 100_000_000_000_000

/// Which Ethereum block the state must have been read at.
pub type AppDatum {
  expected_block_digest: ByteArray,
}

validator steel_erc20 {
  spend(
    datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(datum_data) = datum
    expect app_datum: AppDatum = datum_data

    // [1] Cryptographic binding: proof valid ⇒ journal_bytes authenticated.
    expect
      verify.verify(
        redeemer.pi_a,
        redeemer.pi_b,
        redeemer.pi_c,
        redeemer.commitment_uncompressed,
        redeemer.commitment_pok,
        redeemer.journal_bytes,
      )

    // [2] App policy over the authenticated journal.
    let j = journal.decode(redeemer.journal_bytes)
    and {
      j.version == journal.version_block,
      j.config_id == expected_config_id,
      j.block_digest == app_datum.expected_block_digest,
      j.token == expected_token,
      j.account == expected_account,
      j.balance >= min_balance,
    }
  }

  else(_) {
    fail
  }
}

// =====================================================================
// Fixture tests: the live proof from the pipeline run (Sepolia block
// 11223202, balance 399534748753251 ≥ min_balance).
// =====================================================================

const fixture_block_digest: ByteArray =
  #"4c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc198"

const fixture_journal: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000ab40a24c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc19890c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d00000000000000000000000009737100d2f42a196de56ed0d1f6ff598a250e7e400000000000000000000000000000000000000000000000000016b5feec65d63"

// Journal with the balance word's last byte flipped (…5d63 → …5d64).
const tampered_balance_journal: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000ab40a24c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc19890c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d00000000000000000000000009737100d2f42a196de56ed0d1f6ff598a250e7e400000000000000000000000000000000000000000000000000016b5feec65d64"

// Journal with the commitment digest's first byte flipped (4c → 4d).
const tampered_digest_journal: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000ab40a24d83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc19890c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d00000000000000000000000009737100d2f42a196de56ed0d1f6ff598a250e7e400000000000000000000000000000000000000000000000000016b5feec65d63"

fn fixture_redeemer(journal_bytes: ByteArray) -> Redeemer {
  Redeemer {
    pi_a: #"a480cec23e5524af74dde45401ce0d78f4f40b1a14bc4469ed56ec63be0d83136b497bfc7b05dadc5ac5a022dd1b3801",
    pi_b: #"a5e5de4febf20aabb8add04172a6f8e2dc34173716c6baa5ceaaff9c8ce74902bf3d1b50fdb829066aeeb0961530d15c09747f59c1528787cdd38f6a1f00f3f511df120917d2dc87d776c508d1f6a8ece917f55e6ee869f47ad56d5863b83d6b",
    pi_c: #"b7f4be9f98f5f146d15d4de1657c2c78ababfb639d961ee9c9d4fe2d0a5acedefd0ae296f82f5bb56181015ef58a6cfb",
    commitment_uncompressed: #"02173e9f48c607cb24013653577f462718f30824c73e339d61b0a1e3ba1c02e0ad8566ca6b299089c8707e747ef04188138667488245cd4e0ec8f84d127e0046ac4b544685d5666cec78f503c5d8b25bcd34cbe952101e11fc2ed81179107bc2",
    commitment_pok: #"8d195910c7fbe0331fd8c4d250c015285d9ad89bca81d75d851ff453b291ac822764170c558df78802e330f981d25a0e",
    journal_bytes,
  }
}

fn spend_with(datum_digest: ByteArray, journal_bytes: ByteArray) -> Bool {
  let datum_data: Data = AppDatum { expected_block_digest: datum_digest }
  steel_erc20.spend(
    Some(datum_data),
    fixture_redeemer(journal_bytes),
    OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
      output_index: 0,
    },
    placeholder,
  )
}

test steel_unlocks_with_valid_proof() {
  spend_with(fixture_block_digest, fixture_journal)
}

// Any journal edit breaks the claim-digest chain → the wrapped proof no longer
// verifies, even though the policy fields would still parse.
test steel_rejects_tampered_balance() fail {
  spend_with(fixture_block_digest, tampered_balance_journal)
}

test steel_rejects_tampered_block_digest() fail {
  spend_with(fixture_block_digest, tampered_digest_journal)
}

// Valid proof, but the datum pins a different Ethereum block → policy reject.
test steel_rejects_wrong_pinned_block() fail {
  spend_with(
    #"0000000000000000000000000000000000000000000000000000000000000000",
    fixture_journal,
  )
}

test steel_rejects_truncated_journal() fail {
  spend_with(
    fixture_block_digest,
    // First 160 bytes only — balance word missing.
    #"0000000000000000000000000000000000000000000000000000000000ab40a24c83d8d6fdabab33329d1b204f194fa0559a3103d952a0cd8ed27aa56e5bc19890c1e882b1f0fda4dc7f1c66c07ed3d2a74e443834905faa9f32f583b71f459d000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d00000000000000000000000009737100d2f42a196de56ed0d1f6ff598a250e7e4",
  )
}
