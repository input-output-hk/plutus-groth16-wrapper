//! Backend-parametric generators for the outer-layer test suite.
//!
//! The standard outer-layer tests (positive verify + the `inner_vk_hash` and
//! public-input tamper-negatives) and the deployable-redeemer scaffolding are
//! identical across every outer backend × inner system: only the literal proof
//! fields differ, and those are exactly [`OuterCodegen::proof_params`] zipped
//! with the values a plugin reads from its concrete proof type. This module
//! owns that shared shape so each plugin crate only contributes the
//! inner-system-specific tests and the literal proof values.
//!
//! [`OuterCodegen::proof_params`]: crate::OuterCodegen::proof_params

use crate::codegen::composer::TestBlock;

// --- Aiken literal helpers ---------------------------------------------------

/// `#"…"` ByteArray literal.
pub fn ba(hex: &str) -> String {
    format!("#\"{hex}\"")
}

/// `0x…` Int literal.
pub fn int(hex: &str) -> String {
    format!("0x{hex}")
}

/// `[0x.., 0x.., …]` over a slice of 32-byte BE Fr hex strings.
pub fn int_list(items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|h| int(h)).collect();
    format!("[{}]", body.join(", "))
}

/// Increment a 32-byte big-endian hex value by 1 (the last byte of a real
/// public input is never `0xff` here, so no carry to worry about).
pub fn bump_last(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] += 1;
    hex::encode(bytes)
}

/// Flip the low bit of the first byte — a different, same-length value that must
/// make the composed entry point reject.
pub fn flip_first_byte(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    bytes[0] ^= 0x01;
    hex::encode(bytes)
}

/// A mock UTxO ref. The validator ignores datum/utxo/tx, so a placeholder tx
/// and a zero ref suffice to exercise the deployable `spend` handler.
const MOCK_REF: &str = "OutputReference { transaction_id: #\"0000000000000000000000000000000000000000000000000000000000000000\", output_index: 0 }";

/// The outer layer under test, plus the literal proof fields a plugin read from
/// its concrete proof type (aligned with [`proof_params`], each already an
/// Aiken literal such as `#"…"`).
///
/// [`proof_params`]: crate::OuterCodegen::proof_params
pub struct OuterLayer<'a> {
    /// Outer Aiken module basename (e.g. `"groth16"` / `"plonk"`).
    pub outer_mod: &'a str,
    /// [`proof_params`](crate::OuterCodegen::proof_params), in order.
    pub proof_params: &'a [&'a str],
    /// Literal proof field values aligned with `proof_params`.
    pub proof_lits: &'a [String],
    /// `inner_vk_hash`, raw lowercase hex (no `0x`).
    pub inner_vk_hash: &'a str,
    /// The full outer public-input vector, each a 32-byte BE Fr hex.
    pub inputs: &'a [String],
}

impl OuterLayer<'_> {
    /// `<mod>.verify(proof…, <vkh>, <ins>)` with literal vk-hash / inputs exprs.
    fn verify_call(&self, vkh: &str, ins: &str) -> String {
        format!(
            "{}.verify(\n  {},\n  {vkh},\n  {ins},\n)",
            self.outer_mod,
            self.proof_lits.join(",\n  ")
        )
    }

    /// The backend-agnostic outer-layer suite: a positive verify plus the
    /// `inner_vk_hash` and public-input tamper-negatives.
    pub fn suite(&self) -> Vec<TestBlock> {
        let vkhash = int(self.inner_vk_hash);
        let inputs = int_list(self.inputs);

        let mut tampered = self.inputs.to_vec();
        tampered[0] = bump_last(&self.inputs[0]);
        let inputs_tampered = int_list(&tampered);

        vec![
            TestBlock::pass("verify_valid_proof", self.verify_call(&vkhash, &inputs)),
            TestBlock::fail(
                "verify_tampered_inner_vk_hash",
                self.verify_call(&format!("{vkhash} + 1"), &inputs),
            ),
            TestBlock::fail(
                "verify_tampered_input",
                self.verify_call(&vkhash, &inputs_tampered),
            ),
        ]
    }

    /// A `Redeemer { <proof fields>, <extra inner fields> }` literal. The proof
    /// fields are `proof_params` zipped with `proof_lits`; `extra` carries the
    /// inner-system redeemer fields (name, Aiken literal).
    pub fn redeemer(&self, extra: &[(&str, String)]) -> String {
        let proof_fields = self
            .proof_params
            .iter()
            .zip(self.proof_lits.iter())
            .map(|(name, val)| format!("{name}: {val}"))
            .chain(extra.iter().map(|(name, val)| format!("{name}: {val}")))
            .collect::<Vec<_>>()
            .join(",\n  ");
        format!("Redeemer {{\n  {proof_fields},\n}}")
    }

    /// Wrap a `Redeemer { … }` literal into the composed `wrapper.spend(…)` call
    /// through the deployable redeemer path.
    pub fn composed_spend(redeemer: &str) -> String {
        format!("wrapper.spend(\n  None,\n  {redeemer},\n  {MOCK_REF},\n  placeholder,\n)")
    }
}
