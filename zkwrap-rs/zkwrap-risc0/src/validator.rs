//! The RISC Zero validator factory — the host's one-call entry point.
//!
//! [`build_validator`] turns a verified `Receipt` + its canonical bundle + the
//! outer proof into a ready-to-`aiken check` Aiken project. It owns the three
//! things a host should not hand-assemble: outer-backend selection (from the
//! proof's `backend` id), the standard positive/tamper **test suite**, and the
//! `ComposeRequest`. Hosts that need something exotic can still drop down to
//! [`zkwrap_core::compose`] directly.

use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{InnerReceipt, Receipt};
use thiserror::Error;

use zkwrap_core::{
    compose, CodegenError, ComposeRequest, GeneratedProject, Groth16Backend, InnerCodegen,
    OuterCodegen, OuterProof, TestBlock,
};

use crate::{Canonicalized, Risc0Codegen};

/// Inputs to [`build_validator`]. All borrowed — the host already holds each.
pub struct Risc0ValidatorRequest<'a> {
    /// The verified receipt — source of the journal bytes and claim digest the
    /// generated tests bind against.
    pub receipt: &'a Receipt,
    /// The canonical bundle from [`canonicalize`](crate::canonicalize); its
    /// `codegen` section drives the inner-layer wiring.
    pub canonical: &'a Canonicalized,
    /// The outer proof from the prover. Its `backend` id selects the outer layer.
    pub outer_proof: &'a OuterProof,
    /// Raw `outer_vk.json` text from the trusted setup.
    pub outer_vk_json: &'a str,
    /// Aiken project name, `namespace/name` form (e.g. `"zkwrap/risc0_groth16"`).
    pub project_name: &'a str,
}

/// Why [`build_validator`] could not produce a project.
#[derive(Debug, Error)]
pub enum BuildValidatorError {
    #[error("receipt is not Groth16-compressed")]
    NotGroth16,
    #[error("unknown outer backend {0:?}")]
    UnknownBackend(String),
    #[error("malformed outer proof: {0}")]
    MalformedProof(String),
    #[error("compose: {0}")]
    Compose(#[from] CodegenError),
}

/// Build the Aiken validator project for a RISC Zero outer proof.
///
/// Selects the outer layer from `outer_proof.backend`, generates the standard
/// test suite (outer verify + tamper, plus the RISC Zero journal-auth tests),
/// and composes the project. Call [`GeneratedProject::write_to`] to materialize
/// it on disk.
pub fn build_validator(
    req: &Risc0ValidatorRequest,
) -> Result<GeneratedProject, BuildValidatorError> {
    // Outer-backend dispatch lives here: each arm delegates to a `build_<backend>`
    // that knows that backend's proof shape. Add an arm per new outer backend.
    match req.outer_proof.backend.as_str() {
        b if b == Groth16Backend.backend_id() => build_groth16(req),
        other => Err(BuildValidatorError::UnknownBackend(other.to_string())),
    }
}

/// Construct the project for a gnark Groth16/BLS12-381 outer proof.
fn build_groth16(req: &Risc0ValidatorRequest) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = Groth16Backend;
    let (journal_hex, claim_digest) = risc0_journal_facts(req.receipt)?;
    let tests = groth16_tests(&backend, req.outer_proof, &journal_hex, &claim_digest)?;

    Ok(compose(&ComposeRequest {
        project_name: req.project_name,
        outer: &backend,
        inner: &Risc0Codegen,
        vk_json: req.outer_vk_json,
        inner_vk_hash: &req.outer_proof.inner_vk_hash,
        codegen_meta: &req.canonical.codegen,
        tests: &tests,
    })?)
}

/// `(journal_hex, claim_digest)` from the RISC Zero receipt — the inner facts the
/// journal-auth tests bind to, independent of the outer backend.
fn risc0_journal_facts(receipt: &Receipt) -> Result<(String, String), BuildValidatorError> {
    let InnerReceipt::Groth16(groth16) = &receipt.inner else {
        return Err(BuildValidatorError::NotGroth16);
    };
    Ok((
        hex::encode(&receipt.journal.bytes),
        hex::encode(groth16.claim.digest().as_bytes()),
    ))
}

/// The standard positive + tamper-negative suite for a Groth16 outer proof.
/// The outer-layer tests use the universal outer ABI
/// (`groth16.verify(<proof…>, inner_vk_hash, inputs)`) with the Groth16 proof
/// points read here; the RISC Zero journal-auth tests reference the consts the
/// inner wiring bakes (kept in this crate so a rename moves together).
fn groth16_tests(
    outer: &Groth16Backend,
    proof: &OuterProof,
    journal_hex: &str,
    expected_claim_digest: &str,
) -> Result<Vec<TestBlock>, BuildValidatorError> {
    let outer_mod = outer.module_name();
    let inner_mod = Risc0Codegen.module_name();
    let n_real = Risc0Codegen.n_real();

    // The proof-side literal prefix, shared by the outer `verify` and the
    // composed entry point (both take the same Groth16 proof points first).
    let pi_a = ba(&proof.proof.ar);
    let pi_b = ba(&proof.proof.bs);
    let pi_c = ba(&proof.proof.krs);
    let cu = ba(proof
        .commitment_uncompressed()
        .map_err(|e| BuildValidatorError::MalformedProof(e.to_string()))?);
    let pok = ba(&proof.proof.commitment_pok);
    let proof_lits = format!("{pi_a},\n  {pi_b},\n  {pi_c},\n  {cu},\n  {pok}");

    let vkhash = int(&proof.inner_vk_hash);
    let inputs = int_list(&proof.inputs);

    let mut tampered = proof.inputs.clone();
    tampered[0] = bump_last(&proof.inputs[0]);
    let inputs_tampered = int_list(&tampered);

    let reals = int_list(&proof.inputs[0..n_real]);
    let journal_tampered = flip_first_byte(journal_hex);

    // Outer layer, literal-input form: <mod>.verify(proof…, vkhash, inputs).
    let l1_verify = |vkh: &str, ins: &str| {
        format!("{outer_mod}.verify(\n  {proof_lits},\n  {vkh},\n  {ins},\n)")
    };
    // Composed entry, journal form: verify(proof…, journal_bytes).
    let composed = |journal: &str| format!("verify(\n  {proof_lits},\n  {},\n)", ba(journal));

    Ok(vec![
        TestBlock::pass("verify_valid_proof", l1_verify(&vkhash, &inputs)),
        TestBlock::fail(
            "verify_tampered_inner_vk_hash",
            l1_verify(&format!("{vkhash} + 1"), &inputs),
        ),
        TestBlock::fail("verify_tampered_input", l1_verify(&vkhash, &inputs_tampered)),
        TestBlock::pass(
            "claim_digest_chain_matches",
            format!(
                "{inner_mod}.compute_claim_digest_from_journal({}, image_id, post_state_digest) == {}",
                ba(journal_hex),
                ba(expected_claim_digest)
            ),
        ),
        TestBlock::pass(
            "risc0_inputs_match_proof",
            format!(
                "{inner_mod}.real_inputs({}, control_root_0, control_root_1, image_id, post_state_digest, bn254_control_id) == {reals}",
                ba(journal_hex)
            ),
        ),
        TestBlock::pass("verify_risc0_valid_proof", composed(journal_hex)),
        TestBlock::fail("verify_risc0_tampered_journal", composed(&journal_tampered)),
    ])
}

// --- Aiken literal helpers ---------------------------------------------------

/// `#"…"` ByteArray literal.
fn ba(hex: &str) -> String {
    format!("#\"{hex}\"")
}

/// `0x…` Int literal.
fn int(hex: &str) -> String {
    format!("0x{hex}")
}

/// `[0x.., 0x.., …]` over a slice of 32-byte BE Fr hex strings.
fn int_list(items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|h| int(h)).collect();
    format!("[{}]", body.join(", "))
}

/// Increment a 32-byte big-endian hex value by 1 (last byte of a real BN254 Fr
/// public input is never 0xff here, so no carry to worry about).
fn bump_last(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] += 1;
    hex::encode(bytes)
}

/// Flip the low bit of the journal's first byte — a different, same-length
/// journal that must make the composed entry point reject.
fn flip_first_byte(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    bytes[0] ^= 0x01;
    hex::encode(bytes)
}
