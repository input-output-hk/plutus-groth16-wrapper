//! The RISC Zero validator factory — the host's one-call entry point.
//!
//! [`build_validator`] turns a verified `Receipt` + its canonical bundle + the
//! outer proof into a ready-to-`aiken check` Aiken project. It owns the three
//! things a host should not hand-assemble: outer-backend selection (from the
//! parsed [`OuterProof`] variant), the standard positive/tamper **test suite**,
//! and the `ComposeRequest`. Hosts that need something exotic can still drop
//! down to [`zkwrap_core::compose`] directly.
//!
//! The backend-agnostic outer-layer tests and the deployable-redeemer
//! scaffolding live in [`zkwrap_core::outer_tests`]; only the RISC Zero
//! journal-auth tests are contributed here.

use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{InnerReceipt, Receipt};
use thiserror::Error;

use zkwrap_core::outer_tests::{ba, flip_first_byte, int_list, OuterLayer};
use zkwrap_core::{
    compose, CodegenError, ComposeRequest, GeneratedProject, Groth16Backend, Groth16OuterProof,
    InnerCodegen, OuterCodegen, OuterProof, PlonkBackend, PlonkOuterProof, TestBlock,
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
    /// The outer proof from the prover. Its variant selects the outer layer.
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
    #[error("malformed outer proof: {0}")]
    MalformedProof(String),
    #[error("compose: {0}")]
    Compose(#[from] CodegenError),
}

/// Build the Aiken validator project for a RISC Zero outer proof.
///
/// Selects the outer layer from the [`OuterProof`] variant, generates the
/// standard test suite (outer verify + tamper, plus the RISC Zero journal-auth
/// tests), and composes the project. Call [`GeneratedProject::write_to`] to
/// materialize it on disk.
pub fn build_validator(
    req: &Risc0ValidatorRequest,
) -> Result<GeneratedProject, BuildValidatorError> {
    // Outer-backend dispatch: each arm delegates to a `build_<backend>` that
    // knows that backend's proof shape. Add an arm per new outer backend.
    match req.outer_proof {
        OuterProof::Groth16(proof) => build_groth16(req, proof),
        OuterProof::Plonk(proof) => build_plonk(req, proof),
    }
}

/// Construct the project for a gnark Groth16/BLS12-381 outer proof.
fn build_groth16(
    req: &Risc0ValidatorRequest,
    proof: &Groth16OuterProof,
) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = Groth16Backend;
    let (journal_hex, claim_digest) = risc0_journal_facts(req.receipt)?;
    let proof_hex = proof
        .proof_field_hex()
        .map_err(|e| BuildValidatorError::MalformedProof(e.to_string()))?;
    let proof_lits: Vec<String> = proof_hex.iter().map(|h| ba(h)).collect();
    let layer = OuterLayer {
        outer_mod: backend.module_name(),
        proof_params: backend.proof_params(),
        proof_lits: &proof_lits,
        inner_vk_hash: &proof.inner_vk_hash,
        inputs: &proof.inputs,
    };
    let tests = risc0_tests(&layer, &journal_hex, &claim_digest);

    Ok(compose(&ComposeRequest {
        project_name: req.project_name,
        outer: &backend,
        inner: &Risc0Codegen,
        vk_json: req.outer_vk_json,
        inner_vk_hash: &proof.inner_vk_hash,
        codegen_meta: &req.canonical.codegen,
        tests: &tests,
    })?)
}

/// Construct the project for a gnark PLONK/BLS12-381 outer proof.
fn build_plonk(
    req: &Risc0ValidatorRequest,
    proof: &PlonkOuterProof,
) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = PlonkBackend;
    let (journal_hex, claim_digest) = risc0_journal_facts(req.receipt)?;
    let proof_hex = proof.proof_field_hex();
    let proof_lits: Vec<String> = proof_hex.iter().map(|h| ba(h)).collect();
    let layer = OuterLayer {
        outer_mod: backend.module_name(),
        proof_params: backend.proof_params(),
        proof_lits: &proof_lits,
        inner_vk_hash: &proof.inner_vk_hash,
        inputs: &proof.inputs,
    };
    let tests = risc0_tests(&layer, &journal_hex, &claim_digest);

    Ok(compose(&ComposeRequest {
        project_name: req.project_name,
        outer: &backend,
        inner: &Risc0Codegen,
        vk_json: req.outer_vk_json,
        inner_vk_hash: &proof.inner_vk_hash,
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

/// The standard suite for a RISC Zero outer proof: the backend-agnostic outer
/// layer tests ([`OuterLayer::suite`]) plus the RISC Zero journal-auth tests and
/// the composed deployable-redeemer path. Backend-parametric over the layer, so
/// it serves every outer backend; only the literal proof fields (already in
/// `layer`) differ.
fn risc0_tests(
    layer: &OuterLayer,
    journal_hex: &str,
    expected_claim_digest: &str,
) -> Vec<TestBlock> {
    let inner_mod = Risc0Codegen.module_name();
    let n_real = Risc0Codegen.n_real();
    let reals = int_list(&layer.inputs[0..n_real]);
    let journal_tampered = flip_first_byte(journal_hex);

    let redeemer = |journal: &str| layer.redeemer(&[("journal_bytes", ba(journal))]);
    let composed = |journal: &str| OuterLayer::composed_spend(&redeemer(journal));

    let mut tests = layer.suite();
    tests.extend([
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
    ]);
    tests
}
