//! The SP1 validator factory — the host's one-call entry point.
//!
//! [`build_validator`] turns a canonical bundle + outer proof into a
//! ready-to-`aiken check` Aiken project. It owns outer-backend selection (from
//! the parsed [`OuterProof`] variant), the standard positive/tamper **test
//! suite**, and the `ComposeRequest`. Hosts that need something exotic can still
//! drop down to [`zkwrap_core::compose`] directly.
//!
//! The backend-agnostic outer-layer tests and the deployable-redeemer
//! scaffolding live in [`zkwrap_core::outer_tests`] (shared with
//! `zkwrap_risc0::validator`); only the SP1 public-values / nonce tests are
//! contributed here.

use thiserror::Error;

use zkwrap_core::outer_tests::{ba, flip_first_byte, int, int_list, OuterLayer};
use zkwrap_core::{
    compose, CodegenError, ComposeRequest, GeneratedProject, Groth16Backend, Groth16OuterProof,
    InnerCodegen, OuterCodegen, OuterProof, PlonkBackend, PlonkOuterProof, TestBlock,
};

use crate::{Canonicalized, Sp1Codegen};

/// Inputs to [`build_validator`]. All borrowed — the host already holds each.
pub struct Sp1ValidatorRequest<'a> {
    /// The canonical bundle from [`canonicalize`](crate::canonicalize); its
    /// `codegen` section (`sp1_program_vkey_hash`/`exit_code`/`vk_root`) drives the wiring.
    pub canonical: &'a Canonicalized,
    /// The outer proof from the prover. Its variant selects the outer layer.
    pub outer_proof: &'a OuterProof,
    /// Raw `outer_vk.json` text from the trusted setup.
    pub outer_vk_json: &'a str,
    /// The SP1 public values (the bytes the guest committed). The generated SP1
    /// tests bind the `committed_values_digest` derivation against these.
    pub public_values: &'a [u8],
    /// Aiken project name, `namespace/name` form (e.g. `"zkwrap/sp1_groth16"`).
    pub project_name: &'a str,
}

/// Why [`build_validator`] could not produce a project.
#[derive(Debug, Error)]
pub enum BuildValidatorError {
    #[error("malformed outer proof: {0}")]
    MalformedProof(String),
    #[error("compose: {0}")]
    Compose(#[from] CodegenError),
}

/// Build the Aiken validator project for an SP1 outer proof.
///
/// Selects the outer layer from the [`OuterProof`] variant, generates the
/// standard test suite (outer verify + tamper, plus the SP1 public-values/nonce
/// tests), and composes the project. Call [`GeneratedProject::write_to`] to
/// materialize it on disk.
pub fn build_validator(req: &Sp1ValidatorRequest) -> Result<GeneratedProject, BuildValidatorError> {
    match req.outer_proof {
        OuterProof::Groth16(proof) => build_groth16(req, proof),
        OuterProof::Plonk(proof) => build_plonk(req, proof),
    }
}

/// Construct the project for a gnark Groth16/BLS12-381 outer proof.
fn build_groth16(
    req: &Sp1ValidatorRequest,
    proof: &Groth16OuterProof,
) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = Groth16Backend;
    let proof_hex = proof
        .proof_field_hex()
        .map_err(|e| BuildValidatorError::MalformedProof(e.to_string()))?;
    build_with(
        req,
        &backend,
        &proof.inner_vk_hash,
        &proof.inputs,
        &proof_hex,
    )
}

/// Construct the project for a gnark PLONK/BLS12-381 outer proof.
fn build_plonk(
    req: &Sp1ValidatorRequest,
    proof: &PlonkOuterProof,
) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = PlonkBackend;
    build_with(
        req,
        &backend,
        &proof.inner_vk_hash,
        &proof.inputs,
        &proof.proof_field_hex(),
    )
}

/// Backend-parametric assembly: build the outer layer wiring, the SP1 test
/// suite, and compose. The only per-backend inputs are the [`OuterCodegen`] and
/// the proof field hex (in its `proof_params` order).
fn build_with(
    req: &Sp1ValidatorRequest,
    backend: &dyn OuterCodegen,
    inner_vk_hash: &str,
    inputs: &[String],
    proof_hex: &[String],
) -> Result<GeneratedProject, BuildValidatorError> {
    let public_values_hex = hex::encode(req.public_values);
    // proof_nonce is public input 4 of the canonical bundle (see `canonicalize`).
    let proof_nonce_hex = hex::encode(req.canonical.proof.public_inputs[4].0);

    let proof_lits: Vec<String> = proof_hex.iter().map(|h| ba(h)).collect();
    let layer = OuterLayer {
        outer_mod: backend.module_name(),
        proof_params: backend.proof_params(),
        proof_lits: &proof_lits,
        inner_vk_hash,
        inputs,
    };
    let tests = sp1_tests(&layer, &public_values_hex, &proof_nonce_hex);

    Ok(compose(&ComposeRequest {
        project_name: req.project_name,
        outer: backend,
        inner: &Sp1Codegen,
        vk_json: req.outer_vk_json,
        inner_vk_hash,
        codegen_meta: &req.canonical.codegen,
        tests: &tests,
    })?)
}

/// The standard suite for an SP1 outer proof: the backend-agnostic outer layer
/// tests ([`OuterLayer::suite`]) plus the SP1 public-values / nonce tests and the
/// composed deployable-redeemer path.
fn sp1_tests(layer: &OuterLayer, public_values_hex: &str, proof_nonce_hex: &str) -> Vec<TestBlock> {
    let inner_mod = Sp1Codegen.module_name();
    let n_real = Sp1Codegen.n_real();
    let reals = int_list(&layer.inputs[0..n_real]);
    let public_values_tampered = flip_first_byte(public_values_hex);
    let proof_nonce_tampered = flip_first_byte(proof_nonce_hex);

    let redeemer = |public_values: &str, proof_nonce: &str| {
        layer.redeemer(&[
            ("public_values", ba(public_values)),
            ("proof_nonce", ba(proof_nonce)),
        ])
    };
    let composed = |public_values: &str, proof_nonce: &str| {
        OuterLayer::composed_spend(&redeemer(public_values, proof_nonce))
    };

    let mut tests = layer.suite();
    tests.extend([
        TestBlock::pass(
            "committed_values_digest_matches",
            format!(
                "{inner_mod}.committed_values_digest({}) == {}",
                ba(public_values_hex),
                int(&layer.inputs[1])
            ),
        ),
        TestBlock::pass(
            "sp1_inputs_match_proof",
            format!(
                "{inner_mod}.real_inputs({}, {}, sp1_program_vkey_hash, exit_code, vk_root) == {reals}",
                ba(public_values_hex),
                ba(proof_nonce_hex)
            ),
        ),
        TestBlock::pass(
            "verify_sp1_valid_proof",
            composed(public_values_hex, proof_nonce_hex),
        ),
        TestBlock::fail(
            "verify_sp1_tampered_public_values",
            composed(&public_values_tampered, proof_nonce_hex),
        ),
        TestBlock::fail(
            "verify_sp1_tampered_proof_nonce",
            composed(public_values_hex, &proof_nonce_tampered),
        ),
    ]);
    tests
}
