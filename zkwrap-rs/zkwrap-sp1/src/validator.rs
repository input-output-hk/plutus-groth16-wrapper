//! The SP1 validator factory — the host's one-call entry point.
//!
//! [`build_validator`] turns a canonical bundle + outer proof into a
//! ready-to-`aiken check` Aiken project. It owns outer-backend selection (from
//! the proof's `backend` id), the standard positive/tamper **test suite**, and
//! the `ComposeRequest`. Hosts that need something exotic can still drop down to
//! [`zkwrap_core::compose`] directly.
//!
//! Mirrors `zkwrap_risc0::validator`; the inner-agnostic outer tests are
//! duplicated for now (slated for extraction into a shared `zkwrap-core`
//! generator once both plugins are green).

use thiserror::Error;

use zkwrap_core::{
    compose, CodegenError, ComposeRequest, GeneratedProject, Groth16Backend, InnerCodegen,
    OuterCodegen, OuterProof, TestBlock,
};

use crate::{Canonicalized, Sp1Codegen};

/// Inputs to [`build_validator`]. All borrowed — the host already holds each.
pub struct Sp1ValidatorRequest<'a> {
    /// The canonical bundle from [`canonicalize`](crate::canonicalize); its
    /// `codegen` section (`vkey_hash`/`exit_code`/`vk_root`) drives the wiring.
    pub canonical: &'a Canonicalized,
    /// The outer proof from the prover. Its `backend` id selects the outer layer.
    pub outer_proof: &'a OuterProof,
    /// Raw `outer_vk.json` text from the trusted setup.
    pub outer_vk_json: &'a str,
    /// The SP1 public values (the bytes the guest committed). The generated SP1
    /// tests bind the `committed_values_digest` derivation against these.
    pub public_values: &'a [u8],
    /// The per-proof `proof_nonce` (32-byte big-endian, public input 4).
    pub proof_nonce: &'a [u8],
    /// Aiken project name, `namespace/name` form (e.g. `"zkwrap/sp1_groth16"`).
    pub project_name: &'a str,
}

/// Why [`build_validator`] could not produce a project.
#[derive(Debug, Error)]
pub enum BuildValidatorError {
    #[error("unknown outer backend {0:?}")]
    UnknownBackend(String),
    #[error("malformed outer proof: {0}")]
    MalformedProof(String),
    #[error("compose: {0}")]
    Compose(#[from] CodegenError),
}

/// Build the Aiken validator project for an SP1 outer proof.
///
/// Selects the outer layer from `outer_proof.backend`, generates the standard
/// test suite (outer verify + tamper, plus the SP1 public-values/nonce tests),
/// and composes the project. Call [`GeneratedProject::write_to`] to materialize
/// it on disk.
pub fn build_validator(req: &Sp1ValidatorRequest) -> Result<GeneratedProject, BuildValidatorError> {
    match req.outer_proof.backend.as_str() {
        b if b == Groth16Backend.backend_id() => build_groth16(req),
        other => Err(BuildValidatorError::UnknownBackend(other.to_string())),
    }
}

/// Construct the project for a gnark Groth16/BLS12-381 outer proof.
fn build_groth16(req: &Sp1ValidatorRequest) -> Result<GeneratedProject, BuildValidatorError> {
    let backend = Groth16Backend;
    let public_values_hex = hex::encode(req.public_values);
    let proof_nonce_hex = hex::encode(req.proof_nonce);
    let tests = groth16_tests(
        &backend,
        req.outer_proof,
        &public_values_hex,
        &proof_nonce_hex,
    )?;

    Ok(compose(&ComposeRequest {
        project_name: req.project_name,
        outer: &backend,
        inner: &Sp1Codegen,
        vk_json: req.outer_vk_json,
        inner_vk_hash: &req.outer_proof.inner_vk_hash,
        codegen_meta: &req.canonical.codegen,
        tests: &tests,
    })?)
}

/// The standard positive + tamper-negative suite for a Groth16 outer proof.
/// The outer-layer tests use the universal outer ABI
/// (`groth16.verify(<proof…>, inner_vk_hash, inputs)`); the SP1 tests reference
/// the consts the inner wiring bakes (`vkey_hash`/`exit_code`/`vk_root`) and the
/// `public_values` + `proof_nonce` redeemer fields.
fn groth16_tests(
    outer: &Groth16Backend,
    proof: &OuterProof,
    public_values_hex: &str,
    proof_nonce_hex: &str,
) -> Result<Vec<TestBlock>, BuildValidatorError> {
    let outer_mod = outer.module_name();
    let inner_mod = Sp1Codegen.module_name();
    let n_real = Sp1Codegen.n_real();

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
    let public_values_tampered = flip_first_byte(public_values_hex);
    let proof_nonce_tampered = flip_first_byte(proof_nonce_hex);

    // Outer layer, literal-input form: <mod>.verify(proof…, vkhash, inputs).
    let l1_verify = |vkh: &str, ins: &str| {
        format!("{outer_mod}.verify(\n  {proof_lits},\n  {vkh},\n  {ins},\n)")
    };

    // Composed entry through the deployable redeemer path. Field names match the
    // generated `Redeemer` type: the outer backend's proof params + public_values
    // + proof_nonce.
    let redeemer = |public_values: &str, proof_nonce: &str| {
        let proof_fields = outer
            .proof_params()
            .iter()
            .zip([&pi_a, &pi_b, &pi_c, &cu, &pok])
            .map(|(name, val)| format!("{name}: {val}"))
            .collect::<Vec<_>>()
            .join(",\n  ");
        format!(
            "Redeemer {{\n  {proof_fields},\n  public_values: {},\n  proof_nonce: {},\n}}",
            ba(public_values),
            ba(proof_nonce)
        )
    };
    // A mock UTxO ref; the validator ignores datum/utxo/tx, so a placeholder tx
    // and a zero ref suffice to exercise the deployable `spend` handler.
    let mock_ref = "OutputReference { transaction_id: #\"0000000000000000000000000000000000000000000000000000000000000000\", output_index: 0 }";
    let composed = |public_values: &str, proof_nonce: &str| {
        format!(
            "wrapper.spend(\n  None,\n  {},\n  {mock_ref},\n  placeholder,\n)",
            redeemer(public_values, proof_nonce)
        )
    };

    Ok(vec![
        TestBlock::pass("verify_valid_proof", l1_verify(&vkhash, &inputs)),
        TestBlock::fail(
            "verify_tampered_inner_vk_hash",
            l1_verify(&format!("{vkhash} + 1"), &inputs),
        ),
        TestBlock::fail(
            "verify_tampered_input",
            l1_verify(&vkhash, &inputs_tampered),
        ),
        TestBlock::pass(
            "committed_values_digest_matches",
            format!(
                "{inner_mod}.committed_values_digest({}) == {}",
                ba(public_values_hex),
                int(&proof.inputs[1])
            ),
        ),
        TestBlock::pass(
            "sp1_inputs_match_proof",
            format!(
                "{inner_mod}.real_inputs({}, {}, vkey_hash, exit_code, vk_root) == {reals}",
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

/// Increment a 32-byte big-endian hex value by 1 (the last byte of a real
/// BN254 Fr public input is never 0xff here, so no carry to worry about).
fn bump_last(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] += 1;
    hex::encode(bytes)
}

/// Flip the low bit of the first byte — a different, same-length value that must
/// make the composed entry point reject.
fn flip_first_byte(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    bytes[0] ^= 0x01;
    hex::encode(bytes)
}
