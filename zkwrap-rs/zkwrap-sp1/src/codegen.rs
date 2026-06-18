//! The inner-layer half of the SP1 plugin: ships the generic, constant-free
//! inner-layer source (`sp1.ak`) and implements [`InnerCodegen`], turning the
//! canonical inner proof's `meta.json.codegen` section (the per-program/version
//! `sp1_program_vkey_hash`, `exit_code`, `vk_root`) into the wiring the Composer
//! bakes into `validators/verify.ak`.

use serde_json::Value;
use zkwrap_core::{CodegenError, InnerCodegen, InnerWiring, RawParam};

use crate::SYSTEM_ID;

const MODULE_NAME: &str = "sp1";
const N_REAL: usize = 5;

/// The generic inner-layer source, vendored verbatim into the generated project.
const INNER_SOURCE: &str = include_str!("codegen/sp1.ak");

/// SP1 inner-layer codegen.
pub struct Sp1Codegen;

impl InnerCodegen for Sp1Codegen {
    fn system_id(&self) -> &str {
        SYSTEM_ID
    }

    fn n_real(&self) -> usize {
        N_REAL
    }

    fn module_name(&self) -> &str {
        MODULE_NAME
    }

    fn module_source(&self) -> &'static str {
        INNER_SOURCE
    }

    fn wiring(&self, codegen: &Value) -> Result<InnerWiring, CodegenError> {
        // Baked, as BN254 Fr `Int`s: inputs[0]=vkey_hash, [2]=exit_code, [3]=vk_root.
        let program_vkey_hash = hex_field(codegen, "sp1_program_vkey_hash", 32)?;
        let exit_code = hex_field(codegen, "exit_code", 32)?;
        let vk_root = hex_field(codegen, "vk_root", 32)?;

        let consts = vec![
            format!(
                "const sp1_program_vkey_hash: Int = 0x{}",
                hex::encode(&program_vkey_hash)
            ),
            format!("const exit_code: Int = 0x{}", hex::encode(&exit_code)),
            format!("const vk_root: Int = 0x{}", hex::encode(&vk_root)),
        ];

        Ok(InnerWiring {
            consts,
            // Per-proof inputs: public_values (→ committed_values_digest) and the nonce.
            raw_params: vec![
                RawParam::new("public_values", "ByteArray"),
                RawParam::new("proof_nonce", "ByteArray"),
            ],
            call_expr:
                "sp1.real_inputs(public_values, proof_nonce, sp1_program_vkey_hash, exit_code, vk_root)"
                    .to_string(),
        })
    }
}

fn hex_field(codegen: &Value, key: &str, expect_len: usize) -> Result<Vec<u8>, CodegenError> {
    let s = codegen
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| CodegenError::Meta(format!("missing string field {key:?}")))?;
    let bytes = hex::decode(s).map_err(|e| CodegenError::Meta(format!("{key}: bad hex: {e}")))?;
    if bytes.len() != expect_len {
        return Err(CodegenError::Meta(format!(
            "{key}: expected {expect_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkwrap_core::OuterProof;

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    /// The codegen meta as `canonicalize` would emit it, sourced from the
    /// committed SP1 manifest (`sp1_vkey_hash`, `exit_code_hex`, `vk_root_hex`).
    fn test_codegen() -> Value {
        let m: Value = serde_json::from_slice(
            &std::fs::read(repo_path("fixtures/sp1-hello-world/manifest.json")).unwrap(),
        )
        .unwrap();
        serde_json::json!({
            "sp1_program_vkey_hash": m["sp1_vkey_hash"].as_str().unwrap().trim_start_matches("0x"),
            "exit_code": m["exit_code_hex"].as_str().unwrap(),
            "vk_root": m["vk_root_hex"].as_str().unwrap(),
        })
    }

    fn const_value(consts: &[String], name: &str) -> String {
        let prefix = format!("const {name}: ");
        let line = consts
            .iter()
            .find(|c| c.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no const {name}"));
        line.split('=').nth(1).unwrap().trim().to_string()
    }

    fn assert_int_const_matches(consts: &[String], name: &str, expected_be_hex: &str) {
        let v = const_value(consts, name);
        let hex_part = v.strip_prefix("0x").expect("0x int literal");
        assert_eq!(
            format!("{:0>64}", hex_part),
            expected_be_hex,
            "const {name}"
        );
    }

    /// The baked version-constant inputs (program vkey hash=[0], exit_code=[2],
    /// vk_root=[3]) must equal the corresponding slots of the outer proof.
    #[test]
    fn baked_consts_match_outer_proof() {
        let wiring = Sp1Codegen.wiring(&test_codegen()).unwrap();
        let proof = OuterProof::from_json(
            &std::fs::read_to_string(repo_path(
                "fixtures/outer-proofs/sp1-groth16-outer-proof.json",
            ))
            .unwrap(),
        )
        .unwrap();
        assert_int_const_matches(&wiring.consts, "sp1_program_vkey_hash", &proof.inputs[0]);
        assert_int_const_matches(&wiring.consts, "exit_code", &proof.inputs[2]);
        assert_int_const_matches(&wiring.consts, "vk_root", &proof.inputs[3]);
    }

    #[test]
    fn wiring_shape() {
        let wiring = Sp1Codegen.wiring(&test_codegen()).unwrap();
        assert_eq!(
            wiring.raw_params,
            vec![
                RawParam::new("public_values", "ByteArray"),
                RawParam::new("proof_nonce", "ByteArray"),
            ]
        );
        assert_eq!(
            wiring.call_expr,
            "sp1.real_inputs(public_values, proof_nonce, sp1_program_vkey_hash, exit_code, vk_root)"
        );
        assert_eq!(wiring.consts.len(), 3);
        assert_eq!(Sp1Codegen.n_real(), 5);
        assert_eq!(Sp1Codegen.module_name(), "sp1");
        assert_eq!(Sp1Codegen.system_id(), "sp1-v6");
    }

    #[test]
    fn rejects_short_field() {
        let mut bad = test_codegen();
        bad["sp1_program_vkey_hash"] = serde_json::json!("0034");
        assert!(matches!(
            Sp1Codegen.wiring(&bad),
            Err(CodegenError::Meta(_))
        ));
    }

    #[test]
    fn rejects_missing_field() {
        assert!(matches!(
            Sp1Codegen.wiring(&serde_json::json!({})),
            Err(CodegenError::Meta(_))
        ));
    }
}
