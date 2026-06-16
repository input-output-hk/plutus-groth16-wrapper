//! The inner-layer half of the SP1 plugin: ships the generic, constant-free
//! inner-layer source (`sp1.ak`) and implements [`InnerCodegen`], turning the
//! canonical inner proof's `meta.json.codegen` section (the per-program
//! `vkey_hash`) into the wiring the Composer bakes into `validators/verify.ak`.

use serde_json::Value;
use zkwrap_core::{CodegenError, InnerCodegen, InnerWiring, RawParam};

use crate::SYSTEM_ID;

const MODULE_NAME: &str = "sp1";
const N_REAL: usize = 2;

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
        let vkey_hash = hex_field(codegen, "vkey_hash", 32)?;

        // inputs[0] = vkey_hash, the program identity, baked as a BN254 Fr Int.
        let consts = vec![format!(
            "const vkey_hash: Int = 0x{}",
            hex::encode(&vkey_hash)
        )];

        Ok(InnerWiring {
            consts,
            raw_params: vec![RawParam::new("public_values", "ByteArray")],
            call_expr: "sp1.real_inputs(public_values, vkey_hash)".to_string(),
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

    fn test_codegen() -> Value {
        let vkey_hash = hex::encode(
            std::fs::read(repo_path("fixtures/sp1-hello-world/vkey_hash.bin")).unwrap(),
        );
        serde_json::json!({ "vkey_hash": vkey_hash })
    }

    fn const_value(consts: &[String], name: &str) -> String {
        let prefix = format!("const {name}: ");
        let line = consts
            .iter()
            .find(|c| c.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no const {name}"));
        line.split('=').nth(1).unwrap().trim().to_string()
    }

    /// The baked `vkey_hash` Int const must equal the 32-byte BE Fr hex of
    /// inputs[0] from the outer proof (compared numerically via zero-padding).
    #[test]
    fn baked_vkey_hash_matches_outer_proof() {
        let wiring = Sp1Codegen.wiring(&test_codegen()).unwrap();
        let proof = OuterProof::from_json(
            &std::fs::read_to_string(repo_path("fixtures/sp1-outer-proof.json")).unwrap(),
        )
        .unwrap();
        let v = const_value(&wiring.consts, "vkey_hash");
        let hex_part = v.strip_prefix("0x").expect("0x int literal");
        assert_eq!(format!("{:0>64}", hex_part), proof.inputs[0]);
    }

    #[test]
    fn wiring_shape() {
        let wiring = Sp1Codegen.wiring(&test_codegen()).unwrap();
        assert_eq!(
            wiring.raw_params,
            vec![RawParam::new("public_values", "ByteArray")]
        );
        assert_eq!(
            wiring.call_expr,
            "sp1.real_inputs(public_values, vkey_hash)"
        );
        assert_eq!(wiring.consts.len(), 1);
        assert_eq!(Sp1Codegen.n_real(), 2);
        assert_eq!(Sp1Codegen.module_name(), "sp1");
        assert_eq!(Sp1Codegen.system_id(), "sp1-v3");
    }

    #[test]
    fn rejects_short_field() {
        let bad = serde_json::json!({ "vkey_hash": "0034" });
        assert!(matches!(
            Sp1Codegen.wiring(&bad),
            Err(CodegenError::Meta(_))
        ));
    }

    #[test]
    fn rejects_missing_field() {
        let bad = serde_json::json!({});
        assert!(matches!(
            Sp1Codegen.wiring(&bad),
            Err(CodegenError::Meta(_))
        ));
    }
}
