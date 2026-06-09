//! The inner-layer half of the RISC Zero plugin: ships the generic,
//! constant-free inner-layer source (`risc0.ak`) and implements
//! [`InnerCodegen`], turning the canonical inner proof's `meta.json.codegen`
//! section (per-guest constants) into the wiring the Composer bakes into
//! `validators/verify.ak`.

use serde_json::Value;
use zkwrap_core::{CodegenError, InnerCodegen, InnerWiring, RawParam};

use crate::SYSTEM_ID;

const MODULE_NAME: &str = "risc0";
const N_REAL: usize = 5;

/// The generic inner-layer source, vendored verbatim into the generated project.
const INNER_SOURCE: &str = include_str!("codegen/risc0.ak");

/// RISC Zero inner-layer codegen.
pub struct Risc0Codegen;

impl InnerCodegen for Risc0Codegen {
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
        let image_id = hex_field(codegen, "image_id", 32)?;
        let post_state = hex_field(codegen, "post_state_digest", 32)?;
        let control_root = hex_field(codegen, "control_root", 32)?;
        let bn254_control_id = hex_field(codegen, "bn254_control_id", 32)?;

        // inputs[0,1] = split_digest(control_root): each 16-byte half read
        // little-endian (== reverse the half, read big-endian).
        let cr0 = hex::encode(le_int_bytes(&control_root[0..16]));
        let cr1 = hex::encode(le_int_bytes(&control_root[16..32]));
        // inputs[4] = Fr(reverse_bytes(bn254_control_id)).
        let bn254 = hex::encode(le_int_bytes(&bn254_control_id));

        let consts = vec![
            format!("const control_root_0: Int = 0x{cr0}"),
            format!("const control_root_1: Int = 0x{cr1}"),
            format!("const image_id: ByteArray = #\"{}\"", hex::encode(&image_id)),
            format!(
                "const post_state_digest: ByteArray = #\"{}\"",
                hex::encode(&post_state)
            ),
            format!("const bn254_control_id: Int = 0x{bn254}"),
        ];

        Ok(InnerWiring {
            consts,
            raw_params: vec![RawParam::new("journal_bytes", "ByteArray")],
            call_expr: "risc0.real_inputs(journal_bytes, control_root_0, control_root_1, \
                        image_id, post_state_digest, bn254_control_id)"
                .to_string(),
        })
    }
}

/// Big-endian bytes of the integer obtained by reading `bytes` little-endian
/// (i.e. the reversed byte order). Suitable for an Aiken `0x…` literal.
fn le_int_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.reverse();
    v
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

    fn risc0_fixture_hex(name: &str) -> String {
        hex::encode(std::fs::read(repo_path(&format!("experiments/risc0-hello-world/fixtures/{name}"))).unwrap())
    }

    /// The `meta.json.codegen` section, assembled from the RISC Zero fixtures.
    /// `post_state_digest` (SystemState{pc:0, merkle_root:ZERO}.digest()) is the
    /// cleanly-halted constant pinned in the spike.
    fn test_codegen() -> Value {
        serde_json::json!({
            "image_id": risc0_fixture_hex("image_id.bin"),
            "post_state_digest": "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            "control_root": risc0_fixture_hex("control_root.bin"),
            "bn254_control_id": risc0_fixture_hex("bn254_control_id.bin"),
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

    /// A baked `0x…` Int const must equal the corresponding 32-byte BE Fr hex
    /// from outer_proof.json (compared numerically via zero-padding).
    fn assert_int_const_matches(consts: &[String], name: &str, expected_be_hex: &str) {
        let v = const_value(consts, name);
        let hex_part = v.strip_prefix("0x").expect("0x int literal");
        let padded = format!("{:0>64}", hex_part);
        assert_eq!(padded, expected_be_hex, "const {name} mismatch");
    }

    #[test]
    fn baked_inputs_match_outer_proof() {
        let wiring = Risc0Codegen.wiring(&test_codegen()).unwrap();
        let proof = OuterProof::from_json(
            &std::fs::read_to_string(repo_path("zkwrap-gnark/testdata/groth16-outer-proof.json"))
                .unwrap(),
        )
        .unwrap();

        // Version-constant reals: inputs[0], inputs[1], inputs[4].
        assert_int_const_matches(&wiring.consts, "control_root_0", &proof.inputs[0]);
        assert_int_const_matches(&wiring.consts, "control_root_1", &proof.inputs[1]);
        assert_int_const_matches(&wiring.consts, "bn254_control_id", &proof.inputs[4]);
    }

    #[test]
    fn wiring_shape() {
        let wiring = Risc0Codegen.wiring(&test_codegen()).unwrap();
        assert_eq!(wiring.raw_params, vec![RawParam::new("journal_bytes", "ByteArray")]);
        assert!(wiring.call_expr.starts_with("risc0.real_inputs(journal_bytes,"));
        assert_eq!(wiring.consts.len(), 5);
        // image_id baked as the guest pre_state_digest.
        assert!(wiring
            .consts
            .iter()
            .any(|c| c.contains("image_id: ByteArray = #\"2bc2287e688aaf25")));
    }

    #[test]
    fn rejects_short_field() {
        let bad = serde_json::json!({
            "image_id": "2bc2",
            "post_state_digest": "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            "control_root": "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56",
            "bn254_control_id": "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        });
        assert!(matches!(
            Risc0Codegen.wiring(&bad),
            Err(CodegenError::Meta(_))
        ));
    }
}
