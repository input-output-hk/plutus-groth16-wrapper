//! The inner-layer half of the SP1 plugin: ships the generic, constant-free
//! inner-layer source (`sp1.ak`), the typed per-program codegen data
//! ([`Sp1CodegenData`], the bundle's `codegen` section), and the
//! [`InnerCodegen`] impl. [`Sp1CodegenData::wiring`] turns those typed constants
//! (`sp1_program_vkey_hash`, `exit_code`, `vk_root`) into the [`InnerWiring`] the
//! Composer bakes into `validators/verify.ak`.

use serde::{Deserialize, Serialize};
use zkwrap_core::{Hex32, InnerCodegen, InnerWiring, RawParam};

use crate::SYSTEM_ID;

const MODULE_NAME: &str = "sp1";
const N_REAL: usize = 5;

/// The generic inner-layer source, vendored verbatim into the generated project.
const INNER_SOURCE: &str = include_str!("codegen/sp1.ak");

/// The SP1 per-program codegen constants — the `codegen` section of the
/// canonical bundle's `meta.json`. Produced by [`canonicalize`](crate::canonicalize)
/// and consumed by [`wiring`](Self::wiring); typed (and hex/length-validated by
/// serde via [`Hex32`]) so the wiring is total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1CodegenData {
    pub sp1_program_vkey_hash: Hex32,
    pub exit_code: Hex32,
    pub vk_root: Hex32,
}

impl Sp1CodegenData {
    /// The per-program wiring the Composer bakes into `validators/verify.ak`.
    /// Baked, as BN254 Fr `Int`s: inputs[0]=vkey_hash, [2]=exit_code, [3]=vk_root.
    pub fn wiring(&self) -> InnerWiring {
        let consts = vec![
            format!(
                "const sp1_program_vkey_hash: Int = 0x{}",
                hex::encode(self.sp1_program_vkey_hash.0)
            ),
            format!("const exit_code: Int = 0x{}", hex::encode(self.exit_code.0)),
            format!("const vk_root: Int = 0x{}", hex::encode(self.vk_root.0)),
        ];

        InnerWiring {
            consts,
            // Per-proof inputs: public_values (→ committed_values_digest) and the nonce.
            raw_params: vec![
                RawParam::new("public_values", "ByteArray"),
                RawParam::new("proof_nonce", "ByteArray"),
            ],
            call_expr:
                "sp1.real_inputs(public_values, proof_nonce, sp1_program_vkey_hash, exit_code, vk_root)"
                    .to_string(),
        }
    }
}

/// SP1 inner-layer codegen (the static half: module source, name, n_real).
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use zkwrap_core::{Groth16OuterProof, OuterProof, PlonkOuterProof};

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn hex32_hex(s: &str) -> Hex32 {
        Hex32(hex::decode(s).unwrap().as_slice().try_into().unwrap())
    }

    /// The typed codegen as `canonicalize` would emit it, sourced from the
    /// committed SP1 manifest (`sp1_vkey_hash`, `exit_code_hex`, `vk_root_hex`).
    fn test_codegen() -> Sp1CodegenData {
        let m: Value = serde_json::from_slice(
            &std::fs::read(repo_path("fixtures/sp1-hello-world/manifest.json")).unwrap(),
        )
        .unwrap();
        Sp1CodegenData {
            sp1_program_vkey_hash: hex32_hex(
                m["sp1_vkey_hash"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            ),
            exit_code: hex32_hex(m["exit_code_hex"].as_str().unwrap()),
            vk_root: hex32_hex(m["vk_root_hex"].as_str().unwrap()),
        }
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
    /// Backend-parametric: the inner public inputs are independent of the outer
    /// backend, so this holds for every backend's proof.
    fn assert_baked_consts_match<P: OuterProof>(proof_rel: &str) {
        let wiring = test_codegen().wiring();
        let proof = P::from_json(&std::fs::read_to_string(repo_path(proof_rel)).unwrap()).unwrap();
        assert_int_const_matches(&wiring.consts, "sp1_program_vkey_hash", &proof.inputs()[0]);
        assert_int_const_matches(&wiring.consts, "exit_code", &proof.inputs()[2]);
        assert_int_const_matches(&wiring.consts, "vk_root", &proof.inputs()[3]);
    }

    #[test]
    fn baked_consts_match_groth16_proof() {
        assert_baked_consts_match::<Groth16OuterProof>(
            "fixtures/outer-proofs/sp1-groth16-outer-proof.json",
        );
    }

    #[test]
    fn baked_consts_match_plonk_proof() {
        assert_baked_consts_match::<PlonkOuterProof>(
            "fixtures/outer-proofs/sp1-plonk-outer-proof.json",
        );
    }

    #[test]
    fn wiring_shape() {
        let wiring = test_codegen().wiring();
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

    /// A wrong-length hex field is rejected at deserialize time by `Hex32`.
    #[test]
    fn rejects_short_field() {
        let json = r#"{
            "sp1_program_vkey_hash": "0034",
            "exit_code": "0000000000000000000000000000000000000000000000000000000000000000",
            "vk_root": "0000000000000000000000000000000000000000000000000000000000000000"
        }"#;
        let parsed: Result<Sp1CodegenData, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    /// A missing field is rejected at deserialize time.
    #[test]
    fn rejects_missing_field() {
        let parsed: Result<Sp1CodegenData, _> = serde_json::from_str("{}");
        assert!(parsed.is_err());
    }
}
