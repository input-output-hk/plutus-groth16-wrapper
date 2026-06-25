//! The inner-layer half of the RISC Zero plugin: ships the generic,
//! constant-free inner-layer source (`risc0.ak`), the typed per-guest codegen
//! data ([`Risc0CodegenData`], the bundle's `codegen` section), and the
//! [`InnerCodegen`] impl. [`Risc0CodegenData::wiring`] turns those typed
//! constants into the [`InnerWiring`] the Composer bakes into
//! `validators/verify.ak`.

use serde::{Deserialize, Serialize};
use zkwrap_core::{Hex32, InnerCodegen, InnerWiring, RawParam};

use crate::SYSTEM_ID;

const MODULE_NAME: &str = "risc0";
const N_REAL: usize = 5;

/// The generic inner-layer source, vendored verbatim into the generated project.
const INNER_SOURCE: &str = include_str!("codegen/risc0.ak");

/// The RISC Zero per-guest codegen constants — the `codegen` section of the
/// canonical bundle's `meta.json`. Produced by [`canonicalize`](crate::canonicalize)
/// and consumed by [`wiring`](Self::wiring); typed (and hex/length-validated by
/// serde via [`Hex32`]) so the wiring is total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Risc0CodegenData {
    pub image_id: Hex32,
    pub post_state_digest: Hex32,
    pub control_root: Hex32,
    pub bn254_control_id: Hex32,
}

impl Risc0CodegenData {
    /// The per-guest wiring the Composer bakes into `validators/verify.ak`.
    pub fn wiring(&self) -> InnerWiring {
        // inputs[0,1] = split_digest(control_root): each 16-byte half read
        // little-endian (== reverse the half, read big-endian).
        let cr = &self.control_root.0;
        let cr0 = hex::encode(le_int_bytes(&cr[0..16]));
        let cr1 = hex::encode(le_int_bytes(&cr[16..32]));
        // inputs[4] = Fr(reverse_bytes(bn254_control_id)).
        let bn254 = hex::encode(le_int_bytes(&self.bn254_control_id.0));

        let consts = vec![
            format!("const control_root_0: Int = 0x{cr0}"),
            format!("const control_root_1: Int = 0x{cr1}"),
            format!(
                "const image_id: ByteArray = #\"{}\"",
                hex::encode(self.image_id.0)
            ),
            format!(
                "const post_state_digest: ByteArray = #\"{}\"",
                hex::encode(self.post_state_digest.0)
            ),
            format!("const bn254_control_id: Int = 0x{bn254}"),
        ];

        InnerWiring {
            consts,
            raw_params: vec![RawParam::new("journal_bytes", "ByteArray")],
            call_expr: "risc0.real_inputs(journal_bytes, control_root_0, control_root_1, \
                        image_id, post_state_digest, bn254_control_id)"
                .to_string(),
        }
    }
}

/// RISC Zero inner-layer codegen (the static half: module source, name, n_real).
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
}

/// Big-endian bytes of the integer obtained by reading `bytes` little-endian
/// (i.e. the reversed byte order). Suitable for an Aiken `0x…` literal.
fn le_int_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.reverse();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkwrap_core::{Groth16OuterProof, OuterProof, PlonkOuterProof};

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn hex32_fixture(name: &str) -> Hex32 {
        let bytes =
            std::fs::read(repo_path(&format!("fixtures/risc0-hello-world/{name}"))).unwrap();
        Hex32(bytes.as_slice().try_into().unwrap())
    }

    fn hex32_hex(s: &str) -> Hex32 {
        Hex32(hex::decode(s).unwrap().as_slice().try_into().unwrap())
    }

    /// The typed `codegen` section, assembled from the RISC Zero fixtures.
    /// `post_state_digest` (SystemState{pc:0, merkle_root:ZERO}.digest()) is the
    /// cleanly-halted constant pinned in the spike.
    fn test_codegen() -> Risc0CodegenData {
        Risc0CodegenData {
            image_id: hex32_fixture("image_id.bin"),
            post_state_digest: hex32_hex(
                "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            ),
            control_root: hex32_fixture("control_root.bin"),
            bn254_control_id: hex32_fixture("bn254_control_id.bin"),
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

    /// A baked `0x…` Int const must equal the corresponding 32-byte BE Fr hex
    /// from outer_proof.json (compared numerically via zero-padding).
    fn assert_int_const_matches(consts: &[String], name: &str, expected_be_hex: &str) {
        let v = const_value(consts, name);
        let hex_part = v.strip_prefix("0x").expect("0x int literal");
        let padded = format!("{:0>64}", hex_part);
        assert_eq!(padded, expected_be_hex, "const {name} mismatch");
    }

    /// The baked version-constant reals (inputs[0], [1], [4]) must equal the
    /// corresponding slots of the outer proof. Backend-parametric: the inner
    /// public inputs are independent of the outer backend, so this holds for
    /// every backend's proof.
    fn assert_baked_inputs_match<P: OuterProof>(proof_rel: &str) {
        let wiring = test_codegen().wiring();
        let proof = P::from_json(&std::fs::read_to_string(repo_path(proof_rel)).unwrap()).unwrap();
        assert_int_const_matches(&wiring.consts, "control_root_0", &proof.inputs()[0]);
        assert_int_const_matches(&wiring.consts, "control_root_1", &proof.inputs()[1]);
        assert_int_const_matches(&wiring.consts, "bn254_control_id", &proof.inputs()[4]);
    }

    #[test]
    fn baked_inputs_match_groth16_proof() {
        assert_baked_inputs_match::<Groth16OuterProof>(
            "fixtures/outer-proofs/risc0-groth16-outer-proof.json",
        );
    }

    #[test]
    fn baked_inputs_match_plonk_proof() {
        assert_baked_inputs_match::<PlonkOuterProof>(
            "fixtures/outer-proofs/risc0-plonk-outer-proof.json",
        );
    }

    #[test]
    fn wiring_shape() {
        let wiring = test_codegen().wiring();
        assert_eq!(
            wiring.raw_params,
            vec![RawParam::new("journal_bytes", "ByteArray")]
        );
        assert!(wiring
            .call_expr
            .starts_with("risc0.real_inputs(journal_bytes,"));
        assert_eq!(wiring.consts.len(), 5);
        // image_id baked as the guest pre_state_digest.
        assert!(wiring
            .consts
            .iter()
            .any(|c| c.contains("image_id: ByteArray = #\"2bc2287e688aaf25")));
    }

    /// A wrong-length hex field is rejected at deserialize time by `Hex32`,
    /// before any wiring runs.
    #[test]
    fn rejects_short_field() {
        let json = r#"{
            "image_id": "2bc2",
            "post_state_digest": "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            "control_root": "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56",
            "bn254_control_id": "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404"
        }"#;
        let parsed: Result<Risc0CodegenData, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }
}
