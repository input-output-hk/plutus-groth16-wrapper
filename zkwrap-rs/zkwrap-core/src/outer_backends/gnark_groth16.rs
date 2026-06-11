//! The gnark Groth16/BLS12-381 outer backend — the outer-layer proving engine.
//!
//! Renders the generic `groth16.ak` verifier with the setup-bound crypto
//! (outer VK points, IC array, Pedersen commitment keys) baked into `verify`
//! from an [`OuterVk`].

/// The outer-proof artifact schema (`outer_vk.json` / `outer_proof.json`).
pub mod artifacts;
/// Off-chain `InnerVKHash` cross-check (gnark-crypto drift detector; not on the
/// codegen path).
pub mod vk_hash;

use self::artifacts::OuterVk;
use crate::codegen::{CodegenError, OuterCodegen, OuterWiring};
use minijinja::{context, Environment};

const OUTER_TEMPLATE: &str = include_str!("gnark_groth16/outer.ak.jinja");
const BACKEND_ID: &str = "gnark-groth16-bls12381";
const MODULE_NAME: &str = "groth16";

/// Proof-side parameters forwarded into `groth16.verify` ahead of
/// `inner_vk_hash` and the inputs list (the outer-layer ABI; see [`crate::codegen`]).
const PROOF_PARAMS: &[&str] = &[
    "pi_a",
    "pi_b",
    "pi_c",
    "commitment_uncompressed",
    "commitment_pok",
];

/// The gnark Groth16/BLS12-381 outer backend.
pub struct Groth16Backend;

impl OuterCodegen for Groth16Backend {
    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn module_name(&self) -> &str {
        MODULE_NAME
    }

    fn proof_params(&self) -> &'static [&'static str] {
        PROOF_PARAMS
    }

    fn render(&self, vk_json: &str) -> Result<OuterWiring, CodegenError> {
        let vk = OuterVk::from_json(vk_json).map_err(|e| CodegenError::Artifact(e.to_string()))?;
        if vk.backend != BACKEND_ID {
            return Err(CodegenError::Artifact(format!(
                "backend mismatch: outer_vk.json says {:?}, this backend is {BACKEND_ID:?}",
                vk.backend
            )));
        }
        let ck = vk.commitment_key();
        let mut env = Environment::new();
        // Line-oriented codegen: trim the newline after a block tag and strip
        // leading whitespace before one, so loop bodies keep their own indent.
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_template(MODULE_NAME, OUTER_TEMPLATE)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        let tmpl = env
            .get_template(MODULE_NAME)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        let source = tmpl
            .render(context! {
                max_inputs => vk.max_inputs,
                alpha_g1 => vk.alpha_g1,
                beta_g2 => vk.beta_g2,
                gamma_g2 => vk.gamma_g2,
                delta_g2 => vk.delta_g2,
                ic => vk.ic,
                ck_g => ck.g,
                ck_g_sigma_neg => ck.g_sigma_neg,
            })
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        Ok(OuterWiring {
            source,
            max_inputs: vk.max_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_vk_json() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/groth16-setup/outer_vk.json");
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn renders_baked_vk_constants() {
        let out = Groth16Backend.render(&fixture_vk_json()).unwrap().source;
        // The outer VK points and the commitment key are baked in as consts.
        // We assert the consts are emitted (with a hex payload), not their exact
        // trusted-setup values — those change on every (re)setup, so pinning the
        // hex only makes the test brittle.
        assert!(out.contains("const vk_alpha_g1: ByteArray = #\""));
        assert!(out.contains("const ck_g_sigma_neg: ByteArray = #\""));
    }

    #[test]
    fn renders_full_ic_array_and_unroll() {
        let out = Groth16Backend.render(&fixture_vk_json()).unwrap().source;
        // 11 IC constants for MAX_INPUTS = 8: ic_0 .. ic_10.
        assert!(out.contains("const ic_0: ByteArray"));
        assert!(out.contains("const ic_10: ByteArray"));
        assert!(!out.contains("const ic_11: ByteArray"));
        // compute_vk_x destructures exactly MAX_INPUTS inputs and folds commit_fr at ic_10.
        assert!(out.contains("expect [i0, i1, i2, i3, i4, i5, i6, i7] = inputs"));
        assert!(out.contains("let acc = add_term(acc, i7, ic_9)"));
        assert!(out.contains("let acc = add_term(acc, commit_fr, ic_10)"));
    }

    #[test]
    fn no_unrendered_template_holes() {
        let out = Groth16Backend.render(&fixture_vk_json()).unwrap().source;
        assert!(!out.contains("{{"), "unrendered minijinja hole remains");
        assert!(!out.contains("{%"), "unrendered minijinja tag remains");
    }
}
