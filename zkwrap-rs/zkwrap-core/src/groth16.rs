//! The gnark Groth16/BLS12-381 outer backend — the Layer 1 proving engine.
//!
//! Renders the generic `groth16.ak` verifier with the setup-bound crypto
//! (outer VK points, IC array, Pedersen commitment keys) baked into `verify`
//! from an [`OuterVk`]. This is the Layer 1 half of ADR-0007; it lives in
//! `zkwrap-core` for now and moves to a dedicated `zkwrap-groth16` crate when a
//! second backend (PLONK) lands.

use crate::codegen::{CodegenError, OuterBackend};
use crate::outer::OuterVk;
use minijinja::{context, Environment};

const LAYER1_TEMPLATE: &str = include_str!("groth16.ak.jinja");
const BACKEND_ID: &str = "gnark-groth16-bls12381";
const MODULE_NAME: &str = "groth16";

/// Proof-side parameters forwarded into `groth16.verify` ahead of
/// `inner_vk_hash` and the inputs list (the Layer 1 ABI; see [`crate::codegen`]).
const PROOF_PARAMS: &[&str] = &["pi_a", "pi_b", "pi_c", "commitment_uncompressed", "commitment_pok"];

/// The gnark Groth16/BLS12-381 outer backend.
pub struct Groth16Backend;

impl OuterBackend for Groth16Backend {
    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn module_name(&self) -> &str {
        MODULE_NAME
    }

    fn proof_params(&self) -> &'static [&'static str] {
        PROOF_PARAMS
    }

    fn render_layer1(&self, vk: &OuterVk) -> Result<String, CodegenError> {
        if vk.backend != BACKEND_ID {
            return Err(CodegenError::Render(format!(
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
        env.add_template(MODULE_NAME, LAYER1_TEMPLATE)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        let tmpl = env
            .get_template(MODULE_NAME)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        tmpl.render(context! {
            max_inputs => vk.max_inputs,
            alpha_g1 => vk.alpha_g1,
            beta_g2 => vk.beta_g2,
            gamma_g2 => vk.gamma_g2,
            delta_g2 => vk.delta_g2,
            ic => vk.ic,
            ck_g => ck.g,
            ck_g_sigma_neg => ck.g_sigma_neg,
        })
        .map_err(|e| CodegenError::Render(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_vk() -> OuterVk {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("zkwrap-gnark/testdata/groth16-setup/outer_vk.json");
        OuterVk::from_json(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn renders_baked_vk_constants() {
        let out = Groth16Backend.render_layer1(&fixture_vk()).unwrap();
        // Outer VK points baked in.
        assert!(out.contains(
            "const vk_alpha_g1: ByteArray = #\"b0a27b5ce1e9e0fb9b1e0930686f8f3b8198c17927f23ea4925baf618661e699ace14793be2cc7b8df30b3478351bec6\""
        ));
        // Commitment key baked in.
        assert!(out.contains("const ck_g_sigma_neg: ByteArray = #\"a293e6ccd6fad9dd"));
    }

    #[test]
    fn renders_full_ic_array_and_unroll() {
        let out = Groth16Backend.render_layer1(&fixture_vk()).unwrap();
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
        let out = Groth16Backend.render_layer1(&fixture_vk()).unwrap();
        assert!(!out.contains("{{"), "unrendered minijinja hole remains");
        assert!(!out.contains("{%"), "unrendered minijinja tag remains");
    }
}
