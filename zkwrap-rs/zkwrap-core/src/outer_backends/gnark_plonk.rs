//! The gnark PLONK/BLS12-381 outer backend — the outer-layer proving engine.
//!
//! Renders the generic `plonk.ak` verifier with the setup-bound crypto (PLONK
//! VK points + domain sizes) baked into `verify` from a [`PlonkVk`]. The
//! transcript-bound VK points are baked in their uncompressed (transcript-
//! preimage) form; the verifier derives the compressed form on-chain. The proof
//! fields arrive as redeemer parameters; see [`PROOF_PARAMS`].

/// The PLONK outer-proof artifact schema (`outer_vk.json` / `outer_proof.json`).
pub mod artifacts;

use self::artifacts::PlonkVk;
use crate::codegen::{CodegenError, OuterCodegen, OuterWiring};
use minijinja::{context, Environment};

const OUTER_TEMPLATE: &str = include_str!("gnark_plonk/plonk.ak.jinja");
const BACKEND_ID: &str = artifacts::BACKEND_ID;
const MODULE_NAME: &str = "plonk";

/// Proof-side parameters forwarded into `plonk.verify` ahead of `inner_vk_hash`
/// and the inputs list (the outer-layer ABI; see [`crate::codegen`]).
///
/// Transcript-bound points (`lro_*`, `z`, `h_*`, `bsb_0`, `lin_digest`) carry
/// their uncompressed (96-byte gnark RawBytes) form — the exact transcript
/// preimage — and the verifier derives the compressed form on-chain. The
/// EC-only opening proofs (`batched_h`, `zshift_h`) carry the compressed form.
/// `claimed_values` is the 7 gnark-ordered Fr openings concatenated.
const PROOF_PARAMS: &[&str] = &[
    "lro_0",
    "lro_1",
    "lro_2",
    "z",
    "h_0",
    "h_1",
    "h_2",
    "bsb_0",
    "lin_digest",
    "batched_h",
    "zshift_h",
    "claimed_values",
    "zshift_val",
];

/// The gnark PLONK/BLS12-381 outer backend.
pub struct PlonkBackend;

impl OuterCodegen for PlonkBackend {
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
        let vk = PlonkVk::from_json(vk_json).map_err(|e| CodegenError::Artifact(e.to_string()))?;
        // PlonkVk::from_json already enforces the backend id and the
        // single-commitment / three-permutation shape the template relies on.

        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_template(MODULE_NAME, OUTER_TEMPLATE)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        let tmpl = env
            .get_template(MODULE_NAME)
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        let source = tmpl
            .render(context! {
                num_inputs => vk.num_inputs,
                size => vk.size,
                nb_public => vk.nb_public_variables,
                commitment_index => vk.commitment_index(),
                size_inv => vk.size_inv,
                generator => vk.generator,
                coset_shift => vk.coset_shift,
                kzg_g1 => vk.kzg.g1,
                kzg_g2_0 => vk.kzg.g2_0,
                kzg_g2_1 => vk.kzg.g2_1,
                s0_u => vk.s[0],
                s1_u => vk.s[1],
                s2_u => vk.s[2],
                ql_u => vk.ql,
                qr_u => vk.qr,
                qm_u => vk.qm,
                qo_u => vk.qo,
                qk_u => vk.qk,
                qcp0_u => vk.qcp[0],
            })
            .map_err(|e| CodegenError::Render(e.to_string()))?;
        Ok(OuterWiring {
            source,
            // PLONK does not pad: the public-input vector length is exactly
            // num_inputs, so the Composer adds zero trailing zeros.
            max_inputs: vk.num_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_vk_json() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/plonk-setup/outer_vk.json");
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn renders_baked_vk_constants() {
        let out = PlonkBackend.render(&fixture_vk_json()).unwrap().source;
        // Transcript-bound VK points are baked only in uncompressed form
        assert!(out.contains("const ql_u: ByteArray = #\""));
        assert!(out.contains("const qcp0_u: ByteArray = #\""));
        assert!(out.contains("g1_from_u(ql_u)"));
        // Domain sizes baked from the VK, not hardcoded from the tiny spike.
        assert!(out.contains("const vk_size: Int = 4194304"));
        assert!(out.contains("const vk_nb_public: Int = 6"));
    }

    #[test]
    fn reports_exact_num_inputs_no_padding() {
        let wiring = PlonkBackend.render(&fixture_vk_json()).unwrap();
        assert_eq!(wiring.max_inputs, 5);
    }

    #[test]
    fn no_unrendered_template_holes() {
        let out = PlonkBackend.render(&fixture_vk_json()).unwrap().source;
        assert!(!out.contains("{{"), "unrendered minijinja hole remains");
        assert!(!out.contains("{%"), "unrendered minijinja tag remains");
    }
}
