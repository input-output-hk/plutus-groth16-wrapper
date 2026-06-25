//! The backend-agnostic outer proof.
//!
//! `outer_proof.json` carries a `backend` discriminator and an
//! otherwise-disjoint proof shape per outer system (Groth16 vs PLONK).

use crate::codegen::OuterCodegen;
use crate::outer_backends::gnark_groth16::artifacts::OuterParseError;

/// A parsed outer proof, abstracted over its outer backend. Everything the
/// off-chain pipeline needs from a proof — its public inputs, the codegen for
/// its backend, and the redeemer field hex — is reachable here without naming
/// the concrete type.
/// The per-backend `impl OuterProof` blocks live with their concrete proof
/// types, in `outer_backends::gnark_groth16::artifacts` / `gnark_plonk::artifacts`.
pub trait OuterProof {
    /// Parse this backend's `outer_proof.json`.
    fn from_json(json: &str) -> Result<Self, OuterParseError>
    where
        Self: Sized;

    /// Outer-backend id (`backend` field), which keys the outer layer.
    fn backend(&self) -> &str;

    /// In-circuit Poseidon hash of the inner VK (the first public signal),
    /// 32-byte BE Fr hex — the codegen's `inner_vk_hash` constant.
    fn inner_vk_hash(&self) -> &str;

    /// The public-input vector (each a 32-byte BE Fr hex). Groth16 pads to
    /// `MAX_INPUTS`; PLONK is the exact `n_real` inputs.
    fn inputs(&self) -> &[String];

    /// Length of the public-input vector (`max_inputs` for Groth16, `num_inputs`
    /// for PLONK — both equal `inputs().len()`).
    fn num_inputs(&self) -> usize {
        self.inputs().len()
    }

    /// The redeemer proof-field values as raw lowercase hex, paired one-to-one
    /// (same length, same order) with this backend's
    /// [`codegen()`](Self::codegen)'s [`OuterCodegen::proof_params`] — the names.
    /// The validator zips the two into the generated `Redeemer` / `verify(…)`
    /// call, wrapping each value as an Aiken `ByteArray` literal, so the ordering
    /// here IS the on-chain ABI contract. Fallible because some backends
    /// (Groth16) require an artifact that may be absent.
    fn proof_param_values(&self) -> Result<Vec<String>, OuterParseError>;

    /// The outer-layer codegen for this proof's backend. Pairing it with
    /// [`Self::proof_param_values`] on the same value keeps the redeemer field
    /// order and the verifier ABI in lockstep.
    fn codegen(&self) -> &'static dyn OuterCodegen;
}


pub fn parse_outer_proof(json: &str) -> Result<Box<dyn OuterProof>, OuterParseError> {
    use crate::outer_backends::{gnark_groth16, gnark_plonk};
    use crate::{Groth16OuterProof, PlonkOuterProof};

    #[derive(serde::Deserialize)]
    struct Tag {
        backend: String,
    }
    let Tag { backend } = serde_json::from_str(json)?;
    match backend.as_str() {
        gnark_groth16::artifacts::BACKEND_ID => Ok(Box::new(Groth16OuterProof::from_json(json)?)),
        gnark_plonk::artifacts::BACKEND_ID => Ok(Box::new(PlonkOuterProof::from_json(json)?)),
        other => Err(OuterParseError::Shape(format!(
            "unknown outer backend {other:?}"
        ))),
    }
}
