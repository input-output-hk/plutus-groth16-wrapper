//! The backend-agnostic outer proof.
//!
//! `outer_proof.json` carries a `backend` discriminator and an
//! otherwise-disjoint proof shape per outer system (Groth16 vs PLONK). This enum
//! is the one type the pipeline names: the [`Prover`](../../zkwrap_prover) trait
//! returns it, and the validator factories dispatch on it. [`OuterProof::from_json`]
//! peeks the `backend` field and parses into the matching variant; each backend
//! owns its concrete artifact type.

use crate::outer_backends::gnark_groth16::artifacts::Groth16OuterProof;
use crate::outer_backends::gnark_plonk::artifacts::PlonkOuterProof;
use crate::outer_backends::gnark_plonk::artifacts::BACKEND_ID as PLONK_BACKEND_ID;
use serde::Deserialize;
use thiserror::Error;

pub use crate::outer_backends::gnark_groth16::artifacts::OuterParseError;

/// A parsed outer proof, tagged by its outer backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OuterProof {
    /// gnark Groth16/BLS12-381 (`gnark-groth16-bls12381`).
    Groth16(Groth16OuterProof),
    /// gnark PLONK/BLS12-381 (`gnark-plonk-bls12381`).
    Plonk(PlonkOuterProof),
}

/// Minimal header read first to route the full parse to the right variant.
#[derive(Deserialize)]
struct BackendHeader {
    backend: String,
}

#[derive(Debug, Error)]
pub enum OuterDispatchError {
    #[error("read backend: {0}")]
    Header(serde_json::Error),
    #[error("unknown outer backend {0:?}")]
    UnknownBackend(String),
    #[error(transparent)]
    Parse(#[from] OuterParseError),
}

const GROTH16_BACKEND_ID: &str = "gnark-groth16-bls12381";

impl OuterProof {
    /// Parse `outer_proof.json`, dispatching on its `backend` field.
    pub fn from_json(s: &str) -> Result<Self, OuterDispatchError> {
        let header: BackendHeader = serde_json::from_str(s).map_err(OuterDispatchError::Header)?;
        match header.backend.as_str() {
            GROTH16_BACKEND_ID => Ok(OuterProof::Groth16(Groth16OuterProof::from_json(s)?)),
            PLONK_BACKEND_ID => Ok(OuterProof::Plonk(PlonkOuterProof::from_json(s)?)),
            other => Err(OuterDispatchError::UnknownBackend(other.to_string())),
        }
    }

    /// The outer-backend id (`backend` field), which keys the outer layer.
    pub fn backend(&self) -> &str {
        match self {
            OuterProof::Groth16(p) => &p.backend,
            OuterProof::Plonk(p) => &p.backend,
        }
    }

    /// In-circuit Poseidon hash of the inner VK (the first public signal),
    /// 32-byte BE Fr hex — the codegen's `inner_vk_hash` constant.
    pub fn inner_vk_hash(&self) -> &str {
        match self {
            OuterProof::Groth16(p) => &p.inner_vk_hash,
            OuterProof::Plonk(p) => &p.inner_vk_hash,
        }
    }

    /// The public-input vector (each a 32-byte BE Fr hex). For Groth16 this is
    /// the `MAX_INPUTS`-padded vector; for PLONK it is the exact `n_real` inputs.
    pub fn inputs(&self) -> &[String] {
        match self {
            OuterProof::Groth16(p) => &p.inputs,
            OuterProof::Plonk(p) => &p.inputs,
        }
    }

    /// Length of the public-input vector (`max_inputs` for Groth16, `num_inputs`
    /// for PLONK).
    pub fn num_inputs(&self) -> usize {
        match self {
            OuterProof::Groth16(p) => p.max_inputs,
            OuterProof::Plonk(p) => p.num_inputs,
        }
    }
}
