//! Parsing of the outer-backend artifacts produced by `zkwrap-gnark`:
//! `outer_vk.json` (trusted-setup verifying key) and `outer_proof.json`
//! (a single proof). These cross the language boundary as **data**, not as
//! generated Aiken — codegen stays uniformly in Rust regardless of which
//! prover produced them (ADR-0007).
//!
//! Schema: `docs/schemas/outer-proof-artifacts.md`. All point fields are
//! lowercase hex (no `0x`), compressed BLS12-381 (48-byte G1, 96-byte G2),
//! matching what Cardano's `bls12_381_*_uncompress` builtins expect.

use serde::Deserialize;

/// A Pedersen (Bowe–Gabizon) commitment verifying key: two compressed G2 points.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CommitmentKey {
    /// `[g]_2`, compressed G2 hex.
    pub g: String,
    /// `[g^{-σ}]_2`, compressed G2 hex.
    pub g_sigma_neg: String,
}

/// The outer Groth16/BLS12-381 verifying key (`outer_vk.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OuterVk {
    /// Outer-backend identifier, e.g. `"gnark-groth16-bls12381"`. Keys the outer layer.
    pub backend: String,
    /// `MAX_INPUTS` baked into the wrapper circuit at trusted-setup time.
    pub max_inputs: usize,
    pub alpha_g1: String,
    pub beta_g2: String,
    pub gamma_g2: String,
    pub delta_g2: String,
    /// IC array. Length `max_inputs + 2 + commitment_keys.len()`:
    /// `ic[0]` constant term, `ic[1]` the `InnerVKHash` coefficient,
    /// `ic[2..max_inputs+2]` the per-input coefficients, trailing slot(s) the
    /// Pedersen-commitment-folded public input(s).
    pub ic: Vec<String>,
    pub commitment_keys: Vec<CommitmentKey>,
    #[serde(default)]
    pub public_and_commitment_committed: Vec<Vec<i64>>,
}

impl OuterVk {
    pub fn from_json(s: &str) -> Result<Self, OuterParseError> {
        let vk: OuterVk = serde_json::from_str(s).map_err(OuterParseError::Json)?;
        vk.validate()?;
        Ok(vk)
    }

    /// Structural checks the templates rely on. This spike pins the
    /// single-commitment, empty-committed-wires shape (ADR-0006).
    fn validate(&self) -> Result<(), OuterParseError> {
        if self.commitment_keys.len() != 1 {
            return Err(OuterParseError::Shape(format!(
                "expected exactly 1 commitment key, found {}",
                self.commitment_keys.len()
            )));
        }
        let expected_ic = self.max_inputs + 2 + self.commitment_keys.len();
        if self.ic.len() != expected_ic {
            return Err(OuterParseError::Shape(format!(
                "ic length {} != max_inputs+2+commitment_keys ({})",
                self.ic.len(),
                expected_ic
            )));
        }
        Ok(())
    }

    /// The single Pedersen commitment key (validated to exist).
    pub fn commitment_key(&self) -> &CommitmentKey {
        &self.commitment_keys[0]
    }
}

/// The Groth16 proof points and Pedersen artifacts within `outer_proof.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OuterProofPoints {
    pub ar: String,
    pub bs: String,
    pub krs: String,
    /// Uncompressed (96-byte, gnark RawBytes `x_be ‖ y_be`) Pedersen
    /// commitments — the exact preimage gnark hashes for `commit_fr` and the
    /// redeemer-side artifact the Aiken verifier consumes. (The compressed
    /// `commitments` form gnark also emits is not parsed here: codegen only
    /// needs the uncompressed bytes; the verifier derives the compressed form
    /// on-chain.)
    #[serde(default)]
    pub commitments_uncompressed: Vec<String>,
    pub commitment_pok: String,
}

/// A single outer proof (`outer_proof.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OuterProof {
    pub backend: String,
    pub max_inputs: usize,
    pub proof: OuterProofPoints,
    /// In-circuit Poseidon hash of the inner VK, 32-byte BE Fr hex.
    pub inner_vk_hash: String,
    /// The `MAX_INPUTS`-length public-input vector, each a 32-byte BE Fr hex.
    pub inputs: Vec<String>,
}

impl OuterProof {
    pub fn from_json(s: &str) -> Result<Self, OuterParseError> {
        let p: OuterProof = serde_json::from_str(s).map_err(OuterParseError::Json)?;
        if p.inputs.len() != p.max_inputs {
            return Err(OuterParseError::Shape(format!(
                "inputs length {} != max_inputs {}",
                p.inputs.len(),
                p.max_inputs
            )));
        }
        Ok(p)
    }

    /// The single uncompressed (96-byte) Pedersen commitment — the redeemer
    /// artifact the verifier hashes and decompresses. Carried in the proof
    /// because it is expensive to derive it in Plutus on-chain.
    pub fn commitment_uncompressed(&self) -> Result<&str, OuterParseError> {
        self.proof
            .commitments_uncompressed
            .first()
            .map(String::as_str)
            .ok_or_else(|| OuterParseError::Shape("proof has no commitments_uncompressed".into()))
    }
}

#[derive(Debug)]
pub enum OuterParseError {
    Json(serde_json::Error),
    Shape(String),
}

impl std::fmt::Display for OuterParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OuterParseError::Json(e) => write!(f, "json: {e}"),
            OuterParseError::Shape(s) => write!(f, "shape: {s}"),
        }
    }
}

impl std::error::Error for OuterParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate a repo-relative path from this crate's manifest dir
    /// (`zkwrap-rs/zkwrap-core` → repo root is two levels up).
    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn vk_json() -> String {
        std::fs::read_to_string(repo_path(
            "zkwrap-gnark/testdata/groth16-setup/outer_vk.json",
        ))
        .unwrap()
    }

    fn proof_json() -> String {
        std::fs::read_to_string(repo_path("zkwrap-gnark/testdata/groth16-outer-proof.json"))
            .unwrap()
    }

    #[test]
    fn parses_outer_vk_fixture() {
        let vk = OuterVk::from_json(&vk_json()).unwrap();
        assert_eq!(vk.backend, "gnark-groth16-bls12381");
        assert_eq!(vk.max_inputs, 8);
        // const + vkhash + 8 inputs + 1 commit_fr = 11
        assert_eq!(vk.ic.len(), 11);
        assert_eq!(vk.commitment_keys.len(), 1);
        // alpha matches the spike's baked constant.
        assert_eq!(
            vk.alpha_g1,
            "b0a27b5ce1e9e0fb9b1e0930686f8f3b8198c17927f23ea4925baf618661e699ace14793be2cc7b8df30b3478351bec6"
        );
    }

    #[test]
    fn parses_outer_proof_fixture() {
        let p = OuterProof::from_json(&proof_json()).unwrap();
        assert_eq!(p.backend, "gnark-groth16-bls12381");
        assert_eq!(p.max_inputs, 8);
        assert_eq!(p.inputs.len(), 8);
        assert_eq!(
            p.inner_vk_hash,
            "0c42ca6b6e6c574b5b21c90360bed01945966b844fb47b5430d0d801bbe8e6ca"
        );
        // Uncompressed (96-byte) form: same x with the raw-finite marker, plus y.
        let cu = p.commitment_uncompressed().unwrap();
        assert_eq!(cu.len(), 192);
        assert!(cu.starts_with("082fa3134bc25666"));
        // Last three input slots are the MAX_INPUTS padding zeros.
        for slot in &p.inputs[5..8] {
            assert_eq!(
                slot,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
        }
    }

    #[test]
    fn rejects_ic_length_mismatch() {
        let mut v: serde_json::Value = serde_json::from_str(&vk_json()).unwrap();
        v["ic"].as_array_mut().unwrap().pop();
        let err = OuterVk::from_json(&v.to_string()).unwrap_err();
        assert!(matches!(err, OuterParseError::Shape(_)));
    }
}
