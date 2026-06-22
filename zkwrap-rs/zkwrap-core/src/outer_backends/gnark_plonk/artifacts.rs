//! Parsing of the gnark **PLONK**/BLS12-381 outer-backend artifacts produced by
//! `zkwrap-gnark --backend plonk`: `outer_vk.json` (the PLONK verifying key) and
//! `outer_proof.json` (a single PLONK proof). Sibling to the Groth16
//! [`artifacts`](super::super::gnark_groth16::artifacts) parser.
//!
//! Schema: `docs/schemas/plonk-outer-proof-artifacts.md`. Unlike Groth16, the
//! PLONK backend does **no `MAX_INPUTS` padding** — `num_inputs` is the inner
//! system's exact `n_real`. Every G1 point carries both a `c` (48-byte
//! compressed, for on-chain EC ops) and a `u` (96-byte uncompressed gnark
//! `RawBytes`, the exact SHA-256 Fiat-Shamir transcript preimage) form; the
//! transcript-bound VK points carry the uncompressed form in the parallel
//! `*_u` fields.

use serde::Deserialize;

pub use super::super::gnark_groth16::artifacts::OuterParseError;

/// The PLONK outer-backend id, recorded in both artifacts' `backend` field.
pub const BACKEND_ID: &str = "gnark-plonk-bls12381";

/// A G1 point carrying both encodings (`c` compressed, `u` uncompressed).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct G1Obj {
    pub c: String,
    pub u: String,
}

/// KZG SRS commitments inside the PLONK VK.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KzgVk {
    /// `[1]₁` (G1 generator), compressed.
    pub g1: String,
    /// `[1]₂` (G2 generator), compressed.
    pub g2_0: String,
    /// `[s]₂` (secret-scaled G2), compressed.
    pub g2_1: String,
}

/// The outer PLONK/BLS12-381 verifying key (`outer_vk.json`).
///
/// The transcript-bound G1 points (`s`, `ql..qk`, `qcp`) appear in **both**
/// compressed (for EC ops) and uncompressed (for the SHA-256 transcript) form;
/// the codegen bakes both as Aiken module constants.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlonkVk {
    pub backend: String,
    /// Exact inner public-input count (`= n_real`); the wrapper public-input
    /// vector is `[InnerVKHash, input_0, …, input_{num_inputs − 1}]`.
    pub num_inputs: usize,
    /// Padded domain size `n` (power of two); `Zₕ(ζ) = ζⁿ − 1`.
    pub size: u64,
    /// `n⁻¹` in Fr, 32-byte BE hex.
    pub size_inv: String,
    /// Domain generator `ω`, 32-byte BE hex.
    pub generator: String,
    /// `1 + num_inputs` — public-variable count, used to offset the BSB22
    /// commitment's Lagrange point in the public-input fold.
    pub nb_public_variables: u64,
    /// Coset generator (gnark default `7`), 32-byte BE hex.
    pub coset_shift: String,
    pub kzg: KzgVk,
    /// Permutation commitments `[S₁, S₂, S₃]`, compressed.
    pub s: Vec<String>,
    /// Uncompressed `S` forms (transcript preimage).
    pub s_u: Vec<String>,
    pub ql: String,
    pub ql_u: String,
    pub qr: String,
    pub qr_u: String,
    pub qm: String,
    pub qm_u: String,
    pub qo: String,
    pub qo_u: String,
    pub qk: String,
    pub qk_u: String,
    /// Commitment-selector commitments, one per BSB22 commitment, compressed.
    pub qcp: Vec<String>,
    /// Uncompressed `Qcp` forms.
    pub qcp_u: Vec<String>,
    /// Constraint (wire) index of each BSB22 commitment (locates its Lagrange
    /// point in the public-input fold).
    pub commitment_constraint_indexes: Vec<u64>,
}

impl PlonkVk {
    pub fn from_json(s: &str) -> Result<Self, OuterParseError> {
        let vk: PlonkVk = serde_json::from_str(s).map_err(OuterParseError::Json)?;
        vk.validate()?;
        Ok(vk)
    }

    /// Structural checks the `plonk.ak` template relies on. The production
    /// wrapper forces exactly one BSB22 commitment (`api.Commit` over the public
    /// inputs), and the permutation argument has exactly three `S` polynomials.
    fn validate(&self) -> Result<(), OuterParseError> {
        if self.backend != BACKEND_ID {
            return Err(OuterParseError::Shape(format!(
                "backend {:?} != {BACKEND_ID:?}",
                self.backend
            )));
        }
        if self.s.len() != 3 || self.s_u.len() != 3 {
            return Err(OuterParseError::Shape(format!(
                "expected 3 permutation commitments, found s={} s_u={}",
                self.s.len(),
                self.s_u.len()
            )));
        }
        if self.qcp.len() != 1 || self.qcp_u.len() != 1 {
            return Err(OuterParseError::Shape(format!(
                "expected exactly 1 BSB22 commitment selector, found qcp={} qcp_u={}",
                self.qcp.len(),
                self.qcp_u.len()
            )));
        }
        if self.commitment_constraint_indexes.len() != self.qcp.len() {
            return Err(OuterParseError::Shape(format!(
                "commitment_constraint_indexes length {} != qcp length {}",
                self.commitment_constraint_indexes.len(),
                self.qcp.len()
            )));
        }
        Ok(())
    }

    /// The single BSB22 commitment's wire index (validated to exist).
    pub fn commitment_index(&self) -> u64 {
        self.commitment_constraint_indexes[0]
    }
}

/// KZG batch-opening proof at `ζ` plus the claimed openings there.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BatchedProof {
    /// `Wζ` — the folded opening proof (EC-only; only `c` is load-bearing).
    pub h: G1Obj,
    /// Claimed evaluations at `ζ`, gnark order `[lin, l, r, o, s1, s2, qcp…]`.
    pub claimed_values: Vec<String>,
}

/// KZG opening proof of `Z` at the shifted point `ζω`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OpeningProof {
    /// `Wζω` (EC-only; only `c` is load-bearing).
    pub h: G1Obj,
    /// Claimed evaluation `Z(ζω)`, 32-byte BE Fr hex.
    pub claimed_value: String,
}

/// A single PLONK outer proof (`outer_proof.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlonkOuterProof {
    pub backend: String,
    pub num_inputs: usize,
    /// In-circuit Poseidon2 hash of the inner VK, 32-byte BE Fr hex (the first
    /// public signal; baked by codegen as the `inner_vk_hash` constant).
    pub inner_vk_hash: String,
    /// The public-input vector, length exactly `num_inputs` (no padding).
    pub inputs: Vec<String>,
    /// Wire commitments `[L, R, O]`.
    pub lro: Vec<G1Obj>,
    /// Grand-product (permutation) commitment.
    pub z: G1Obj,
    /// Quotient commitments `[H₀, H₁, H₂]`.
    pub h: Vec<G1Obj>,
    /// BSB22 commitments, one per `qcp` entry.
    pub bsb22_commitments: Vec<G1Obj>,
    /// The linearized-polynomial commitment (recomputed on-chain, its supplied
    /// uncompressed bytes bound to the recomputed point then hashed).
    pub lin_digest: G1Obj,
    pub batched_proof: BatchedProof,
    pub z_shifted_opening: OpeningProof,
}

impl PlonkOuterProof {
    pub fn from_json(s: &str) -> Result<Self, OuterParseError> {
        let p: PlonkOuterProof = serde_json::from_str(s).map_err(OuterParseError::Json)?;
        p.validate()?;
        Ok(p)
    }

    fn validate(&self) -> Result<(), OuterParseError> {
        if self.backend != BACKEND_ID {
            return Err(OuterParseError::Shape(format!(
                "backend {:?} != {BACKEND_ID:?}",
                self.backend
            )));
        }
        if self.inputs.len() != self.num_inputs {
            return Err(OuterParseError::Shape(format!(
                "inputs length {} != num_inputs {}",
                self.inputs.len(),
                self.num_inputs
            )));
        }
        if self.lro.len() != 3 {
            return Err(OuterParseError::Shape(format!(
                "lro: expected 3 points, found {}",
                self.lro.len()
            )));
        }
        if self.h.len() != 3 {
            return Err(OuterParseError::Shape(format!(
                "h: expected 3 points, found {}",
                self.h.len()
            )));
        }
        if self.bsb22_commitments.len() != 1 {
            return Err(OuterParseError::Shape(format!(
                "bsb22_commitments: expected 1, found {}",
                self.bsb22_commitments.len()
            )));
        }
        // [lin, l, r, o, s1, s2, qcp] for the single-commitment production shape.
        if self.batched_proof.claimed_values.len() != 7 {
            return Err(OuterParseError::Shape(format!(
                "batched_proof.claimed_values: expected 7, found {}",
                self.batched_proof.claimed_values.len()
            )));
        }
        Ok(())
    }

    /// The proof field values as raw lowercase hex, in
    /// [`PlonkBackend::proof_params`](super::PlonkBackend) order. Transcript-bound
    /// points contribute their uncompressed (`u`) form; the EC-only opening
    /// proofs (`batched_h`, `zshift_h`) their compressed (`c`) form;
    /// `claimed_values` is the seven gnark-ordered Fr openings concatenated. The
    /// validator wraps each as an Aiken `ByteArray` literal.
    pub fn proof_field_hex(&self) -> Vec<String> {
        vec![
            self.lro[0].u.clone(),
            self.lro[1].u.clone(),
            self.lro[2].u.clone(),
            self.z.u.clone(),
            self.h[0].u.clone(),
            self.h[1].u.clone(),
            self.h[2].u.clone(),
            self.bsb22_commitments[0].u.clone(),
            self.lin_digest.u.clone(),
            self.batched_proof.h.c.clone(),
            self.z_shifted_opening.h.c.clone(),
            self.batched_proof.claimed_values.concat(),
            self.z_shifted_opening.claimed_value.clone(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn vk_json() -> String {
        std::fs::read_to_string(repo_path("fixtures/plonk-setup/outer_vk.json")).unwrap()
    }

    fn proof_json() -> String {
        std::fs::read_to_string(repo_path(
            "fixtures/outer-proofs/risc0-plonk-outer-proof.json",
        ))
        .unwrap()
    }

    #[test]
    fn parses_plonk_vk_fixture() {
        let vk = PlonkVk::from_json(&vk_json()).unwrap();
        assert_eq!(vk.backend, BACKEND_ID);
        assert_eq!(vk.num_inputs, 5);
        assert_eq!(vk.nb_public_variables, 6); // 1 + num_inputs
        assert_eq!(vk.s.len(), 3);
        assert_eq!(vk.s_u.len(), 3);
        assert_eq!(vk.qcp.len(), 1);
        // Compressed G1 = 48 bytes = 96 hex; uncompressed = 96 bytes = 192 hex.
        assert_eq!(vk.ql.len(), 96);
        assert_eq!(vk.ql_u.len(), 192);
    }

    #[test]
    fn parses_plonk_proof_fixture() {
        let p = PlonkOuterProof::from_json(&proof_json()).unwrap();
        assert_eq!(p.backend, BACKEND_ID);
        assert_eq!(p.num_inputs, 5);
        assert_eq!(p.inputs.len(), 5);
        assert_eq!(p.lro.len(), 3);
        assert_eq!(p.h.len(), 3);
        assert_eq!(p.bsb22_commitments.len(), 1);
        assert_eq!(p.batched_proof.claimed_values.len(), 7);
        assert_eq!(p.lin_digest.u.len(), 192);
    }

    #[test]
    fn rejects_input_count_mismatch() {
        let mut v: serde_json::Value = serde_json::from_str(&proof_json()).unwrap();
        v["inputs"].as_array_mut().unwrap().pop();
        let err = PlonkOuterProof::from_json(&v.to_string()).unwrap_err();
        assert!(matches!(err, OuterParseError::Shape(_)));
    }
}
