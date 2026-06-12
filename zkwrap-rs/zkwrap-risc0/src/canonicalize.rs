//! The serializer half of the RISC Zero plugin: converts a native
//! RISC Zero Groth16 [`Receipt`] into the canonical inner-proof bundle that the
//! outer wrapper prover consumes.
//!
//! A host program (which already runs the risc0 prover and holds the `Receipt`) calls
//! [`canonicalize`] and writes the result:
//!
//! ```ignore
//! let receipt = prover.prove_with_opts(env, ELF, &ProverOpts::groth16())?.receipt;
//! zkwrap_risc0::canonicalize(&receipt, IMAGE_ID)?.write_to("out/canonical")?;
//! ```

use std::borrow::Cow;
use std::path::Path;

use thiserror::Error;

use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{InnerReceipt, Receipt};
use zkwrap_core::{Bn254Fr, Bn254G1, Bn254G2, Bn254Proof, Bn254Vk, CanonicalInnerProof};

use crate::SYSTEM_ID;

/// The full canonical inner-proof bundle the plugin emits: the cryptographic
/// proof (the `plugin → prover` contract, consumed by `zkwrap-gnark`) plus the
/// opaque `codegen` section (the `plugin → Composer` contract, baked into
/// `meta.json` and consumed at deploy time; ignored by the prover).
///
/// The two are kept separate on purpose: `CanonicalInnerProof` stays the pure,
/// system-agnostic crypto contract, and the system-specific `codegen` data rides
/// alongside it here. See `zkwrap-core::inner` and ADR-0007.
pub struct Canonicalized {
    pub proof: CanonicalInnerProof,
    pub codegen: serde_json::Value,
}

impl Canonicalized {
    /// Persist the whole bundle to `dir`: `vk.bin`, `proof.bin`,
    /// `public_inputs.bin`, and `meta.json` (with the `codegen` section).
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        self.proof.write_to(dir, Some(&self.codegen))
    }
}

#[derive(Debug, Error)]
pub enum CanonicalizeError {
    #[error("receipt verify: {0}")]
    Verify(String),
    #[error("receipt is not Groth16-compressed")]
    NotGroth16,
    #[error("claim: {0}")]
    Claim(String),
    #[error("groth16 verifying key: {0}")]
    VerifyingKey(String),
    #[error("seal is {0} bytes, want 256")]
    Seal(usize),
}

/// Verify a RISC Zero Groth16 `receipt` against `image_id` and convert it into
/// the canonical inner-proof bundle (I/O-free; call [`Canonicalized::write_to`]
/// to persist). `receipt.verify` binds the proof to `image_id`, so a wrong
/// `image_id` (or an invalid receipt) is rejected before anything is extracted.
pub fn canonicalize(
    receipt: &Receipt,
    image_id: impl Into<Digest>,
) -> Result<Canonicalized, CanonicalizeError> {
    let image_id: Digest = image_id.into();
    receipt
        .verify(image_id)
        .map_err(|e| CanonicalizeError::Verify(e.to_string()))?;

    let InnerReceipt::Groth16(groth16) = &receipt.inner else {
        return Err(CanonicalizeError::NotGroth16);
    };

    // proof.bin = the 256-byte seal (already gnark Ar‖Bs‖Krs order).
    let seal: [u8; 256] = groth16
        .seal
        .as_slice()
        .try_into()
        .map_err(|_| CanonicalizeError::Seal(groth16.seal.len()))?;
    let proof = Bn254Proof::from_bytes(&seal);

    // Public-input components. claim_digest binds image_id + journal + post-state
    // + exit code; post-state comes from the claim itself.
    let claim_digest = digest32(&groth16.claim.digest());
    let claim = groth16
        .claim
        .as_value()
        .map_err(|e| CanonicalizeError::Claim(e.to_string()))?;
    let post_state = digest32(&claim.post.digest());
    let control_root = digest32(&ALLOWED_CONTROL_ROOT);
    let bn254_control_id = digest32(&BN254_IDENTITY_CONTROL_ID);

    // The 5 BN254 Fr public inputs (see risc0_groth16::verifier::Verifier::new):
    //   [0,1] = split_digest(control_root), [2,3] = split_digest(claim_digest),
    //   [4]   = Fr(reverse_bytes(bn254_control_id)).
    let (cr0, cr1) = split_digest(&control_root);
    let (cd0, cd1) = split_digest(&claim_digest);
    let id_fr = fr_from_reversed(&bn254_control_id);
    let public_inputs = vec![cr0, cr1, cd0, cd1, id_fr];

    let proof = CanonicalInnerProof {
        vk: risc0_verifying_key()?,
        proof,
        public_inputs,
        system_id: Cow::Borrowed(SYSTEM_ID),
    };

    // The per-guest codegen section the deploy-time Composer consumes
    // (see `Risc0Codegen::wiring`). Opaque to the prover.
    let codegen = serde_json::json!({
        "image_id": hex::encode(image_id.as_bytes()),
        "post_state_digest": hex::encode(post_state),
        "control_root": hex::encode(control_root),
        "bn254_control_id": hex::encode(bn254_control_id),
    });

    Ok(Canonicalized { proof, codegen })
}

/// The fixed RISC Zero Groth16 verifying key, serialized into the canonical
/// `Bn254Vk` layout. `risc0_groth16::verifying_key()` serializes (via serde-ark)
/// to the ark `CanonicalSerialize` byte form; we round-trip through ark to read
/// the points, then re-emit them in the canonical `x‖y` / `X.A1‖X.A0‖Y.A1‖Y.A0`
/// big-endian order `Bn254Vk` expects.
fn risc0_verifying_key() -> Result<Bn254Vk, CanonicalizeError> {
    let rk = risc0_groth16::verifying_key();
    let vk_bytes: Vec<u8> = serde_json::from_value(
        serde_json::to_value(&rk).map_err(|e| CanonicalizeError::VerifyingKey(e.to_string()))?,
    )
    .map_err(|e| CanonicalizeError::VerifyingKey(e.to_string()))?;
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])
        .map_err(|e| CanonicalizeError::VerifyingKey(e.to_string()))?;
    Ok(Bn254Vk {
        alpha_g1: g1_bytes(&vk.alpha_g1),
        beta_g2: g2_bytes(&vk.beta_g2),
        gamma_g2: g2_bytes(&vk.gamma_g2),
        delta_g2: g2_bytes(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(g1_bytes).collect(),
    })
}

/// 32-byte big-endian encoding of a BN254 `Fq`, zero-padded on the left.
fn fq_be(x: &Fq) -> [u8; 32] {
    let be = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// G1 affine → `x_be ‖ y_be`.
fn g1_bytes(p: &G1Affine) -> Bn254G1 {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_be(&p.x));
    out[32..64].copy_from_slice(&fq_be(&p.y));
    Bn254G1(out)
}

/// G2 affine → gnark `WriteRawTo` order `X.A1 ‖ X.A0 ‖ Y.A1 ‖ Y.A0` (imaginary
/// part `c1` before real part `c0`).
fn g2_bytes(p: &G2Affine) -> Bn254G2 {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_be(&p.y.c0));
    Bn254G2(out)
}

/// `risc0_groth16::verifier::split_digest`: reverse `d` to big-endian, split at
/// byte 16, and return the low half then the high half, each as a BN254 `Fr`
/// (the 16-byte half placed in the low bytes of a 32-byte big-endian element).
fn split_digest(d: &[u8; 32]) -> (Bn254Fr, Bn254Fr) {
    let mut be = *d;
    be.reverse();
    (fr_from_low16(&be[16..32]), fr_from_low16(&be[0..16]))
}

fn fr_from_low16(half: &[u8]) -> Bn254Fr {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(half);
    Bn254Fr(out)
}

/// `Fr(reverse_bytes(d))` — the full 32-byte value read in the opposite byte order.
fn fr_from_reversed(d: &[u8; 32]) -> Bn254Fr {
    let mut be = *d;
    be.reverse();
    Bn254Fr(be)
}

fn digest32(d: &Digest) -> [u8; 32] {
    d.as_bytes().try_into().expect("sha-256 digest is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(repo_path(rel)).unwrap()
    }

    const FIX: &str = "fixtures/risc0-hello-world";
    const CANON: &str = "fixtures/canonical-inner/risc0-hello-world";

    /// Oracle test: canonicalizing the committed hello-world receipt must
    /// reproduce the committed canonical bundle byte-for-byte (vk/proof/inputs),
    /// and emit a codegen section matching the committed RISC Zero constants.
    #[test]
    fn canonicalize_matches_committed_bundle() {
        let receipt: Receipt = serde_json::from_str(
            &std::fs::read_to_string(repo_path(&format!("{FIX}/receipt.json"))).unwrap(),
        )
        .unwrap();
        let image_id =
            Digest::try_from(fixture(&format!("{FIX}/image_id.bin")).as_slice()).unwrap();

        let c = canonicalize(&receipt, image_id).unwrap();

        assert_eq!(
            c.proof.vk_bytes(),
            fixture(&format!("{CANON}/vk.bin")),
            "vk.bin"
        );
        assert_eq!(
            c.proof.proof_bytes().to_vec(),
            fixture(&format!("{CANON}/proof.bin")),
            "proof.bin"
        );
        assert_eq!(
            c.proof.public_inputs_bytes(),
            fixture(&format!("{CANON}/public_inputs.bin")),
            "public_inputs.bin"
        );

        let hexf = |rel: &str| hex::encode(fixture(rel));
        assert_eq!(
            c.codegen["control_root"].as_str().unwrap(),
            hexf(&format!("{FIX}/control_root.bin"))
        );
        assert_eq!(
            c.codegen["bn254_control_id"].as_str().unwrap(),
            hexf(&format!("{FIX}/bn254_control_id.bin"))
        );
        assert_eq!(
            c.codegen["image_id"].as_str().unwrap(),
            hexf(&format!("{FIX}/image_id.bin"))
        );
        assert_eq!(c.codegen["post_state_digest"].as_str().unwrap().len(), 64);
    }
}
