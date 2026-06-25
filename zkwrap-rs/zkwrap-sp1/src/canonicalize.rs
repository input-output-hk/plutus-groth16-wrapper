//! The serializer half of the SP1 plugin: converts an SP1 (v6.x) Groth16 proof
//! into the canonical inner-proof bundle the outer wrapper prover consumes.
//!
//! [`canonicalize`] takes SP1's native [`SP1Proof`] plus the committed
//! `public_values` and depends only on `sp1-verifier` — for the proof types, the
//! embedded fixed circuit VK, and the gnark→ark decoders. The host already holds
//! both (`&proof.proof`, `proof.public_values.as_slice()`).
//!
//! ```ignore
//! let proof = prover.prove(&pk, stdin).groth16().run()?;
//! zkwrap_sp1::canonicalize(&proof.proof, proof.public_values.as_slice())?
//!     .write_to("out/canonical")?;
//! ```

use std::borrow::Cow;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, VerifyingKey as ArkVk};
use sha2::{Digest, Sha256};
use sp1_verifier::{
    load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes, SP1Proof,
    GROTH16_VK_BYTES,
};
use thiserror::Error;

use zkwrap_core::{
    Bn254Fr, Bn254G1, Bn254G2, Bn254Proof, Bn254Vk, CanonicalBundle, CanonicalInnerProof, Hex32,
};

use crate::codegen::Sp1CodegenData;
use crate::SYSTEM_ID;

/// SP1 v6 Groth16 `encoded_proof` layout (the bytes after the 4-byte vkey-hash
/// prefix in `SP1ProofWithPublicValues::bytes()`):
///   [0..32]   exit_code      (public input 2)
///   [32..64]  vk_root        (public input 3)
///   [64..96]  proof_nonce    (public input 4)
///   [96..352] raw gnark proof (Ar‖Bs‖Krs, 256 B uncompressed)
const ENCODED_PROOF_LEN: usize = 352;
const RAW_PROOF_OFFSET: usize = 96;

#[derive(Debug, Error)]
pub enum CanonicalizeError {
    #[error("proof is not a Groth16 proof")]
    NotGroth16,
    #[error("encoded_proof is {0} bytes, want {ENCODED_PROOF_LEN}")]
    EncodedProofLen(usize),
    #[error("encoded_proof: bad hex: {0}")]
    EncodedProofHex(hex::FromHexError),
    #[error("vkey_hash (public input 0) is not a valid decimal Fr: {0:?}")]
    VkeyHash(String),
    #[error("{0} is not a canonical BN254 Fr element (>= r)")]
    NonCanonical(&'static str),
    #[error("guest exit_code is non-zero (0x{0}); only successful executions (exit_code == 0) are wrapped")]
    NonZeroExitCode(String),
    #[error("malformed inner Groth16 proof")]
    BadProof,
    #[error(
        "inner Groth16 verification failed (tampered public values, or not an SP1 v6.1.0 proof)"
    )]
    Verify,
}

/// Convert an SP1 (v6.x) Groth16 proof into the canonical inner-proof bundle.
///
/// - `proof`: the host's `SP1Proof` (i.e. `&sp1_proof_with_public_values.proof`).
/// - `public_values`: the bytes the guest committed (`public_values.as_slice()`).
///
/// The 5 BN254 Fr public inputs are
/// `[vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce]`:
/// `vkey_hash` is the proof's `public_inputs[0]`; `committed_values_digest =
/// SHA256(public_values)` with the top 3 bits masked (SP1's `hash_public_inputs`,
/// == `digest_be mod 2^253`); and `exit_code`/`vk_root`/`proof_nonce` come from
/// the `encoded_proof` prefix. The inner proof is verified against SP1's fixed
/// v6.1.0 VK and these inputs.
pub fn canonicalize(
    proof: &SP1Proof,
    public_values: &[u8],
) -> Result<CanonicalBundle<Sp1CodegenData>, CanonicalizeError> {
    let SP1Proof::Groth16(groth16) = proof else {
        return Err(CanonicalizeError::NotGroth16);
    };

    // encoded_proof = exit_code ‖ vk_root ‖ proof_nonce ‖ raw gnark proof.
    let encoded =
        hex::decode(&groth16.encoded_proof).map_err(CanonicalizeError::EncodedProofHex)?;
    if encoded.len() != ENCODED_PROOF_LEN {
        return Err(CanonicalizeError::EncodedProofLen(encoded.len()));
    }
    let exit_code: [u8; 32] = encoded[0..32].try_into().unwrap();
    let vk_root: [u8; 32] = encoded[32..64].try_into().unwrap();
    let proof_nonce: [u8; 32] = encoded[64..96].try_into().unwrap();
    let raw: [u8; 256] = encoded[RAW_PROOF_OFFSET..ENCODED_PROOF_LEN]
        .try_into()
        .unwrap();

    // Enforce a successful execution. SP1's own verifier defaults to
    // expected_exit_code == 0; we bake exit_code into the validator as a trusted
    // constant, so a non-zero code (a panicked/reverted guest) must be rejected
    // here — otherwise the generated validator would attest a failed run.
    if exit_code != [0u8; 32] {
        return Err(CanonicalizeError::NonZeroExitCode(hex::encode(exit_code)));
    }

    // vkey_hash (program identity, public input 0) lives only in the decimal
    // public-inputs list, not the encoded_proof prefix.
    let vkey_hash_fr = fr_from_decimal(&groth16.public_inputs[0])
        .ok_or_else(|| CanonicalizeError::VkeyHash(groth16.public_inputs[0].clone()))?;
    let vkey_hash = fr_to_be(&vkey_hash_fr);

    let exit_fr = canonical_fr(&exit_code).ok_or(CanonicalizeError::NonCanonical("exit_code"))?;
    let vkr_fr = canonical_fr(&vk_root).ok_or(CanonicalizeError::NonCanonical("vk_root"))?;
    let nonce_fr =
        canonical_fr(&proof_nonce).ok_or(CanonicalizeError::NonCanonical("proof_nonce"))?;
    let cvd = committed_values_digest(public_values);

    // SP1's fixed v6.1.0 Groth16 VK + the inner proof, both decoded by SP1's own
    // gnark→ark converters.
    let ark_vk = load_ark_groth16_verifying_key_from_bytes(*GROTH16_VK_BYTES)
        .expect("sp1-verifier GROTH16_VK_BYTES is a valid Groth16 VK");
    let ark_proof = load_ark_proof_from_bytes(&raw).map_err(|_| CanonicalizeError::BadProof)?;

    // Binding: the inner proof must verify against the 5 inputs. `cvd` is
    // recomputed (not taken from the proof), so a tampered `public_values` fails.
    let pvk = prepare_verifying_key(&ark_vk);
    let inputs = [vkey_hash_fr, fr_be(&cvd.0), exit_fr, vkr_fr, nonce_fr];
    if !matches!(
        Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs),
        Ok(true)
    ) {
        return Err(CanonicalizeError::Verify);
    }

    let proof = CanonicalInnerProof {
        vk: canonical_vk(&ark_vk),
        proof: Bn254Proof::from_bytes(&raw),
        public_inputs: vec![
            Bn254Fr(vkey_hash),
            cvd,
            Bn254Fr(exit_code),
            Bn254Fr(vk_root),
            Bn254Fr(proof_nonce),
        ],
        system_id: Cow::Borrowed(SYSTEM_ID),
    };

    // The per-program codegen section the Composer bakes as consts. `proof_nonce`
    // is per-proof, so it is NOT here — it rides in the redeemer with `public_values`.
    let codegen = Sp1CodegenData {
        sp1_program_vkey_hash: Hex32(vkey_hash),
        exit_code: Hex32(exit_code),
        vk_root: Hex32(vk_root),
    };

    Ok(CanonicalBundle { proof, codegen })
}

/// SP1's `committed_values_digest`: `SHA256(public_values)` with the top 3 bits
/// of the big-endian digest masked off so it fits in BN254 Fr (== `mod 2^253`).
fn committed_values_digest(public_values: &[u8]) -> Bn254Fr {
    let mut d: [u8; 32] = Sha256::digest(public_values).into();
    d[0] &= 0x1f;
    Bn254Fr(d)
}

/// Parse a decimal string into an `Fr` (the form SP1 uses for `public_inputs`).
fn fr_from_decimal(s: &str) -> Option<Fr> {
    s.parse::<Fr>().ok()
}

/// Parse a 32-byte big-endian value as an `Fr`, requiring it to be canonical
/// (`< r`). Returns `None` if it would need reduction.
fn canonical_fr(be: &[u8; 32]) -> Option<Fr> {
    let fr = Fr::from_be_bytes_mod_order(be);
    (&fr_to_be(&fr) == be).then_some(fr)
}

fn fr_be(be: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(be)
}

/// 32-byte big-endian encoding of an `Fr`, zero-padded on the left.
fn fr_to_be(fr: &Fr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Re-serialize the ark VK into the canonical uncompressed [`Bn254Vk`] layout
/// (`vk.bin` for the gnark prover).
fn canonical_vk(vk: &ArkVk<Bn254>) -> Bn254Vk {
    Bn254Vk {
        alpha_g1: g1_canon(&vk.alpha_g1),
        beta_g2: g2_canon(&vk.beta_g2),
        gamma_g2: g2_canon(&vk.gamma_g2),
        delta_g2: g2_canon(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(g1_canon).collect(),
    }
}

/// 32-byte big-endian encoding of a BN254 `Fq`, zero-padded on the left.
fn fq_be(x: &Fq) -> [u8; 32] {
    let be = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// ark G1 → canonical `x_be ‖ y_be`.
fn g1_canon(p: &G1Affine) -> Bn254G1 {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_be(&p.x));
    out[32..64].copy_from_slice(&fq_be(&p.y));
    Bn254G1(out)
}

/// ark G2 → canonical gnark order `X.A1 ‖ X.A0 ‖ Y.A1 ‖ Y.A0` (imaginary `c1`
/// before real `c0`).
fn g2_canon(p: &G2Affine) -> Bn254G2 {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_be(&p.y.c0));
    Bn254G2(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_verifier::Groth16Bn254Proof;

    fn repo_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(repo_path(rel)).unwrap()
    }

    const RAW: &str = "fixtures/sp1-hello-world";
    const CANON: &str = "fixtures/canonical-inner/sp1-hello-world";

    /// Build an `SP1Proof::Groth16` whose `bytes()`/`encoded_proof` and
    /// `public_inputs[0]` match the committed raw fixtures, the way a host's
    /// proof would. `proof_bytes.bin` = 4-byte prefix + 352-byte encoded_proof.
    fn sp1_proof() -> SP1Proof {
        let proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        let manifest: serde_json::Value =
            serde_json::from_slice(&fixture(&format!("{RAW}/manifest.json"))).unwrap();
        let vkey_hash_dec = manifest["public_inputs"][0].as_str().unwrap().to_string();
        SP1Proof::Groth16(Groth16Bn254Proof {
            public_inputs: [
                vkey_hash_dec,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            encoded_proof: hex::encode(&proof_bytes[4..]),
            raw_proof: String::new(),
            groth16_vkey_hash: proof_bytes[0..32].try_into().unwrap_or([0u8; 32]),
        })
    }

    /// Oracle test: canonicalizing the committed hello-world proof must reproduce
    /// the committed canonical bundle byte-for-byte — and the inner Groth16
    /// verification inside `canonicalize` must pass.
    #[test]
    fn canonicalize_matches_committed_bundle() {
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        let c = canonicalize(&sp1_proof(), &public_values).unwrap();
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
        assert_eq!(c.proof.public_inputs.len(), 5);
        assert_eq!(c.proof.system_id.as_ref(), "sp1-v6");
        assert_eq!(hex::encode(c.codegen.exit_code.0).len(), 64);
        assert_eq!(hex::encode(c.codegen.vk_root.0).len(), 64);
    }

    /// committed_values_digest = SHA256(public_values) mod 2^253 — the top
    /// correctness risk. Compare against the committed public_inputs[1].
    #[test]
    fn committed_values_digest_matches_fixture() {
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        let cvd = committed_values_digest(&public_values);
        let expected = &fixture(&format!("{CANON}/public_inputs.bin"))[32..64];
        assert_eq!(cvd.0.as_slice(), expected);
    }

    /// Tampering the public values breaks the binding (recomputed digest no
    /// longer matches what the proof committed → inner verify fails).
    #[test]
    fn rejects_tampered_public_values() {
        let mut public_values = fixture(&format!("{RAW}/public_values.bin"));
        public_values[0] ^= 0x01;
        assert!(matches!(
            canonicalize(&sp1_proof(), &public_values),
            Err(CanonicalizeError::Verify)
        ));
    }

    /// Tampering the proof_nonce in the encoded_proof breaks the binding (the
    /// inner proof committed to the real nonce as public input 4).
    #[test]
    fn rejects_tampered_proof_nonce() {
        let proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        let SP1Proof::Groth16(mut g) = sp1_proof() else {
            unreachable!()
        };
        let mut encoded = hex::decode(&g.encoded_proof).unwrap();
        encoded[64] ^= 0x01; // first byte of proof_nonce
        g.encoded_proof = hex::encode(&encoded);
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        let _ = proof_bytes;
        assert!(matches!(
            canonicalize(&SP1Proof::Groth16(g), &public_values),
            Err(CanonicalizeError::Verify)
        ));
    }

    /// A non-zero exit_code (panicked/reverted guest) is rejected up front, so
    /// the validator never bakes a failed execution.
    #[test]
    fn rejects_nonzero_exit_code() {
        let SP1Proof::Groth16(mut g) = sp1_proof() else {
            unreachable!()
        };
        let mut encoded = hex::decode(&g.encoded_proof).unwrap();
        encoded[31] = 1; // exit_code = 1 (last byte of the first 32-byte word)
        g.encoded_proof = hex::encode(&encoded);
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        assert!(matches!(
            canonicalize(&SP1Proof::Groth16(g), &public_values),
            Err(CanonicalizeError::NonZeroExitCode(_))
        ));
    }

    #[test]
    fn rejects_non_groth16_shaped_encoded_proof() {
        let SP1Proof::Groth16(mut g) = sp1_proof() else {
            unreachable!()
        };
        g.encoded_proof = hex::encode([0u8; 100]);
        assert!(matches!(
            canonicalize(&SP1Proof::Groth16(g), &[]),
            Err(CanonicalizeError::EncodedProofLen(100))
        ));
    }
}
