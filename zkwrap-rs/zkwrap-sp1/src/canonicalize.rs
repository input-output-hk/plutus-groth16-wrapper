//! The serializer half of the SP1 plugin: converts SP1 (v6.x) Groth16 artifacts
//! into the canonical inner-proof bundle the outer wrapper prover consumes.
//!
//! The core [`canonicalize`] takes **raw artifact bytes** and depends on no SP1
//! crate, so it builds in the default workspace and the acceptance test runs
//! against committed raw fixtures. Binding is established by an `ark-groth16`
//! verification of the inner proof against the baked fixed VK and the 5 public
//! inputs — a wrong `vkey_hash`, tampered `public_values`, or altered
//! `proof_nonce`/`exit_code`/`vk_root` all make that check fail.
//!
//! With the `sp1-sdk` feature, [`canonicalize_proof`] accepts SP1's native
//! proof/vk types and delegates here, for risc0-style host ergonomics:
//!
//! ```ignore
//! let proof = prover.prove(&pk, stdin).groth16().run()?;
//! zkwrap_sp1::canonicalize_proof(&proof, pk.verifying_key())?.write_to("out/canonical")?;
//! ```

use std::borrow::Cow;
use std::path::Path;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof as ArkProof, VerifyingKey as ArkVk};
use sha2::{Digest, Sha256};
use thiserror::Error;

use zkwrap_core::{Bn254Fr, Bn254G1, Bn254G2, Bn254Proof, Bn254Vk, CanonicalInnerProof};

use crate::SYSTEM_ID;

/// SP1 v6 on-chain proof bytes (`SP1ProofWithPublicValues::bytes()`), Groth16:
///   [0..4]    groth16 vkey-hash prefix
///   [4..36]   exit_code      (public input 2)
///   [36..68]  vk_root        (public input 3)
///   [68..100] proof_nonce    (public input 4)
///   [100..356] raw gnark proof (Ar‖Bs‖Krs, 256 B uncompressed)
const PROOF_BYTES_LEN: usize = 356;
const RAW_PROOF_OFFSET: usize = 100;

/// The fixed SP1 Groth16 verifying key (circuit version v6.1.0), in the
/// canonical uncompressed [`Bn254Vk`] layout. Regenerated from the committed
/// compressed VK by `cargo run --bin gen-canonical-vk --features gen-vk` (which
/// asserts a byte-for-byte match). All SP1 v6.1.0 programs share this VK;
/// program identity lives in `vkey_hash`.
const SP1_GROTH16_VK_V6: &[u8] = include_bytes!("sp1_groth16_vk_v6_1_0.bin");

/// The full canonical inner-proof bundle the plugin emits: the cryptographic
/// proof (consumed by `zkwrap-gnark`) plus the opaque `codegen` section
/// (baked into `meta.json`, consumed at deploy time). Mirrors
/// `zkwrap_risc0::Canonicalized`.
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
    #[error("proof bytes are {0}, want {PROOF_BYTES_LEN}")]
    ProofLen(usize),
    #[error("{0} is not a canonical BN254 Fr element (>= r)")]
    NonCanonical(&'static str),
    #[error("baked SP1 verifying key: {0:?}")]
    BakedVk(zkwrap_core::ParseError),
    #[error("a proof or verifying-key point is not on the curve / in the correct subgroup")]
    BadPoint,
    #[error(
        "inner Groth16 verification failed (wrong vkey_hash / tampered public values / nonce)"
    )]
    Verify,
}

/// Convert SP1 (v6.x) Groth16 artifacts into the canonical inner-proof bundle.
///
/// - `proof_bytes`: SP1's 356-byte on-chain proof (`SP1ProofWithPublicValues::bytes()`).
/// - `public_values`: the bytes the guest committed (`SP1PublicValues`).
/// - `vkey_hash`: the program identity, `vk.bytes32()`, 32-byte big-endian.
///
/// The 5 BN254 Fr public inputs are
/// `[vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce]`,
/// where `committed_values_digest = SHA256(public_values)` with the top 3 bits
/// masked off (SP1's `hash_public_inputs`, == `digest_be mod 2^253`) and
/// `exit_code`/`vk_root`/`proof_nonce` are read from the proof prefix. The inner
/// proof is then verified against the baked VK and these inputs.
pub fn canonicalize(
    proof_bytes: &[u8],
    public_values: &[u8],
    vkey_hash: [u8; 32],
) -> Result<Canonicalized, CanonicalizeError> {
    if proof_bytes.len() != PROOF_BYTES_LEN {
        return Err(CanonicalizeError::ProofLen(proof_bytes.len()));
    }
    let exit_code: [u8; 32] = proof_bytes[4..36].try_into().unwrap();
    let vk_root: [u8; 32] = proof_bytes[36..68].try_into().unwrap();
    let proof_nonce: [u8; 32] = proof_bytes[68..100].try_into().unwrap();
    let raw: [u8; 256] = proof_bytes[RAW_PROOF_OFFSET..PROOF_BYTES_LEN]
        .try_into()
        .unwrap();
    let proof = Bn254Proof::from_bytes(&raw);

    // Validate every 32-byte public input is a canonical Fr (< r). `cvd` is
    // < 2^253 < r by construction, so it needs no check.
    let vkey_hash_fr =
        canonical_fr(&vkey_hash).ok_or(CanonicalizeError::NonCanonical("vkey_hash"))?;
    let exit_fr = canonical_fr(&exit_code).ok_or(CanonicalizeError::NonCanonical("exit_code"))?;
    let vkr_fr = canonical_fr(&vk_root).ok_or(CanonicalizeError::NonCanonical("vk_root"))?;
    let nonce_fr =
        canonical_fr(&proof_nonce).ok_or(CanonicalizeError::NonCanonical("proof_nonce"))?;
    let cvd = committed_values_digest(public_values);

    let public_inputs = vec![
        Bn254Fr(vkey_hash),
        cvd.clone(),
        Bn254Fr(exit_code),
        Bn254Fr(vk_root),
        Bn254Fr(proof_nonce),
    ];

    let vk = Bn254Vk::from_bytes(SP1_GROTH16_VK_V6).map_err(CanonicalizeError::BakedVk)?;

    // Binding: the inner Groth16 proof must verify against the baked VK and the
    // 5 public inputs. ark-crypto matches the gnark verification the wrapper
    // circuit performs (commitment-free Groth16/BN254).
    verify_inner(
        &vk,
        &proof,
        &[vkey_hash_fr, fr_be(&cvd.0), exit_fr, vkr_fr, nonce_fr],
    )?;

    let proof = CanonicalInnerProof {
        vk,
        proof,
        public_inputs,
        system_id: Cow::Borrowed(SYSTEM_ID),
    };

    // The per-program codegen section the deploy-time Composer bakes as consts
    // (see `Sp1Codegen::wiring`). `proof_nonce` is per-proof, so it is NOT here —
    // it rides in the redeemer alongside `public_values`.
    let codegen = serde_json::json!({
        "vkey_hash": hex::encode(vkey_hash),
        "exit_code": hex::encode(exit_code),
        "vk_root": hex::encode(vk_root),
    });

    Ok(Canonicalized { proof, codegen })
}

/// SP1's `committed_values_digest`: `SHA256(public_values)` with the top 3 bits
/// of the big-endian digest masked off so it fits in BN254 Fr (== `mod 2^253`).
fn committed_values_digest(public_values: &[u8]) -> Bn254Fr {
    let mut d: [u8; 32] = Sha256::digest(public_values).into();
    d[0] &= 0x1f;
    Bn254Fr(d)
}

/// Parse a 32-byte big-endian value as an `Fr`, requiring it to be canonical
/// (`< r`). Returns `None` if it would need reduction.
fn canonical_fr(be: &[u8; 32]) -> Option<Fr> {
    let fr = Fr::from_be_bytes_mod_order(be);
    let repr = fr.into_bigint().to_bytes_be(); // 32 bytes for the BN254 scalar field
    let mut round = [0u8; 32];
    round[32 - repr.len()..].copy_from_slice(&repr);
    (&round == be).then_some(fr)
}

fn fr_be(be: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(be)
}

/// Verify the inner Groth16 proof, validating point membership first (ark's
/// `verify_proof` assumes valid points; the proof is attacker-controllable).
fn verify_inner(
    vk: &Bn254Vk,
    proof: &Bn254Proof,
    public_inputs: &[Fr],
) -> Result<(), CanonicalizeError> {
    let ark_vk = ArkVk::<Bn254> {
        alpha_g1: g1(&vk.alpha_g1).ok_or(CanonicalizeError::BadPoint)?,
        beta_g2: g2(&vk.beta_g2).ok_or(CanonicalizeError::BadPoint)?,
        gamma_g2: g2(&vk.gamma_g2).ok_or(CanonicalizeError::BadPoint)?,
        delta_g2: g2(&vk.delta_g2).ok_or(CanonicalizeError::BadPoint)?,
        gamma_abc_g1: vk
            .ic
            .iter()
            .map(g1)
            .collect::<Option<Vec<_>>>()
            .ok_or(CanonicalizeError::BadPoint)?,
    };
    let ark_proof = ArkProof::<Bn254> {
        a: g1(&proof.ar).ok_or(CanonicalizeError::BadPoint)?,
        b: g2(&proof.bs).ok_or(CanonicalizeError::BadPoint)?,
        c: g1(&proof.krs).ok_or(CanonicalizeError::BadPoint)?,
    };
    let pvk = prepare_verifying_key(&ark_vk);
    match Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, public_inputs) {
        Ok(true) => Ok(()),
        _ => Err(CanonicalizeError::Verify),
    }
}

fn fq(be: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(be)
}

/// Canonical G1 (`x_be ‖ y_be`) → validated ark `G1Affine`.
fn g1(p: &Bn254G1) -> Option<G1Affine> {
    let pt = G1Affine::new_unchecked(fq(&p.0[0..32]), fq(&p.0[32..64]));
    valid(pt)
}

/// Canonical G2 (`X.A1 ‖ X.A0 ‖ Y.A1 ‖ Y.A0`, gnark order) → validated ark
/// `G2Affine`. gnark's `A1` is the imaginary part `c1`; ark's `Fq2::new(c0, c1)`.
fn g2(p: &Bn254G2) -> Option<G2Affine> {
    let x = Fq2::new(fq(&p.0[32..64]), fq(&p.0[0..32]));
    let y = Fq2::new(fq(&p.0[96..128]), fq(&p.0[64..96]));
    let pt = G2Affine::new_unchecked(x, y);
    valid(pt)
}

fn valid<P: SWCurveConfig>(pt: Affine<P>) -> Option<Affine<P>> {
    // The point at infinity is rejected here; valid Groth16/VK points are never
    // the identity for these slots.
    (!pt.infinity && pt.is_on_curve() && pt.is_in_correct_subgroup_assuming_on_curve())
        .then_some(pt)
}

/// Ergonomic adapter (feature `sp1-sdk`): accept SP1's native proof + verifying
/// key, extract the on-chain proof bytes, and delegate to [`canonicalize`]. This
/// is the only entry point that depends on `sp1-sdk`.
#[cfg(feature = "sp1-sdk")]
pub fn canonicalize_proof(
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    vk: &sp1_sdk::SP1VerifyingKey,
) -> Result<Canonicalized, Sp1SdkError> {
    use sp1_sdk::{HashableKey, SP1Proof};

    if !matches!(proof.proof, SP1Proof::Groth16(_)) {
        return Err(Sp1SdkError::NotGroth16);
    }
    // `bytes()` = vkey prefix ‖ exit_code ‖ vk_root ‖ proof_nonce ‖ raw proof.
    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();

    // `vk.bytes32()` → `0x`-prefixed 32-byte hex of the program vkey hash.
    let vkey_hex = vk.bytes32();
    let vkey_bytes = hex::decode(vkey_hex.trim_start_matches("0x"))
        .map_err(|e| Sp1SdkError::VkeyHash(e.to_string()))?;
    let vkey_hash: [u8; 32] = vkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Sp1SdkError::VkeyHash("not 32 bytes".to_string()))?;

    Ok(canonicalize(&proof_bytes, public_values, vkey_hash)?)
}

#[cfg(feature = "sp1-sdk")]
#[derive(Debug, Error)]
pub enum Sp1SdkError {
    #[error("proof is not a Groth16 proof")]
    NotGroth16,
    #[error("vkey_hash: {0}")]
    VkeyHash(String),
    #[error(transparent)]
    Canonicalize(#[from] CanonicalizeError),
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

    const RAW: &str = "fixtures/sp1-hello-world";
    const CANON: &str = "fixtures/canonical-inner/sp1-hello-world";

    fn vkey_hash() -> [u8; 32] {
        fixture(&format!("{RAW}/vkey_hash.bin"))
            .as_slice()
            .try_into()
            .unwrap()
    }

    fn run() -> Canonicalized {
        let proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        canonicalize(&proof_bytes, &public_values, vkey_hash()).unwrap()
    }

    /// Oracle test: canonicalizing the committed hello-world artifacts must
    /// reproduce the committed canonical bundle byte-for-byte (vk/proof/inputs)
    /// — and the inner Groth16 verification inside `canonicalize` must pass.
    #[test]
    fn canonicalize_matches_committed_bundle() {
        let c = run();
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
        assert_eq!(
            c.codegen["vkey_hash"].as_str().unwrap(),
            hex::encode(vkey_hash())
        );
        // exit_code / vk_root are baked from the proof prefix.
        assert_eq!(c.codegen["exit_code"].as_str().unwrap().len(), 64);
        assert_eq!(c.codegen["vk_root"].as_str().unwrap().len(), 64);
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
        let proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        let mut public_values = fixture(&format!("{RAW}/public_values.bin"));
        public_values[0] ^= 0x01;
        assert!(matches!(
            canonicalize(&proof_bytes, &public_values, vkey_hash()),
            Err(CanonicalizeError::Verify)
        ));
    }

    /// A wrong vkey_hash breaks the binding.
    #[test]
    fn rejects_wrong_vkey_hash() {
        let proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        let mut vh = vkey_hash();
        vh[31] ^= 0x01;
        assert!(matches!(
            canonicalize(&proof_bytes, &public_values, vh),
            Err(CanonicalizeError::Verify)
        ));
    }

    /// Tampering the proof_nonce in the prefix breaks the binding (the inner
    /// proof committed to the real nonce as public input 4).
    #[test]
    fn rejects_tampered_proof_nonce() {
        let mut proof_bytes = fixture(&format!("{RAW}/proof_bytes.bin"));
        proof_bytes[68] ^= 0x01; // first byte of proof_nonce
        let public_values = fixture(&format!("{RAW}/public_values.bin"));
        assert!(matches!(
            canonicalize(&proof_bytes, &public_values, vkey_hash()),
            Err(CanonicalizeError::Verify)
        ));
    }

    #[test]
    fn rejects_wrong_proof_len() {
        assert!(matches!(
            canonicalize(&[0u8; 256], &[], [0u8; 32]),
            Err(CanonicalizeError::ProofLen(256))
        ));
    }
}
