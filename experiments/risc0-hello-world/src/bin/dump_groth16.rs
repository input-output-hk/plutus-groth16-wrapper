use std::fs;
use std::path::Path;

use ark_bn254::{Bn254, Fq12, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::CanonicalDeserialize;
use hello_world_methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_zkvm::{
    default_prover,
    sha::{Digestible, Impl as ShaImpl, Sha256},
    ExecutorEnv, InnerReceipt, ProverOpts,
};
use serde_json::json;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replicates risc0_groth16::verifier::split_digest.
///
/// Input `d` is a RISC Zero Digest (little-endian u32 words, 32 bytes total).
/// Returns two BN254 Fr values as 0x-prefixed 64-char hex strings (big-endian, zero-padded).
///
/// Steps (matching the Rust original exactly):
///   1. Reverse d to big-endian.
///   2. Split at byte 16: b = [0..16], a = [16..32].
///   3. Return (Fr(a), Fr(b)) — first element is the low-half, second is the high-half.
fn split_digest(d: &[u8]) -> (String, String) {
    let big_endian: Vec<u8> = d.iter().rev().cloned().collect();
    let a = &big_endian[16..32]; // low 128-bit half (as big-endian integer)
    let b = &big_endian[0..16]; // high 128-bit half (as big-endian integer)
    (
        format!("0x{:0>64}", to_hex(a)),
        format!("0x{:0>64}", to_hex(b)),
    )
}

// --- snarkjs JSON serialisation helpers ---

fn g1_to_json(p: &G1Affine) -> Vec<String> {
    vec![
        p.x.into_bigint().to_string(),
        p.y.into_bigint().to_string(),
        "1".to_string(),
    ]
}

// G2 snarkjs format: [[X_c0, X_c1], [Y_c0, Y_c1], ["1","0"]]
// where c0 is the "real" part and c1 is the "imaginary" part of each Fq2 coordinate.
fn g2_to_json(p: &G2Affine) -> Vec<Vec<String>> {
    vec![
        vec![
            p.x.c0.into_bigint().to_string(),
            p.x.c1.into_bigint().to_string(),
        ],
        vec![
            p.y.c0.into_bigint().to_string(),
            p.y.c1.into_bigint().to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ]
}

// vk_alphabeta_12 format: [[c0.c0, c0.c1, c0.c2], [c1.c0, c1.c1, c1.c2]]
// where each ci.cj = [Fq_real_dec, Fq_imag_dec].
fn fq12_to_json(f: &Fq12) -> Vec<Vec<Vec<String>>> {
    let fq6_rows = |f6: &ark_bn254::Fq6| -> Vec<Vec<String>> {
        vec![
            vec![
                f6.c0.c0.into_bigint().to_string(),
                f6.c0.c1.into_bigint().to_string(),
            ],
            vec![
                f6.c1.c0.into_bigint().to_string(),
                f6.c1.c1.into_bigint().to_string(),
            ],
            vec![
                f6.c2.c0.into_bigint().to_string(),
                f6.c2.c1.into_bigint().to_string(),
            ],
        ]
    };
    vec![fq6_rows(&f.c0), fq6_rows(&f.c1)]
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Extract PreparedVerifyingKey before proving — it doesn't depend on the proof.
    // VerifyingKey derives serde::Serialize via serde_ark (CanonicalSerialize to bytes);
    // deserialize those bytes as the ark type, then prepare it.
    let pvk: PreparedVerifyingKey<Bn254> = {
        let rk = risc0_groth16::verifying_key();
        let vk_bytes: Vec<u8> =
            serde_json::from_value(serde_json::to_value(&rk).unwrap()).unwrap();
        let ark_vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])
            .expect("ark VerifyingKey deserialization failed");
        ark_groth16::prepare_verifying_key(&ark_vk)
    };

    let (a, b): (u64, u64) = (17, 23);

    let env = ExecutorEnv::builder()
        .write(&a)
        .unwrap()
        .write(&b)
        .unwrap()
        .build()
        .unwrap();

    println!("Proving {a} × {b} with ProverOpts::groth16() ...");
    let receipt = default_prover()
        .prove_with_opts(env, MULTIPLY_ELF, &ProverOpts::groth16())
        .expect("prove_with_opts failed")
        .receipt;

    receipt.verify(MULTIPLY_ID).expect("receipt.verify failed");
    println!("Receipt verified OK");

    let InnerReceipt::Groth16(groth16) = &receipt.inner else {
        panic!(
            "Expected Groth16 inner receipt; got {:?}",
            std::mem::discriminant(&receipt.inner)
        );
    };

    // --- Compute all public-input components ---

    // claim_digest = SHA-256 tagged hash of the ReceiptClaim
    let claim_digest = groth16.claim.digest();
    let claim_digest_bytes = claim_digest.as_bytes();

    let control_root_bytes = ALLOWED_CONTROL_ROOT.as_bytes();
    let bn254_control_id_bytes = BN254_IDENTITY_CONTROL_ID.as_bytes();

    // The 5 BN254 Fr public inputs (see risc0_groth16::verifier::Verifier::new):
    //   [a0, a1] = split_digest(ALLOWED_CONTROL_ROOT)
    //   [c0, c1] = split_digest(claim_digest)
    //   id_fr    = Fr(reverse_bytes(BN254_IDENTITY_CONTROL_ID))
    let (a0, a1) = split_digest(control_root_bytes);
    let (c0, c1) = split_digest(claim_digest_bytes);
    let id_fr = format!(
        "0x{}",
        to_hex(&bn254_control_id_bytes.iter().rev().cloned().collect::<Vec<_>>())
    );

    // --- Write fixtures ---

    let fixtures = Path::new("fixtures");
    fs::create_dir_all(fixtures).expect("failed to create fixtures/");

    // Full receipt (JSON)
    let receipt_json =
        serde_json::to_string_pretty(&receipt).expect("failed to serialize receipt");
    fs::write(fixtures.join("receipt.json"), &receipt_json).unwrap();

    // Raw Groth16 proof bytes
    fs::write(fixtures.join("seal.bin"), &groth16.seal).unwrap();

    // Raw journal bytes (public output of the guest)
    fs::write(fixtures.join("journal.bin"), &receipt.journal.bytes).unwrap();

    // Image ID (8 × u32 little-endian words → 32 bytes)
    let image_id_bytes: Vec<u8> = MULTIPLY_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    fs::write(fixtures.join("image_id.bin"), &image_id_bytes).unwrap();

    // claim_digest, control_root, bn254_control_id as raw bytes
    fs::write(fixtures.join("claim_digest.bin"), claim_digest_bytes).unwrap();
    fs::write(fixtures.join("control_root.bin"), control_root_bytes).unwrap();
    fs::write(fixtures.join("bn254_control_id.bin"), bn254_control_id_bytes).unwrap();

    // 5 public inputs as 0x-prefixed 64-char hex strings (big-endian BN254 Fr)
    let public_inputs = json!({
        "inputs": [a0, a1, c0, c1, id_fr],
        "labels": [
            "a0: split_digest(control_root).0  = Fr(low  16B of big-endian control_root)",
            "a1: split_digest(control_root).1  = Fr(high 16B of big-endian control_root)",
            "c0: split_digest(claim_digest).0  = Fr(low  16B of big-endian claim_digest)",
            "c1: split_digest(claim_digest).1  = Fr(high 16B of big-endian claim_digest)",
            "id: Fr(reverse_bytes(BN254_IDENTITY_CONTROL_ID))"
        ]
    });
    fs::write(
        fixtures.join("public_inputs.json"),
        serde_json::to_string_pretty(&public_inputs).unwrap(),
    )
    .unwrap();

    // VK in snarkjs-compatible JSON format.
    // All coordinate values are extracted from risc0_groth16::verifying_key() at runtime —
    // no hardcoded constants. G2 format: [[X_c0, X_c1], [Y_c0, Y_c1], ["1","0"]].
    // vk_alphabeta_12 = e(alpha_g1, beta_g2) ∈ Fq12, taken from pvk.alpha_g1_beta_g2.
    let vk = json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": pvk.vk.gamma_abc_g1.len() - 1,
        "vk_alpha_1":     g1_to_json(&pvk.vk.alpha_g1),
        "vk_beta_2":      g2_to_json(&pvk.vk.beta_g2),
        "vk_gamma_2":     g2_to_json(&pvk.vk.gamma_g2),
        "vk_delta_2":     g2_to_json(&pvk.vk.delta_g2),
        "vk_alphabeta_12": fq12_to_json(&pvk.alpha_g1_beta_g2),
        "IC": pvk.vk.gamma_abc_g1.iter().map(|p| g1_to_json(p)).collect::<Vec<_>>(),
    });
    fs::write(
        fixtures.join("vk.json"),
        serde_json::to_string_pretty(&vk).unwrap(),
    )
    .unwrap();

    // Human-readable summary
    let c: u64 = receipt.journal.decode().unwrap();
    let _ = ShaImpl::hash_bytes(&[]); // confirm ShaImpl is used (keeps the import live)
    let manifest = json!({
        "risc0_zkvm_version": "3.0.5",
        "risc0_circuit_recursion_version": "4.0.4",
        "proving_mode": "groth16_local",
        "guest": "multiply(17, 23)",
        "journal_decoded_u64": c,
        "journal_hex": to_hex(&receipt.journal.bytes),
        "journal_bytes": receipt.journal.bytes.len(),
        "seal_bytes": groth16.seal.len(),
        "seal_hex_prefix_32b": to_hex(&groth16.seal[..groth16.seal.len().min(32)]),
        "image_id_hex": to_hex(&image_id_bytes),
        "claim_digest_hex": to_hex(claim_digest_bytes),
        "control_root_hex": to_hex(control_root_bytes),
        "bn254_control_id_hex": to_hex(bn254_control_id_bytes),
        "public_inputs_count": 5,
        "public_inputs": [a0, a1, c0, c1, id_fr],
        "verifier_parameters_digest": "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc"
    });
    fs::write(
        fixtures.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Cross-check: read seal.bin + claim_digest.bin + vk.json back from disk and run
    // risc0_groth16::Verifier to confirm all three files are correctly encoded.
    let seal_check = fs::read(fixtures.join("seal.bin")).unwrap();
    let claim_bytes = fs::read(fixtures.join("claim_digest.bin")).unwrap();
    let claim_digest_check = risc0_zkvm::sha::Digest::try_from(claim_bytes.as_slice())
        .expect("claim_digest.bin must be 32 bytes");
    let vk_json_str = fs::read_to_string(fixtures.join("vk.json")).unwrap();
    let vk_parsed: risc0_groth16::VerifyingKeyJson =
        serde_json::from_str(&vk_json_str).expect("failed to parse vk.json");
    let vk_from_file = vk_parsed
        .verifying_key()
        .expect("failed to construct VK from vk.json");
    risc0_groth16::Verifier::new(
        &seal_check,
        ALLOWED_CONTROL_ROOT,
        claim_digest_check,
        BN254_IDENTITY_CONTROL_ID,
        &vk_from_file,
    )
    .expect("Verifier::new failed")
    .verify()
    .expect("FIXTURE CROSS-CHECK FAILED: seal.bin + vk.json + claim_digest.bin are inconsistent");
    println!("Fixture cross-check OK: seal.bin + vk.json + claim_digest.bin verified");

    println!("Artifacts written to fixtures/");
    println!("  receipt.json           {} bytes", receipt_json.len());
    println!("  seal.bin               {} bytes", groth16.seal.len());
    println!(
        "  journal.bin            {} bytes  → decoded u64 = {c}",
        receipt.journal.bytes.len()
    );
    println!("  image_id.bin           32 bytes");
    println!(
        "  claim_digest.bin       32 bytes  → {}",
        to_hex(claim_digest_bytes)
    );
    println!(
        "  control_root.bin       32 bytes  → {}",
        to_hex(control_root_bytes)
    );
    println!(
        "  bn254_control_id.bin   32 bytes  → {}",
        to_hex(bn254_control_id_bytes)
    );
    println!("  public_inputs.json     5 BN254 Fr elements");
    println!("  vk.json                snarkjs-compatible VK (5 public inputs, 6 IC points)");
    println!("  manifest.json          updated");
}
