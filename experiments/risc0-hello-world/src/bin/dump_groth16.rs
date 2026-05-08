use std::fs;
use std::path::Path;

use hello_world_methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts};
use serde_json::json;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

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

    let fixtures = Path::new("fixtures");
    fs::create_dir_all(fixtures).expect("failed to create fixtures/");

    // Full receipt serialized to JSON for later inspection
    let receipt_json =
        serde_json::to_string_pretty(&receipt).expect("failed to serialize receipt");
    fs::write(fixtures.join("receipt.json"), &receipt_json).unwrap();

    // Raw Groth16 proof bytes (the "seal")
    fs::write(fixtures.join("seal.bin"), &groth16.seal).unwrap();

    // Raw journal bytes (public output of the guest)
    fs::write(fixtures.join("journal.bin"), &receipt.journal.bytes).unwrap();

    // Image ID: 8 × u32 words → 32 bytes, each word in little-endian
    let image_id_bytes: Vec<u8> = MULTIPLY_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    fs::write(fixtures.join("image_id.bin"), &image_id_bytes).unwrap();

    // Human-readable summary of all key values
    let c: u64 = receipt.journal.decode().unwrap();
    let manifest = json!({
        "risc0_zkvm_version": "3.0.5",
        "proving_mode": "groth16_local",
        "guest": "multiply(17, 23)",
        "journal_decoded_u64": c,
        "journal_hex": to_hex(&receipt.journal.bytes),
        "journal_bytes": receipt.journal.bytes.len(),
        "seal_bytes": groth16.seal.len(),
        "seal_hex_prefix_32b": to_hex(&groth16.seal[..groth16.seal.len().min(32)]),
        "image_id_hex": to_hex(&image_id_bytes),
        "image_id_words_decimal": MULTIPLY_ID,
    });
    fs::write(
        fixtures.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    println!("Artifacts written to fixtures/");
    println!("  receipt.json  {} bytes", receipt_json.len());
    println!("  seal.bin      {} bytes", groth16.seal.len());
    println!(
        "  journal.bin   {} bytes  → decoded u64 = {c}",
        receipt.journal.bytes.len()
    );
    println!("  image_id.bin  {} bytes", image_id_bytes.len());
    println!("  manifest.json written");
}
