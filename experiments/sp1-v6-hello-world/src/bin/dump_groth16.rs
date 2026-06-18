//! Generates a real SP1 (v6.x) Groth16/BN254 proof and dumps its artifacts, so
//! we can document the current artifact format and feed the zkwrap-sp1 rework.
//!
//! Mirrors the v3.0.0 `experiments/sp1-hello-world` dump, updated to the
//! sp1-sdk 6.2.4 blocking CPU API. Guest: `multiply(17, 23)` → commits `391`.
//!
//! The on-chain proof bytes (`proof.bytes()`) decompose as:
//!   [0..4]    groth16 vkey-hash prefix
//!   [4..36]   exit_code        (public input 2)
//!   [36..68]  vk_root          (public input 3)
//!   [68..100] proof_nonce      (public input 4)
//!   [100..356] raw gnark proof (a‖b‖c, 256 B uncompressed)
//! and the 5 public inputs are [vkey_hash, committed_values_digest, exit_code,
//! vk_root, proof_nonce].

use std::fs;
use std::path::Path;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, HashableKey, ProvingKey, SP1Proof, SP1Stdin, SP1_CIRCUIT_VERSION};

const ELF: sp1_sdk::Elf = include_elf!("multiply-v6");

fn main() {
    let (a, b): (u64, u64) = (17, 23);

    let prover = ProverClient::builder().cpu().build();
    let pk = prover.setup(ELF).expect("setup");
    let vk = pk.verifying_key();
    let sp1_vkey_hash = vk.bytes32(); // 0x-prefixed 32-byte hex
    println!("SP1 circuit version: {SP1_CIRCUIT_VERSION}");
    println!("SP1 vkey hash:       {sp1_vkey_hash}");

    let mut stdin = SP1Stdin::new();
    stdin.write(&a);
    stdin.write(&b);

    println!("Proving {a} x {b} with Groth16 (local CPU, native-gnark) ...");
    let proof = prover.prove(&pk, stdin).groth16().run().expect("groth16 prove");

    let SP1Proof::Groth16(groth16) = &proof.proof else {
        panic!("expected a Groth16 proof");
    };
    let public_inputs: [String; 5] = groth16.public_inputs.clone();
    let raw_proof_hex = groth16.raw_proof.clone();
    let groth16_vkey_hash_hex = hex::encode(groth16.groth16_vkey_hash);

    // The on-chain proof bytes and their decomposition.
    let bytes = proof.bytes();
    assert!(bytes.len() >= 100 + 256, "unexpected proof.bytes() len {}", bytes.len());
    let vk_prefix = &bytes[0..4];
    let exit_code = &bytes[4..36];
    let vk_root = &bytes[36..68];
    let proof_nonce = &bytes[68..100];
    let raw_proof_256 = &bytes[100..356];

    let public_values = proof.public_values.as_slice().to_vec();

    // The fixed Groth16 circuit VK for this SP1 version (downloaded into ~/.sp1).
    let vk_bin = read_groth16_vk();

    let fixtures = Path::new("fixtures");
    fs::create_dir_all(fixtures).expect("mkdir fixtures");
    fs::write(fixtures.join("proof_bytes.bin"), &bytes).unwrap();
    fs::write(fixtures.join("raw_proof_256.bin"), raw_proof_256).unwrap();
    fs::write(fixtures.join("public_values.bin"), &public_values).unwrap();
    fs::write(fixtures.join("exit_code.bin"), exit_code).unwrap();
    fs::write(fixtures.join("vk_root.bin"), vk_root).unwrap();
    fs::write(fixtures.join("proof_nonce.bin"), proof_nonce).unwrap();
    if let Some(vk) = &vk_bin {
        fs::write(fixtures.join("groth16_vk.bin"), vk).unwrap();
    }

    let manifest = serde_json::json!({
        "sp1_sdk_version": "6.2.4",
        "sp1_circuit_version": SP1_CIRCUIT_VERSION,
        "proving_mode": "groth16_local_cpu_native_gnark",
        "guest": "multiply(17, 23)",
        "sp1_vkey_hash": sp1_vkey_hash,
        "groth16_vkey_hash_hex": groth16_vkey_hash_hex,
        "public_inputs_count": 5,
        "public_inputs": public_inputs,
        "public_inputs_labels": [
            "0: vkey_hash (program identity)",
            "1: committed_values_digest = SHA256(public_values) top-3-bits masked",
            "2: exit_code",
            "3: vk_root (recursion VK merkle root, version constant)",
            "4: proof_nonce",
        ],
        "proof_bytes_len": bytes.len(),
        "vk_prefix_hex": hex::encode(vk_prefix),
        "exit_code_hex": hex::encode(exit_code),
        "vk_root_hex": hex::encode(vk_root),
        "proof_nonce_hex": hex::encode(proof_nonce),
        "public_values_hex": hex::encode(&public_values),
        "raw_proof_field_len_bytes": raw_proof_hex.len() / 2,
        "vk_bin_bytes": vk_bin.as_ref().map(|v| v.len()),
    });
    fs::write(fixtures.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap())
        .unwrap();

    println!("\nArtifacts written to fixtures/:");
    println!("  proof.bytes()        {} bytes", bytes.len());
    println!("  raw_proof_256.bin    256 bytes (gnark a|b|c)");
    println!("  public_values.bin    {} bytes", public_values.len());
    println!("  exit_code:           {}", hex::encode(exit_code));
    println!("  vk_root:             {}", hex::encode(vk_root));
    println!("  proof_nonce:         {}", hex::encode(proof_nonce));
    for (i, pi) in public_inputs.iter().enumerate() {
        println!("  public_inputs[{i}] = {pi}");
    }
    match &vk_bin {
        Some(v) => println!("  groth16_vk.bin       {} bytes", v.len()),
        None => println!("  groth16_vk.bin       NOT FOUND — copy it from ~/.sp1 manually"),
    }
}

/// Read the fixed Groth16 VK from the SP1 artifacts dir for this circuit version.
fn read_groth16_vk() -> Option<Vec<u8>> {
    let home = dirs::home_dir()?;
    let path = home
        .join(".sp1/circuits/groth16")
        .join(SP1_CIRCUIT_VERSION)
        .join("groth16_vk.bin");
    fs::read(path).ok()
}
