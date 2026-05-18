use std::fs;
use std::path::Path;

use sp1_sdk::{
    install::groth16_circuit_artifacts_dir, HashableKey, ProverClient, SP1Proof, SP1Stdin,
    SP1_CIRCUIT_VERSION,
};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let (a, b): (u64, u64) = (17, 23);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);

    let sp1_vkey_hash = vk.bytes32();
    println!("SP1 vkey hash: {}", sp1_vkey_hash);

    let mut stdin = SP1Stdin::new();
    stdin.write(&a);
    stdin.write(&b);

    println!("Proving {} × {} with Groth16 ...", a, b);
    let mut proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("groth16 prove failed");

    client.verify(&proof, &vk).expect("sp1 verify failed");
    println!("SP1 verify OK");

    let SP1Proof::Groth16(ref groth16) = proof.proof else {
        panic!(
            "Expected Groth16 inner proof; got {:?}",
            std::mem::discriminant(&proof.proof)
        );
    };

    let raw_proof_bytes = hex::decode(&groth16.raw_proof).expect("raw_proof hex decode failed");
    // SP1's gnark fork serialises: Ar(64) + Bs(128) + Krs(64) + num_commitments(4) + CommitmentPok(64) = 324 bytes
    assert_eq!(raw_proof_bytes.len(), 324, "expected 324-byte raw proof (256 + 4 + 64 CommitmentPok)");

    let public_inputs_0 = groth16.public_inputs[0].clone();
    let public_inputs_1 = groth16.public_inputs[1].clone();
    let groth16_vkey_hash_hex = hex::encode(groth16.groth16_vkey_hash);

    // Snapshot public values bytes before consuming via read().
    let public_values_bytes = proof.public_values.as_slice().to_vec();

    // Copy groth16_vk.bin from the SP1 artifacts dir.
    let artifacts_dir = groth16_circuit_artifacts_dir();
    let vk_bin = fs::read(artifacts_dir.join("groth16_vk.bin"))
        .expect("groth16_vk.bin not found in SP1 artifacts dir");

    // Write fixtures.
    let fixtures = Path::new("fixtures");
    fs::create_dir_all(fixtures).expect("failed to create fixtures/");

    fs::write(fixtures.join("seal.bin"), &raw_proof_bytes).unwrap();
    fs::write(fixtures.join("vk.bin"), &vk_bin).unwrap();
    fs::write(fixtures.join("public_values.bin"), &public_values_bytes).unwrap();

    let public_inputs = serde_json::json!({
        "inputs": [
            public_inputs_0,
            public_inputs_1
        ],
        "labels": [
            "public_inputs[0]: vkey_hash (SHA256 of Groth16 VK, reduced to BN254 Fr, decimal string)",
            "public_inputs[1]: committed_values_digest (SHA256 of public_values.bin, reduced to BN254 Fr, decimal string)"
        ]
    });
    fs::write(
        fixtures.join("public_inputs.json"),
        serde_json::to_string_pretty(&public_inputs).unwrap(),
    )
    .unwrap();

    let c: u64 = proof.public_values.read::<u64>();
    let manifest = serde_json::json!({
        "sp1_sdk_version": "3.4.0",
        "sp1_circuit_version": SP1_CIRCUIT_VERSION,
        "proving_mode": "groth16_local_native_gnark",
        "guest": "multiply(17, 23)",
        "sp1_vkey_hash": sp1_vkey_hash,
        "journal_decoded_u64": c,
        "journal_hex": hex::encode(&public_values_bytes),
        "journal_bytes": public_values_bytes.len(),
        "seal_bytes": raw_proof_bytes.len(),
        "seal_hex_prefix_32b": hex::encode(&raw_proof_bytes[..32]),
        "vk_bin_bytes": vk_bin.len(),
        "public_inputs_count": 2,
        "public_inputs": [
            public_inputs_0,
            public_inputs_1
        ],
        "groth16_vkey_hash_hex": groth16_vkey_hash_hex
    });
    fs::write(
        fixtures.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    println!("Artifacts written to fixtures/");
    println!("  seal.bin               {} bytes", raw_proof_bytes.len());
    println!("  vk.bin                 {} bytes (gnark compressed format)", vk_bin.len());
    println!(
        "  public_values.bin      {} bytes  → decoded u64 = {}",
        public_values_bytes.len(),
        c
    );
    println!("  public_inputs.json     2 BN254 Fr elements");
    println!("  manifest.json          written");
    println!("  vkey_hash:             {}", public_inputs_0);
    println!("  committed_values_digest: {}", public_inputs_1);
    println!("  SP1 circuit version:   {}", SP1_CIRCUIT_VERSION);
}
