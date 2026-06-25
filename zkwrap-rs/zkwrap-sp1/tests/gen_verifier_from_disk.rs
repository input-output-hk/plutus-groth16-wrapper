//! End-to-end test of the `zkwrap-sp1 gen-verifier` CLI: drive the *built
//! binary* exactly as a user would — staged on-disk artifacts in, an Aiken
//! project out — then `aiken check` the generated project. Mirrors
//! `zkwrap-risc0`'s CLI test; the SP1-specific input is `--public-values`
//! instead of `--receipt`.
//!
//! The committed canonical bundle is prover-facing (no `codegen` section), so the
//! test first stages a codegen-bearing bundle with `canonicalize(...).write_to`
//! — the artifact the `wrap` step writes.

use std::path::{Path, PathBuf};
use std::process::Command;

use sp1_verifier::{Groth16Bn254Proof, SP1Proof};

use zkwrap_core::parse_outer_proof;
use zkwrap_sp1::{canonicalize, Canonicalized};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap()
}

fn read_bytes(rel: &str) -> Vec<u8> {
    std::fs::read(repo_path(rel)).unwrap()
}

const PROOF_REL: &str = "fixtures/outer-proofs/sp1-groth16-outer-proof.json";

/// Canonicalize the committed raw SP1 fixtures (as a host would), to stage a
/// codegen-bearing bundle on disk.
fn sp1_canonical(public_values: &[u8]) -> Canonicalized {
    let proof_bytes = read_bytes("fixtures/sp1-hello-world/proof_bytes.bin");
    let manifest: serde_json::Value =
        serde_json::from_str(&read("fixtures/sp1-hello-world/manifest.json")).unwrap();
    let vkey_hash_dec = manifest["public_inputs"][0].as_str().unwrap().to_string();
    let sp1_proof = SP1Proof::Groth16(Groth16Bn254Proof {
        public_inputs: [
            vkey_hash_dec,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ],
        encoded_proof: hex::encode(&proof_bytes[4..]),
        raw_proof: String::new(),
        groth16_vkey_hash: proof_bytes[0..32].try_into().unwrap(),
    });
    canonicalize(&sp1_proof, public_values).unwrap()
}

/// Drive the built `zkwrap-sp1 gen-verifier` binary against the committed
/// fixtures and `aiken check` its output.
#[test]
fn cli_gen_verifier_emits_aiken_check_passing_project() {
    let work = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/generated")
        .join("cli-gen-verifier-sp1");
    let _ = std::fs::remove_dir_all(&work);

    // 1. Stage a codegen-bearing canonical bundle — what the `wrap` step writes.
    let public_values = read_bytes("fixtures/sp1-hello-world/public_values.bin");
    let canon_dir = work.join("canonical");
    sp1_canonical(&public_values).write_to(&canon_dir).unwrap();
    let pv_path = work.join("public_values.bin");
    std::fs::write(&pv_path, &public_values).unwrap();

    // 2. Invoke the built binary as a real subprocess.
    let out_dir = work.join("verifier");
    let status = Command::new(env!("CARGO_BIN_EXE_zkwrap-sp1"))
        .arg("gen-verifier")
        .args(["--canonical".as_ref(), canon_dir.as_os_str()])
        .args(["--public-values".as_ref(), pv_path.as_os_str()])
        .args(["--outer-proof".as_ref(), repo_path(PROOF_REL).as_os_str()])
        .args([
            "--setup".as_ref(),
            repo_path("fixtures/groth16-setup").as_os_str(),
        ])
        .args(["--out".as_ref(), out_dir.as_os_str()])
        .status()
        .expect("failed to spawn zkwrap-sp1 binary");
    assert!(status.success(), "gen-verifier exited with failure");

    // 3. The expected project files are present.
    for rel in [
        "aiken.toml",
        "validators/verify.ak",
        "lib/zkwrap/groth16.ak",
        "lib/zkwrap/sp1.ak",
    ] {
        assert!(
            out_dir.join(rel).is_file(),
            "generated project missing {rel}"
        );
    }

    // 4. `aiken check` the generated project (skipped if aiken isn't installed).
    let Some(aiken) = which_aiken() else {
        eprintln!("`aiken` not found on PATH — skipping `aiken check`");
        return;
    };
    let output = Command::new(&aiken)
        .arg("check")
        .current_dir(&out_dir)
        .output()
        .expect("failed to run aiken check");
    assert!(
        output.status.success(),
        "aiken check failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn parse_outer_proof_dispatches_groth16() {
    let boxed = parse_outer_proof(&read(PROOF_REL)).unwrap();
    assert_eq!(boxed.backend(), "gnark-groth16-bls12381");
}

fn which_aiken() -> Option<String> {
    let probe = if cfg!(windows) { "where" } else { "which" };
    let out = Command::new(probe).arg("aiken").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    (!path.is_empty()).then_some(path)
}
