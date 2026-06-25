//! End-to-end test of the `gen-verifier` CLI: drive the *built binary* exactly
//! as a user would — staged on-disk artifacts in, an Aiken project out — then
//! `aiken check` the generated project.
//!
//! This is the real acceptance test for the CLI: it exercises arg parsing, the
//! on-disk reconstruction ([`Canonicalized::read_from`] + the runtime backend
//! dispatch in [`zkwrap_core::parse_outer_proof`]), project materialization, and
//! the actual on-chain verifier logic against a real proof. The two small unit
//! tests below pin the dispatcher's behavior directly.
//!
//! The canonical bundle the committed fixtures ship is prover-facing (no
//! `codegen` section), so the test first stages a codegen-bearing bundle with
//! `canonicalize(...).write_to(...)` — i.e. the artifact the `wrap` step writes.

use std::path::{Path, PathBuf};
use std::process::Command;

use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;

use zkwrap_core::parse_outer_proof;
use zkwrap_risc0::{canonicalize, Canonicalized};

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

const PROOF_REL: &str = "fixtures/outer-proofs/risc0-groth16-outer-proof.json";

/// Drive the built `zkwrap-risc0 gen-verifier` binary against the committed
/// fixtures and `aiken check` its output.
#[test]
fn cli_gen_verifier_emits_aiken_check_passing_project() {
    // Per-test working dir under the target tree (gitignored), kept on failure
    // for inspection.
    let work = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/generated")
        .join("cli-gen-verifier");
    let _ = std::fs::remove_dir_all(&work);

    // 1. Stage a codegen-bearing canonical bundle — what the `wrap` step writes.
    let receipt: Receipt =
        serde_json::from_str(&read("fixtures/risc0-hello-world/receipt.json")).unwrap();
    let image_id =
        Digest::try_from(read_bytes("fixtures/risc0-hello-world/image_id.bin").as_slice()).unwrap();
    let canon_dir = work.join("canonical");
    canonicalize(&receipt, image_id)
        .unwrap()
        .write_to(&canon_dir)
        .unwrap();

    // 2. Invoke the built binary as a real subprocess.
    let out_dir = work.join("verifier");
    let status = Command::new(env!("CARGO_BIN_EXE_zkwrap-risc0"))
        .arg("gen-verifier")
        .args(["--canonical".as_ref(), canon_dir.as_os_str()])
        .args([
            "--receipt".as_ref(),
            repo_path("fixtures/risc0-hello-world/receipt.json").as_os_str(),
        ])
        .args(["--outer-proof".as_ref(), repo_path(PROOF_REL).as_os_str()])
        .args([
            "--setup".as_ref(),
            repo_path("fixtures/groth16-setup").as_os_str(),
        ])
        .args(["--out".as_ref(), out_dir.as_os_str()])
        .status()
        .expect("failed to spawn zkwrap-risc0 binary");
    assert!(status.success(), "gen-verifier exited with failure");

    // 3. The expected project files are present.
    for rel in [
        "aiken.toml",
        "validators/verify.ak",
        "lib/zkwrap/groth16.ak",
        "lib/zkwrap/risc0.ak",
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

/// `read_from` is the inverse of `write_to`, including the `codegen` section,
/// and is insensitive to `write_to`'s pretty-JSON formatting.
#[test]
fn read_from_round_trips_write_to() {
    let receipt: Receipt =
        serde_json::from_str(&read("fixtures/risc0-hello-world/receipt.json")).unwrap();
    let image_id =
        Digest::try_from(read_bytes("fixtures/risc0-hello-world/image_id.bin").as_slice()).unwrap();
    let canonical = canonicalize(&receipt, image_id).unwrap();

    let dir = std::env::temp_dir().join(format!("zkwrap_read_from_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    canonical.write_to(&dir).unwrap();

    let recovered = Canonicalized::read_from(&dir).unwrap();
    assert_eq!(recovered.proof, canonical.proof, "proof round-trip");
    assert_eq!(recovered.codegen, canonical.codegen, "codegen round-trip");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn parse_outer_proof_dispatches_groth16() {
    let boxed = parse_outer_proof(&read(PROOF_REL)).unwrap();
    assert_eq!(boxed.backend(), "gnark-groth16-bls12381");
}

#[test]
fn parse_outer_proof_rejects_unknown_backend() {
    let bad = r#"{"backend":"nope","max_inputs":8,"proof":{},"inner_vk_hash":"00","inputs":[]}"#;
    assert!(parse_outer_proof(bad).is_err());
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
