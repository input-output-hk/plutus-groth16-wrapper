//! Tracer-bullet acceptance test: the Composer must emit a full
//! Aiken project that `aiken check`s green against the pinned spike fixture,
//! reproducing the spike's pairing outcome. Lifts the spike's nine inline
//! tests into the generated `validators/verify.ak`.
//!
//! The project is written under the workspace `target/` (gitignored) so it can
//! be inspected after the run. If `aiken` is not on `PATH` the test still
//! validates generation and the `aiken check` step is skipped with a notice.

use std::path::{Path, PathBuf};
use std::process::Command;

use zkwrap_core::{compose, ComposeRequest, Groth16Backend, OuterProof, TestBlock};
use zkwrap_risc0::Risc0Codegen;

// --- spike fixture values not present in outer_proof.json (RISC Zero guest
//     output + off-chain cross-checks).
/// `ExpandMsgXmd_SHA256(commitment_uncompressed) mod r`, from gnark.
const EXPECTED_COMMIT_FR: &str =
    "6385ca90542285a400c194342aaab4263f8b62b55282a58b9e6b482218462dc8";
/// Canonical compressed (48-byte) form of the commitment — the value the
/// on-chain `compress_from_uncompressed` helper must reproduce. (Not parsed
/// from the proof: codegen only needs the uncompressed bytes.)
const EXPECTED_COMMITMENT: &str =
    "a82fa3134bc25666c7a42336409323186f0e920d92b7b56f35dfd89555624e4a23fe016711a3aa49ad8fdf6354382bb5";
/// Raw guest output for multiply(17, 23): u64 LE = 391.
const JOURNAL_BYTES: &str = "8701000000000000";
/// Same journal with the low byte flipped (391 → 390).
const JOURNAL_TAMPERED: &str = "8601000000000000";
/// claim_digest reconstructed from JOURNAL_BYTES + version constants.
const EXPECTED_CLAIM_DIGEST: &str =
    "7cad906649785c4893e576973582aaff214f5ad2344e4f7ef575e3c6fc1ba432";
/// SystemState{pc:0, merkle_root:ZERO}.digest() — cleanly-halted constant.
const POST_STATE_DIGEST: &str =
    "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2";

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap()
}

// TODO: copy all necessary testdata inside the crate
fn risc0_fixture_hex(name: &str) -> String {
    hex::encode(std::fs::read(repo_path(&format!("experiments/risc0-hello-world/fixtures/{name}"))).unwrap())
}

/// `#"…"` ByteArray literal.
fn ba(hex: &str) -> String {
    format!("#\"{hex}\"")
}

/// `0x…` Int literal.
fn int(hex: &str) -> String {
    format!("0x{hex}")
}

/// `[0x.., 0x.., …]` over a slice of 32-byte BE Fr hex strings.
fn int_list(items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|h| int(h)).collect();
    format!("[{}]", body.join(", "))
}

/// Increment a 32-byte big-endian hex value by 1 (last byte never 0xff here).
fn bump_last(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] += 1;
    hex::encode(bytes)
}

fn build_tests(proof: &OuterProof) -> Vec<TestBlock> {
    let pi_a = ba(&proof.proof.ar);
    let pi_b = ba(&proof.proof.bs);
    let pi_c = ba(&proof.proof.krs);
    let commitment = ba(EXPECTED_COMMITMENT);
    let cu = ba(proof.commitment_uncompressed().unwrap());
    let pok = ba(&proof.proof.commitment_pok);
    let vkhash = int(&proof.inner_vk_hash);
    let inputs = int_list(&proof.inputs);

    let mut tampered = proof.inputs.clone();
    tampered[0] = bump_last(&proof.inputs[0]);
    let inputs_tampered = int_list(&tampered);

    let reals = int_list(&proof.inputs[0..5]);

    // Outer layer, literal-input form: groth16.verify(proof…, vkhash, inputs).
    let l1_verify = |vkh: &str, ins: &str| {
        format!(
            "groth16.verify(\n  {pi_a},\n  {pi_b},\n  {pi_c},\n  {cu},\n  {pok},\n  {vkh},\n  {ins},\n)"
        )
    };
    // Composed entry, journal form: verify(proof…, journal_bytes).
    let composed = |journal: &str| {
        format!(
            "verify(\n  {pi_a},\n  {pi_b},\n  {pi_c},\n  {cu},\n  {pok},\n  {},\n)",
            ba(journal)
        )
    };

    vec![
        TestBlock::pass(
            "commit_fr_matches_gnark",
            format!("groth16.hash_to_fr({cu}) == {}", int(EXPECTED_COMMIT_FR)),
        ),
        TestBlock::pass(
            "compress_binding_matches",
            format!("groth16.compress_from_uncompressed({cu}) == {commitment}"),
        ),
        TestBlock::pass("verify_valid_proof", l1_verify(&vkhash, &inputs)),
        TestBlock::fail(
            "verify_tampered_inner_vk_hash",
            l1_verify(&format!("{vkhash} + 1"), &inputs),
        ),
        TestBlock::fail("verify_tampered_input", l1_verify(&vkhash, &inputs_tampered)),
        TestBlock::pass(
            "claim_digest_chain_matches",
            format!(
                "risc0.compute_claim_digest_from_journal({}, image_id, post_state_digest) == {}",
                ba(JOURNAL_BYTES),
                ba(EXPECTED_CLAIM_DIGEST)
            ),
        ),
        TestBlock::pass(
            "risc0_inputs_match_fixture",
            format!(
                "risc0.real_inputs({}, control_root_0, control_root_1, image_id, post_state_digest, bn254_control_id) == {reals}",
                ba(JOURNAL_BYTES)
            ),
        ),
        TestBlock::pass("verify_risc0_valid_proof", composed(JOURNAL_BYTES)),
        TestBlock::fail("verify_risc0_tampered_journal", composed(JOURNAL_TAMPERED)),
    ]
}

#[test]
fn composer_emits_aiken_check_passing_project() {
    let vk_json = read("zkwrap-gnark/testdata/groth16-setup/outer_vk.json");
    let proof =
        OuterProof::from_json(&read("zkwrap-gnark/testdata/groth16-outer-proof.json")).unwrap();

    let codegen = serde_json::json!({
        "image_id": risc0_fixture_hex("image_id.bin"),
        "post_state_digest": POST_STATE_DIGEST,
        "control_root": risc0_fixture_hex("control_root.bin"),
        "bn254_control_id": risc0_fixture_hex("bn254_control_id.bin"),
    });

    let tests = build_tests(&proof);

    let project = compose(&ComposeRequest {
        project_name: "zkwrap/risc0_groth16",
        outer: &Groth16Backend,
        inner: &Risc0Codegen,
        vk_json: &vk_json,
        inner_vk_hash: &proof.inner_vk_hash,
        codegen_meta: &codegen,
        tests: &tests,
    })
    .unwrap();

    // Generation sanity: required files present, no unrendered template holes.
    let validator = project.get("validators/verify.ak").expect("validators/verify.ak");
    let layer1 = project.get("lib/zkwrap/groth16.ak").expect("lib/zkwrap/groth16.ak");
    let layer2 = project.get("lib/zkwrap/risc0.ak").expect("lib/zkwrap/risc0.ak");
    for (name, src) in [("groth16", layer1), ("risc0", layer2), ("verify", validator)] {
        assert!(!src.contains("{{") && !src.contains("{%"), "{name}.ak has unrendered holes");
    }
    assert!(validator.contains("const inner_vk_hash: Int = 0x0c42ca6b"));

    // Materialize under the (gitignored) target dir for inspection + aiken check.
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/generated/risc0-verifier");
    let _ = std::fs::remove_dir_all(&out_dir);
    project.write_to(&out_dir).unwrap();
    eprintln!("generated project at {}", out_dir.display());

    let Some(aiken) = which_aiken() else {
        eprintln!("`aiken` not found on PATH — skipping `aiken check`");
        return;
    };

    let output = Command::new(&aiken)
        .arg("check")
        .current_dir(&out_dir)
        .output()
        .expect("failed to run aiken check");

    if !output.status.success() {
        panic!(
            "aiken check failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
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
