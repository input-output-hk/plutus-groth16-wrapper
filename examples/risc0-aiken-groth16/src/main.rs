//! End-to-end RISC Zero → Cardano demo (the tutorial base).
//!
//! Runs the full live pipeline for the `multiply(17, 23)` guest:
//!
//! ```text
//! [1] prove        multiply guest → RISC Zero Groth16 Receipt   (Docker stark2snark)
//! [2] canonicalize Receipt → CanonicalInnerProof                (re-verifies → binding)
//! [3] wrap         CliProver::prove → BLS12-381 OuterProof      (gnark, ~40s PK load)
//! [4] compose      generate Aiken validator project → aiken check
//! ```
//!
//! Nothing is hand-staged between the steps: the live `canonicalize` output
//! drives a real outer proof that drives a green validator. See `README.md`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use risc0_aiken_groth16_methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts};

use zkwrap_core::{compose, ComposeRequest, Groth16Backend, OuterProof, TestBlock};
use zkwrap_prover::{GnarkCliProver, Prover};
use zkwrap_risc0::{canonicalize, Risc0Codegen};

const FACTOR_A: u64 = 17;
const FACTOR_B: u64 = 23;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\n❌ {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gnark_bin = resolve_gnark_bin()?;
    let setup_dir = resolve_setup_dir()?;
    println!("config:");
    println!("  zkwrap-gnark : {}", gnark_bin.display());
    println!("  setup dir    : {}", setup_dir.display());

    // --- [1] prove: run the guest through the RISC Zero Groth16 prover --------
    println!("\n[1/4] proving multiply({FACTOR_A}, {FACTOR_B}) with ProverOpts::groth16() …");
    println!("      (first run pulls the stark2snark Docker image; the SNARK step takes minutes)");
    let env = ExecutorEnv::builder()
        .write(&FACTOR_A)?
        .write(&FACTOR_B)?
        .build()?;
    let receipt = default_prover()
        .prove_with_opts(env, MULTIPLY_ELF, &ProverOpts::groth16())?
        .receipt;
    receipt.verify(MULTIPLY_ID)?;
    let product: u64 = receipt.journal.decode()?;
    let journal_hex = hex::encode(&receipt.journal.bytes);
    println!("      ✔ receipt verified; journal commits {product} (bytes: {journal_hex})");
    let InnerReceipt::Groth16(groth16) = &receipt.inner else {
        return Err("expected a Groth16 receipt".into());
    };
    let expected_claim_digest = hex::encode(groth16.claim.digest().as_bytes());

    // --- [2] canonicalize: Receipt → canonical inner proof --------------------
    println!("\n[2/4] canonicalize: Receipt → CanonicalInnerProof (re-verifies vs image_id) …");
    let canonical = canonicalize(&receipt, MULTIPLY_ID)?;
    let n_real = canonical.proof.public_inputs.len();
    println!("      ✔ n_real = {n_real}; codegen constants extracted (image_id, control_root, …)");

    // --- [3] wrap: canonical inner proof → BLS12-381 outer proof (gnark) ------
    println!("\n[3/4] wrap: CliProver::prove → BLS12-381 outer proof (loads the ~1 GB PK ~40s) …");
    let prover = GnarkCliProver::new(&gnark_bin, &setup_dir);
    let outer = prover.prove(&canonical.proof)?;
    println!(
        "      ✔ outer proof: backend={}, max_inputs={}, inner_vk_hash={}",
        outer.backend, outer.max_inputs, outer.inner_vk_hash
    );

    // --- [4] compose: generate the Aiken validator project + aiken check ------
    println!("\n[4/4] compose: generate Aiken validator project, then `aiken check` …");
    let vk_json = std::fs::read_to_string(setup_dir.join("outer_vk.json"))?;
    let tests = build_tests(&outer, &journal_hex, &expected_claim_digest);

    let project = compose(&ComposeRequest {
        project_name: "zkwrap/risc0_groth16",
        outer: &Groth16Backend,
        inner: &Risc0Codegen,
        vk_json: &vk_json,
        inner_vk_hash: &outer.inner_vk_hash,
        codegen_meta: &canonical.codegen,
        tests: &tests,
    })?;

    let out_dir = manifest_path("generated/risc0-verifier");
    let _ = std::fs::remove_dir_all(&out_dir);
    project.write_to(&out_dir)?;
    println!("      ✔ project written to {}", out_dir.display());

    let Some(aiken) = which_aiken() else {
        println!(
            "\n⚠ `aiken` not found on PATH — skipping the on-chain check.\n  \
             Install it (https://aiken-lang.org/installation-guide), then run:\n    \
             cd {} && aiken check",
            out_dir.display()
        );
        println!("\n✅ pipeline complete through outer proof + project generation.");
        return Ok(());
    };

    println!("      running `{aiken} check` (validates the live proof on-chain logic):\n");
    let status = Command::new(&aiken)
        .arg("check")
        .current_dir(&out_dir)
        .status()?;
    if !status.success() {
        return Err("aiken check failed (see the report above)".into());
    }
    println!(
        "\n✅ aiken check passed — the RISC Zero execution verifies on Cardano's validator logic."
    );
    Ok(())
}

/// Builds the Aiken test blocks from the *live* outer proof and journal — the
/// same shape as `zkwrap-risc0/tests/generates_passing_project.rs`, but every
/// value is derived from this run rather than a committed fixture. The bare
/// names (`control_root_0`, `image_id`, …) resolve to the `const`s the Composer
/// bakes into `validators/verify.ak`.
fn build_tests(
    proof: &OuterProof,
    journal_hex: &str,
    expected_claim_digest: &str,
) -> Vec<TestBlock> {
    let pi_a = ba(&proof.proof.ar);
    let pi_b = ba(&proof.proof.bs);
    let pi_c = ba(&proof.proof.krs);
    let cu = ba(proof.commitment_uncompressed().unwrap());
    let pok = ba(&proof.proof.commitment_pok);
    let vkhash = int(&proof.inner_vk_hash);
    let inputs = int_list(&proof.inputs);

    let mut tampered = proof.inputs.clone();
    tampered[0] = bump_last(&proof.inputs[0]);
    let inputs_tampered = int_list(&tampered);

    let reals = int_list(&proof.inputs[0..5]);
    let journal_tampered = flip_first_byte(journal_hex);

    // Outer layer, literal-input form: groth16.verify(proof…, vkhash, inputs).
    let l1_verify = |vkh: &str, ins: &str| {
        format!("groth16.verify(\n  {pi_a},\n  {pi_b},\n  {pi_c},\n  {cu},\n  {pok},\n  {vkh},\n  {ins},\n)")
    };
    // Composed entry, journal form: verify(proof…, journal_bytes).
    let composed = |journal: &str| {
        format!(
            "verify(\n  {pi_a},\n  {pi_b},\n  {pi_c},\n  {cu},\n  {pok},\n  {},\n)",
            ba(journal)
        )
    };

    vec![
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
                ba(journal_hex),
                ba(expected_claim_digest)
            ),
        ),
        TestBlock::pass(
            "risc0_inputs_match_proof",
            format!(
                "risc0.real_inputs({}, control_root_0, control_root_1, image_id, post_state_digest, bn254_control_id) == {reals}",
                ba(journal_hex)
            ),
        ),
        TestBlock::pass("verify_risc0_valid_proof", composed(journal_hex)),
        TestBlock::fail("verify_risc0_tampered_journal", composed(&journal_tampered)),
    ]
}

// --- Aiken literal helpers (shared shape with generates_passing_project.rs) ---

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

/// Increment a 32-byte big-endian hex value by 1 (last byte is never 0xff for a
/// real BN254 Fr public input here).
fn bump_last(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] += 1;
    hex::encode(bytes)
}

/// Flip the low bit of the journal's first byte — a different, same-length
/// journal that must make the composed entry point reject.
fn flip_first_byte(hex: &str) -> String {
    let mut bytes = hex::decode(hex).unwrap();
    bytes[0] ^= 0x01;
    hex::encode(bytes)
}

// --- config / environment -----------------------------------------------------

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// `ZKWRAP_GNARK_BIN` if set, else `zkwrap-gnark` on PATH.
fn resolve_gnark_bin() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(p) = std::env::var_os("ZKWRAP_GNARK_BIN") {
        let p = PathBuf::from(p);
        if !p.exists() {
            return Err(format!("ZKWRAP_GNARK_BIN={} does not exist", p.display()).into());
        }
        return Ok(p);
    }
    if which("zkwrap-gnark").is_some() {
        return Ok(PathBuf::from("zkwrap-gnark"));
    }
    Err("zkwrap-gnark not found. Build it:\n    \
         cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark\n  \
         then set ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark"
        .into())
}

/// `ZKWRAP_SETUP_DIR` if set, else the committed `fixtures/groth16-setup`.
fn resolve_setup_dir() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let dir = std::env::var_os("ZKWRAP_SETUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_path("fixtures/groth16-setup"));
    if !dir.join("outer_pk.bin").exists() {
        return Err(format!(
            "setup dir {} has no outer_pk.bin. Regenerate it:\n    \
             {} unsafe-setup --max-inputs 8 --out {}",
            dir.display(),
            "zkwrap-gnark",
            dir.display()
        )
        .into());
    }
    Ok(dir)
}

fn which_aiken() -> Option<String> {
    which("aiken")
}

fn which(bin: &str) -> Option<String> {
    let probe = if cfg!(windows) { "where" } else { "which" };
    let out = Command::new(probe).arg(bin).output().ok()?;
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
