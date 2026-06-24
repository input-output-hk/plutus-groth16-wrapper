//! End-to-end RISC Zero → Cardano demo, **PLONK outer backend**.
//!
//! Identical to `../risc0-aiken-groth16` except the wrap step proves a PLONK
//! outer proof instead of Groth16 (the inner RISC Zero proof is the same). Runs
//! the full live pipeline for the `multiply(17, 23)` guest:
//!
//! ```text
//! [1] prove          multiply guest → RISC Zero Groth16 Receipt   (Docker stark2snark)
//! [2] canonicalize   Receipt → CanonicalInnerProof                (re-verifies → binding)
//! [3] wrap           GnarkCliProver::prove → BLS12-381 PLONK OuterProof (gnark)
//! [4] build_validator generate Aiken validator project → aiken check
//! ```
//!
//! Nothing is hand-staged between the steps: the live `canonicalize` output
//! drives a real outer proof that drives a green validator. See `README.md`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use risc0_aiken_plonk_methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

use zkwrap_core::{OuterProof, PlonkOuterProof};
use zkwrap_prover::{GnarkCliProver, Prover};
use zkwrap_risc0::{build_validator, canonicalize, Risc0ValidatorRequest};

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
    println!("      ✔ receipt verified; journal commits {product}");

    // --- [2] canonicalize: Receipt → canonical inner proof --------------------
    println!("\n[2/4] canonicalize: Receipt → CanonicalInnerProof (re-verifies vs image_id) …");
    let canonical = canonicalize(&receipt, MULTIPLY_ID)?;
    let n_real = canonical.proof.public_inputs.len();
    println!("      ✔ n_real = {n_real}; codegen constants extracted (image_id, control_root, …)");

    // --- [3] wrap: canonical inner proof → BLS12-381 PLONK outer proof (gnark) -
    println!(
        "\n[3/4] wrap: GnarkCliProver::prove → BLS12-381 PLONK outer proof (loads the proving key, ~30-40s) …"
    );
    let outer =
        GnarkCliProver::new(&gnark_bin, &setup_dir).prove::<PlonkOuterProof>(&canonical.proof)?;
    println!(
        "      ✔ outer proof: backend={}, num_inputs={}, inner_vk_hash={}",
        outer.backend(),
        outer.num_inputs(),
        outer.inner_vk_hash()
    );

    // --- [4] build_validator: generate the Aiken project + aiken check --------
    // One call: the factory selects the outer layer from `outer.backend`,
    // generates the standard test suite, and composes the project.
    println!("\n[4/4] build_validator: generate Aiken validator project, then `aiken check` …");
    let vk_json = std::fs::read_to_string(setup_dir.join("outer_vk.json"))?;
    let project = build_validator(&Risc0ValidatorRequest {
        receipt: &receipt,
        canonical: &canonical,
        outer_proof: &outer,
        outer_vk_json: &vk_json,
        project_name: "zkwrap/risc0_plonk",
    })?;

    let out_dir = manifest_path("generated/risc0-verifier");
    let _ = std::fs::remove_dir_all(&out_dir);
    project.write_to(&out_dir)?;
    println!("      ✔ project written to {}", out_dir.display());

    aiken_check(&out_dir)
}

/// Run `aiken check` in the generated project to validate the live proof against
/// the validator logic. If `aiken` isn't on PATH, print install guidance and
/// skip (the proof + project are still produced).
fn aiken_check(out_dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(aiken) = which("aiken") else {
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
    // Inherit the terminal so aiken detects a TTY and prints its pretty,
    // colored report instead of the machine-readable JSON it emits when piped.
    let status = Command::new(&aiken)
        .arg("check")
        .current_dir(out_dir)
        .status()?;
    if !status.success() {
        return Err("aiken check failed (see the report above)".into());
    }
    println!(
        "\n✅ aiken check passed — the RISC Zero execution verifies on Cardano's validator logic."
    );
    Ok(())
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

/// `ZKWRAP_SETUP_DIR` if set, else the committed `fixtures/plonk-setup`.
fn resolve_setup_dir() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let dir = std::env::var_os("ZKWRAP_SETUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_path("fixtures/plonk-setup"));
    if !dir.join("outer_pk.bin").exists() {
        return Err(format!(
            "setup dir {} has no outer_pk.bin. Regenerate it:\n    \
             zkwrap-gnark unsafe-setup --backend plonk --max-inputs 5 --out {}",
            dir.display(),
            dir.display()
        )
        .into());
    }
    Ok(dir)
}

fn which(bin: &str) -> Option<String> {
    // risc0 proving is Linux-only, so `which` is always available.
    let out = Command::new("which").arg(bin).output().ok()?;
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
