//! End-to-end SP1 → Cardano demo (the SP1 tutorial base).
//!
//! Runs the full live pipeline for the `multiply(17, 23)` guest:
//!
//! ```text
//! [1] prove          multiply guest → SP1 Groth16 proof          (local native-gnark)
//! [2] canonicalize   SP1 proof → CanonicalInnerProof             (ark-groth16 verify → binding)
//! [3] wrap           GnarkCliProver::prove → BLS12-381 OuterProof (gnark, ~33s PK load)
//! [4] build_validator generate Aiken validator project → aiken check
//! ```
//!
//! Nothing is hand-staged between the steps: the live `canonicalize_proof`
//! output drives a real outer proof that drives a green validator. See
//! `README.md`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, SP1Stdin};

use zkwrap_prover::{GnarkCliProver, Prover as _};
use zkwrap_sp1::{build_validator, canonicalize, Sp1ValidatorRequest};

/// The guest ELF, compiled by `build.rs` (sp1-build) with the SP1 toolchain.
const ELF: sp1_sdk::Elf = include_elf!("multiply");

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

    // --- [1] prove: run the guest through the SP1 Groth16 prover (local CPU) --
    println!("\n[1/4] proving multiply({FACTOR_A}, {FACTOR_B}) with .groth16() …");
    println!("      (loads the ~3.2 GB SP1 Groth16 circuit; local CPU proving takes minutes)");
    let prover = ProverClient::builder().cpu().build();
    let pk = prover.setup(ELF)?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&FACTOR_A);
    stdin.write(&FACTOR_B);

    let proof = prover.prove(&pk, stdin).groth16().run()?;
    let public_values = proof.public_values.as_slice().to_vec();
    println!("      ✔ SP1 proof generated; public values = {}", hex::encode(&public_values));

    // --- [2] canonicalize: SP1 proof → canonical inner proof ------------------
    println!("\n[2/4] canonicalize: SP1 proof → CanonicalInnerProof (ark-groth16 verify) …");
    let canonical = canonicalize(&proof.proof, &public_values)?;
    let n_real = canonical.proof.public_inputs.len();
    // proof_nonce (public input 4) is per-proof; it rides in the validator redeemer.
    let proof_nonce = canonical.proof.public_inputs[4].0;
    println!(
        "      ✔ n_real = {n_real}; baked consts extracted (vkey_hash={})",
        canonical.codegen["vkey_hash"].as_str().unwrap_or("?")
    );

    // --- [3] wrap: canonical inner proof → BLS12-381 outer proof (gnark) ------
    println!(
        "\n[3/4] wrap: GnarkCliProver::prove → BLS12-381 outer proof (loads the ~1 GB PK ~33s) …"
    );
    let outer = GnarkCliProver::new(&gnark_bin, &setup_dir).prove(&canonical.proof)?;
    println!(
        "      ✔ outer proof: backend={}, max_inputs={}, inner_vk_hash={}",
        outer.backend, outer.max_inputs, outer.inner_vk_hash
    );

    // --- [4] build_validator: generate the Aiken project + aiken check --------
    println!("\n[4/4] build_validator: generate Aiken validator project, then `aiken check` …");
    let vk_json = std::fs::read_to_string(setup_dir.join("outer_vk.json"))?;
    let project = build_validator(&Sp1ValidatorRequest {
        canonical: &canonical,
        outer_proof: &outer,
        outer_vk_json: &vk_json,
        public_values: &public_values,
        proof_nonce: &proof_nonce,
        project_name: "zkwrap/sp1_groth16",
    })?;

    let out_dir = manifest_path("generated/sp1-verifier");
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
    let status = Command::new(&aiken)
        .arg("check")
        .current_dir(out_dir)
        .status()?;
    if !status.success() {
        return Err("aiken check failed (see the report above)".into());
    }
    println!("\n✅ aiken check passed — the SP1 execution verifies on Cardano's validator logic.");
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

/// `ZKWRAP_SETUP_DIR` if set, else the committed `fixtures/groth16-setup`.
fn resolve_setup_dir() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let dir = std::env::var_os("ZKWRAP_SETUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_path("fixtures/groth16-setup"));
    if !dir.join("outer_pk.bin").exists() {
        return Err(format!(
            "setup dir {} has no outer_pk.bin. Regenerate it:\n    \
             zkwrap-gnark unsafe-setup --max-inputs 8 --out {}",
            dir.display(),
            dir.display()
        )
        .into());
    }
    Ok(dir)
}

fn which(bin: &str) -> Option<String> {
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
