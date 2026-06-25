//! `zkwrap-risc0` — the RISC Zero plugin CLI.
//!
//! Exposes `gen-verifier`: the deploy-time step that turns on-disk artifacts
//! into a ready-to-`aiken check` Aiken validator project.
//! It is deliberately decoupled from proving — you build the validator *once*,
//! from artifacts the earlier (expensive) steps already wrote to disk:
//!
//! ```text
//! zkwrap-risc0 gen-verifier \
//!     --canonical   out/canonical          # Canonicalized::write_to bundle (codegen consts)
//!     --receipt     out/receipt.json        # the RISC Zero receipt (journal + claim digest)
//!     --outer-proof out/outer-proof.json    # the gnark outer proof (inner_vk_hash + inputs)
//!     --setup       fixtures/groth16-setup  # the trusted setup dir (reads outer_vk.json)
//!     --out         generated/risc0-verifier
//!     [--project-name zkwrap/risc0_groth16] [--check]
//! ```
//!
//! The outer proof is *required* — its public inputs drive the generated unit
//! tests, so every emitted project ships with a real positive/tamper suite that
//! `aiken check` (via `--check`) runs against an actual proof. The receipt is the
//! authoritative source of the journal (a hash preimage not recoverable from any
//! other artifact); the canonical bundle carries the per-guest codegen constants;
//! the setup dir holds the outer VK baked into the generic outer layer.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use risc0_zkvm::Receipt;
use zkwrap_core::parse_outer_proof;
use zkwrap_risc0::{build_validator, Canonicalized, Risc0ValidatorRequest};

const DEFAULT_PROJECT_NAME: &str = "zkwrap/risc0_verifier";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

fn run(args: &[String]) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("gen-verifier") => gen_verifier(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand {other:?}\n\n{USAGE}").into()),
    }
}

const USAGE: &str = "\
zkwrap-risc0 — RISC Zero plugin CLI

USAGE:
    zkwrap-risc0 gen-verifier --canonical <dir> --receipt <file> \\
        --outer-proof <file> --setup <dir> --out <dir> \\
        [--project-name <ns/name>] [--check]

Generate an Aiken validator project from on-disk artifacts (no proving).

OPTIONS:
    --canonical <dir>     canonical inner-proof bundle (Canonicalized::write_to)
    --receipt <file>      RISC Zero receipt JSON (journal + claim digest)
    --outer-proof <file>  gnark outer proof JSON (inner_vk_hash + public inputs)
    --setup <dir>         trusted-setup dir; reads <dir>/outer_vk.json
    --out <dir>           output directory for the generated project
    --project-name <s>    Aiken project name (default: zkwrap/risc0_verifier)
    --check               run `aiken check` in the generated project
";

fn gen_verifier(args: &[String]) -> Result<(), BoxErr> {
    let mut canonical: Option<PathBuf> = None;
    let mut receipt: Option<PathBuf> = None;
    let mut outer_proof: Option<PathBuf> = None;
    let mut setup: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut project_name = DEFAULT_PROJECT_NAME.to_string();
    let mut check = false;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--canonical" => canonical = Some(value()?.into()),
            "--receipt" => receipt = Some(value()?.into()),
            "--outer-proof" => outer_proof = Some(value()?.into()),
            "--setup" => setup = Some(value()?.into()),
            "--out" => out = Some(value()?.into()),
            "--project-name" => project_name = value()?,
            "--check" => check = true,
            other => return Err(format!("unknown flag {other:?}\n\n{USAGE}").into()),
        }
    }

    let canonical = canonical.ok_or("missing --canonical")?;
    let receipt = receipt.ok_or("missing --receipt")?;
    let outer_proof = outer_proof.ok_or("missing --outer-proof")?;
    let setup = setup.ok_or("missing --setup")?;
    let out = out.ok_or("missing --out")?;

    // Reconstruct the inputs `build_validator` needs, from disk.
    let canonical = Canonicalized::read_from(&canonical)
        .map_err(|e| format!("reading canonical bundle: {e}"))?;
    let receipt: Receipt = serde_json::from_str(&std::fs::read_to_string(&receipt)?)
        .map_err(|e| format!("parsing receipt JSON: {e}"))?;
    let outer = parse_outer_proof(&std::fs::read_to_string(&outer_proof)?)
        .map_err(|e| format!("parsing outer proof: {e}"))?;
    let vk_json = std::fs::read_to_string(setup.join("outer_vk.json"))
        .map_err(|e| format!("reading {}/outer_vk.json: {e}", setup.display()))?;

    let project = build_validator(&Risc0ValidatorRequest {
        receipt: &receipt,
        canonical: &canonical,
        outer_proof: &*outer,
        outer_vk_json: &vk_json,
        project_name: &project_name,
    })?;

    project.write_to(&out)?;
    println!(
        "generated {} validator ({} backend) → {}",
        project_name,
        outer.backend(),
        out.display()
    );

    if check {
        aiken_check(&out)?;
    } else {
        println!("run `cd {} && aiken check` to validate on-chain.", out.display());
    }
    Ok(())
}

/// Run `aiken check` in the generated project (used by `--check`).
fn aiken_check(out_dir: &Path) -> Result<(), BoxErr> {
    println!("running `aiken check` in {} …", out_dir.display());
    let status = Command::new("aiken")
        .arg("check")
        .current_dir(out_dir)
        .status()
        .map_err(|e| format!("could not run `aiken` (is it on PATH?): {e}"))?;
    if !status.success() {
        return Err("aiken check failed (see report above)".into());
    }
    println!("aiken check passed.");
    Ok(())
}
