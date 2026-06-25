//! `zkwrap-sp1` — the SP1 plugin CLI.
//!
//! Exposes `gen-verifier`: the deploy-time step that turns on-disk artifacts
//! into a ready-to-`aiken check` Aiken validator project.
//!
//! ```text
//! zkwrap-sp1 gen-verifier \
//!     --canonical      out/canonical          # CanonicalBundle::write_to bundle (codegen consts + proof_nonce)
//!     --public-values  out/public_values.bin  # the bytes the guest committed
//!     --outer-proof    out/outer-proof.json   # the gnark outer proof (inner_vk_hash + inputs)
//!     --setup          fixtures/groth16-setup # the trusted setup dir (reads outer_vk.json)
//!     --out            generated/sp1-verifier
//!     [--project-name zkwrap/sp1_verifier] [--check]
//! ```
//!
//! The outer proof is *required* — its public inputs drive the generated unit
//! tests, so every emitted project ships with a real positive/tamper suite that
//! `aiken check` (via `--check`) runs against an actual proof. `public_values` is
//! the authoritative source of the committed bytes (a hash preimage not
//! recoverable from any other artifact); the canonical bundle carries the
//! per-program codegen constants and the per-proof `proof_nonce`; the setup dir
//! holds the outer VK baked into the generic outer layer.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use zkwrap_core::parse_outer_proof;
use zkwrap_sp1::{build_validator, CanonicalBundle, Sp1CodegenData, Sp1ValidatorRequest};

const DEFAULT_PROJECT_NAME: &str = "zkwrap/sp1_verifier";

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
zkwrap-sp1 — SP1 plugin CLI

USAGE:
    zkwrap-sp1 gen-verifier --canonical <dir> --public-values <file> \\
        --outer-proof <file> --setup <dir> --out <dir> \\
        [--project-name <ns/name>] [--check]

Generate an Aiken validator project from on-disk artifacts.

OPTIONS:
    --canonical <dir>      canonical inner-proof bundle (CanonicalBundle::write_to)
    --public-values <file> the bytes the guest committed
    --outer-proof <file>   gnark outer proof JSON (inner_vk_hash + public inputs)
    --setup <dir>          trusted-setup dir; reads <dir>/outer_vk.json
    --out <dir>            output directory for the generated project
    --project-name <s>     Aiken project name (default: zkwrap/sp1_verifier)
    --check                run `aiken check` in the generated project
";

fn gen_verifier(args: &[String]) -> Result<(), BoxErr> {
    let mut canonical: Option<PathBuf> = None;
    let mut public_values: Option<PathBuf> = None;
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
            "--public-values" => public_values = Some(value()?.into()),
            "--outer-proof" => outer_proof = Some(value()?.into()),
            "--setup" => setup = Some(value()?.into()),
            "--out" => out = Some(value()?.into()),
            "--project-name" => project_name = value()?,
            "--check" => check = true,
            other => return Err(format!("unknown flag {other:?}\n\n{USAGE}").into()),
        }
    }

    let canonical = canonical.ok_or("missing --canonical")?;
    let public_values = public_values.ok_or("missing --public-values")?;
    let outer_proof = outer_proof.ok_or("missing --outer-proof")?;
    let setup = setup.ok_or("missing --setup")?;
    let out = out.ok_or("missing --out")?;

    // Reconstruct the inputs `build_validator` needs, from disk.
    let canonical = CanonicalBundle::<Sp1CodegenData>::read_from(&canonical)
        .map_err(|e| format!("reading canonical bundle: {e}"))?;
    let public_values =
        std::fs::read(&public_values).map_err(|e| format!("reading public values: {e}"))?;
    let outer = parse_outer_proof(&std::fs::read_to_string(&outer_proof)?)
        .map_err(|e| format!("parsing outer proof: {e}"))?;
    let vk_json = std::fs::read_to_string(setup.join("outer_vk.json"))
        .map_err(|e| format!("reading {}/outer_vk.json: {e}", setup.display()))?;

    let project = build_validator(&Sp1ValidatorRequest {
        canonical: &canonical,
        outer_proof: &*outer,
        outer_vk_json: &vk_json,
        public_values: &public_values,
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
        println!(
            "run `cd {} && aiken check` to validate on-chain.",
            out.display()
        );
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
