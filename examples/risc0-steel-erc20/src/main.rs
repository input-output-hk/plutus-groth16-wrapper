//! End-to-end RISC Zero **Steel** → Cardano demo.
//!
//! Proves an Ethereum state fact — `balanceOf(account)` on an ERC-20 token —
//! inside the zkVM via Steel, then runs the wrapped proof through the full
//! zkwrap pipeline:
//!
//! ```text
//! [1] preflight      view call against ETH_RPC_URL → EvmInput (headers + MPT proofs)
//! [2] prove          Steel guest → RISC Zero Groth16 Receipt   (Docker stark2snark)
//! [3] canonicalize   Receipt → CanonicalInnerProof              (re-verifies → binding)
//! [4] wrap           GnarkCliProver::prove → BLS12-381 OuterProof (gnark, ~40s PK load)
//! [5] build_validator generate Aiken validator project → aiken check
//! ```
//!
//! The journal carries Steel's `Commitment` (which Ethereum block the state was
//! read at) plus token/account/balance — everything the app-level Aiken policy
//! later binds against. See `README.md` for the trust-anchor caveat: Cardano
//! cannot check Ethereum block hashes, so the commitment digest is a *claimed*
//! anchor at this stage of the showcase.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use alloy_primitives::Address;
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{
    ethereum::{EthEvmEnv, EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Contract,
};
use risc0_steel_erc20_methods::{ERC20_BALANCE_ELF, ERC20_BALANCE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use url::Url;

use zkwrap_core::{Groth16OuterProof, OuterProof};
use zkwrap_prover::{GnarkCliProver, Prover};
use zkwrap_risc0::{build_validator, canonicalize, Risc0ValidatorRequest};

sol! {
    /// ERC-20 balance function signature. Must match the guest.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

// Must match the guest's journal layout exactly (six static 32-byte words).
sol! {
    struct Journal {
        Commitment commitment;
        address token;
        address account;
        uint256 balance;
    }
}

/// Defaults from the upstream Steel erc20 example: a USDT test token on Sepolia
/// and a holder with a nonzero balance. Override with STEEL_TOKEN / STEEL_ACCOUNT.
const DEFAULT_TOKEN: &str = "0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0";
const DEFAULT_ACCOUNT: &str = "0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\n❌ {e}");
            ExitCode::FAILURE
        }
    }
}

type Error = Box<dyn std::error::Error + Send + Sync>;

fn run() -> Result<(), Error> {
    // reqwest is built with `rustls-no-provider` (keeps aws-lc-sys out of the
    // build — its C compilation fails on WSL /mnt mounts), so a process-wide
    // rustls crypto provider must be installed before any TLS use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "failed to install the rustls ring crypto provider")?;

    let gnark_bin = resolve_gnark_bin()?;
    let setup_dir = resolve_setup_dir()?;
    let rpc_url = resolve_rpc_url()?;
    let token: Address = env_or("STEEL_TOKEN", DEFAULT_TOKEN).parse()?;
    let account: Address = env_or("STEEL_ACCOUNT", DEFAULT_ACCOUNT).parse()?;
    println!("config:");
    println!("  zkwrap-gnark : {}", gnark_bin.display());
    println!("  setup dir    : {}", setup_dir.display());
    println!("  eth rpc      : {rpc_url}");
    println!("  token        : {token}");
    println!("  account      : {account}");

    // --- [1] preflight: run the view call natively, collect state + proofs ----
    println!("\n[1/5] preflight: balanceOf view call against Sepolia (headers + MPT proofs) …");
    let (input, native_balance) = tokio::runtime::Runtime::new()?
        .block_on(preflight(rpc_url, token, account))
        .map_err(|e| format!("preflight failed: {e:#}"))?;
    println!("      ✔ native call returns balance = {native_balance}");

    // --- [2] prove: run the Steel guest through the RISC Zero Groth16 prover --
    println!("\n[2/5] proving the Steel guest with ProverOpts::groth16() …");
    println!("      (first run pulls the stark2snark Docker image; the SNARK step takes minutes)");
    let env = ExecutorEnv::builder()
        .write(&input)?
        .write(&token)?
        .write(&account)?
        .build()?;
    let prove_start = std::time::Instant::now();
    let receipt = default_prover()
        .prove_with_opts(env, ERC20_BALANCE_ELF, &ProverOpts::groth16())?
        .receipt;
    receipt.verify(ERC20_BALANCE_ID)?;
    let journal = Journal::abi_decode(&receipt.journal.bytes)?;
    println!(
        "      ✔ receipt verified in {:?}; journal commits balance = {} at block digest 0x{}",
        prove_start.elapsed(),
        journal.balance,
        hex::encode(journal.commitment.digest)
    );
    if journal.balance != native_balance {
        return Err("journal balance does not match the native preflight call".into());
    }

    // --- [3] canonicalize: Receipt → canonical inner proof --------------------
    println!("\n[3/5] canonicalize: Receipt → CanonicalInnerProof (re-verifies vs image_id) …");
    let canonical = canonicalize(&receipt, ERC20_BALANCE_ID)?;
    let n_real = canonical.proof.public_inputs.len();
    println!("      ✔ n_real = {n_real}; codegen constants extracted (image_id, control_root, …)");

    // --- [4] wrap: canonical inner proof → BLS12-381 outer proof (gnark) ------
    println!(
        "\n[4/5] wrap: GnarkCliProver::prove → BLS12-381 outer proof (loads the ~1 GB PK ~40s) …"
    );
    let wrap_start = std::time::Instant::now();
    let outer =
        GnarkCliProver::new(&gnark_bin, &setup_dir).prove::<Groth16OuterProof>(&canonical.proof)?;
    println!(
        "      ✔ outer proof in {:?}: backend={}, num_inputs={}, inner_vk_hash={}",
        wrap_start.elapsed(),
        outer.backend(),
        outer.num_inputs(),
        outer.inner_vk_hash()
    );

    // --- [5] build_validator: generate the Aiken project + aiken check --------
    println!("\n[5/5] build_validator: generate Aiken validator project, then `aiken check` …");
    let vk_json = std::fs::read_to_string(setup_dir.join("outer_vk.json"))?;
    let project = build_validator(&Risc0ValidatorRequest {
        receipt: &receipt,
        canonical: &canonical,
        outer_proof: &outer,
        outer_vk_json: &vk_json,
        project_name: "zkwrap/steel_erc20",
    })?;

    let out_dir = manifest_path("generated/steel-verifier");
    let _ = std::fs::remove_dir_all(&out_dir);
    project.write_to(&out_dir)?;
    println!("      ✔ project written to {}", out_dir.display());

    aiken_check(&out_dir)
}

/// Steel preflight: execute the view call against the RPC once natively to
/// discover the accessed state, then package `EvmInput` (block header + MPT
/// storage proofs) for RPC-free execution inside the guest.
async fn preflight(
    rpc_url: Url,
    token: Address,
    account: Address,
) -> anyhow::Result<(EthEvmInput, alloy_primitives::U256)> {
    let mut env = EthEvmEnv::builder()
        .rpc(rpc_url)
        .chain_spec(&ETH_SEPOLIA_CHAIN_SPEC)
        .build()
        .await?;

    let mut contract = Contract::preflight(token, &mut env);
    let balance = contract
        .call_builder(&IERC20::balanceOfCall { account })
        .call()
        .await?;

    let input = env.into_input().await?;
    Ok((input, balance))
}

/// Run `aiken check` in the generated project to validate the live proof against
/// the validator logic. If `aiken` isn't on PATH, print install guidance and
/// skip (the proof + project are still produced).
fn aiken_check(out_dir: &Path) -> Result<(), Error> {
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
    let status = Command::new(&aiken).arg("check").current_dir(out_dir).status()?;
    if !status.success() {
        return Err("aiken check failed (see the report above)".into());
    }
    println!(
        "\n✅ aiken check passed — the Ethereum state fact verifies on Cardano's validator logic."
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

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// `ETH_RPC_URL` — a Sepolia RPC endpoint supporting `eth_getProof`.
fn resolve_rpc_url() -> Result<Url, Error> {
    let Ok(raw) = std::env::var("ETH_RPC_URL") else {
        return Err("ETH_RPC_URL not set. Point it at a Sepolia RPC that supports \
                    eth_getProof, e.g.:\n    \
                    export ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com"
            .into());
    };
    Ok(raw.parse()?)
}

/// `ZKWRAP_GNARK_BIN` if set, else `zkwrap-gnark` on PATH.
fn resolve_gnark_bin() -> Result<PathBuf, Error> {
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
fn resolve_setup_dir() -> Result<PathBuf, Error> {
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
