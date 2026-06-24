//! The off-chain pipeline's outer-prover driver.
//!
//! Decouples "produce the outer proof" from "how the outer prover is invoked"
//! behind the [`Prover`] trait. The first and only backend so far is
//! [`GnarkCliProver`], which spawns the one-shot `zkwrap-gnark prove` binary
//! over the file-based boundary: it writes the canonical inner proof to a temp
//! directory, runs the prover, and reads back the outer proof.
//!
//! ```ignore
//! let prover = GnarkCliProver::new("/path/to/zkwrap-gnark", "fixtures/groth16-setup");
//! let outer = prover.prove(&canonical.proof)?;
//! ```

mod gnark_cli_prover;
mod utils;

pub use gnark_cli_prover::GnarkCliProver;

use std::path::PathBuf;

use thiserror::Error;
use zkwrap_core::{CanonicalInnerProof, OuterParseError, OuterProof};

/// Produces a BLS12-381 outer proof from a canonical inner proof. The trait
/// names only `zkwrap-core` types so backends are swappable without
/// touching `canonicalize` or codegen.
pub trait Prover {
    fn prove<P: OuterProof>(&self, inner: &CanonicalInnerProof) -> Result<P, ProveError>;
}

/// Why an outer-proof attempt failed. Shared across backends — the trait's
/// error contract — though some variants are specific to the CLI backend.
#[derive(Debug, Error)]
pub enum ProveError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("spawn {}: {source}", .bin.display())]
    Spawn {
        bin: PathBuf,
        source: std::io::Error,
    },
    #[error("zkwrap-gnark prove failed (exit status {status:?}): {stderr}")]
    GnarkFailed { status: Option<i32>, stderr: String },
    #[error("parse outer proof: {0}")]
    Parse(#[from] OuterParseError),
}
