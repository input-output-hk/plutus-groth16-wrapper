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

use zkwrap_core::{CanonicalInnerProof, OuterParseError, OuterProof};

/// Produces a BLS12-381 outer proof from a canonical inner proof. The trait
/// names only `zkwrap-core` types so backends are swappable without
/// touching `canonicalize` or codegen.
pub trait Prover {
    fn prove(&self, inner: &CanonicalInnerProof) -> Result<OuterProof, ProveError>;
}

/// Why an outer-proof attempt failed. Shared across backends — the trait's
/// error contract — though some variants are specific to the CLI backend.
#[derive(Debug)]
pub enum ProveError {
    /// Writing the bundle or reading the outer proof failed.
    Io(std::io::Error),
    /// The `zkwrap-gnark` binary could not be spawned (e.g. not found).
    Spawn {
        bin: PathBuf,
        source: std::io::Error,
    },
    /// The prover ran but exited non-zero.
    GnarkFailed { status: Option<i32>, stderr: String },
    /// The prover's `outer_proof.json` could not be parsed.
    Parse(OuterParseError),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProveError::Io(e) => write!(f, "io: {e}"),
            ProveError::Spawn { bin, source } => {
                write!(f, "spawn {}: {source}", bin.display())
            }
            ProveError::GnarkFailed { status, stderr } => match status {
                Some(c) => write!(f, "zkwrap-gnark exited {c}: {stderr}"),
                None => write!(f, "zkwrap-gnark killed by signal: {stderr}"),
            },
            ProveError::Parse(e) => write!(f, "parse outer proof: {e}"),
        }
    }
}

impl std::error::Error for ProveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProveError::Io(e) => Some(e),
            ProveError::Spawn { source, .. } => Some(source),
            ProveError::Parse(e) => Some(e),
            ProveError::GnarkFailed { .. } => None,
        }
    }
}
