//! [`GnarkCliProver`] — the one-shot CLI backend of the [`Prover`](crate::Prover) trait.

use std::path::PathBuf;
use std::process::Command;

use zkwrap_core::{CanonicalInnerProof, OuterProof};

use crate::utils::TempDir;
use crate::{ProveError, Prover};

/// Spawns the one-shot `zkwrap-gnark prove` binary. The proving key and circuit
/// stay server-side in `setup_dir`; only the canonical inner proof bytes are the
/// transport (written to a temp dir, the same bytes `write_to` persists).
pub struct GnarkCliProver {
    gnark_bin: PathBuf,
    setup_dir: PathBuf,
}

impl GnarkCliProver {
    /// `gnark_bin` is the `zkwrap-gnark` executable; `setup_dir` holds
    /// `outer_pk.bin`, `outer_vk.json`, and `circuit.r1cs`.
    pub fn new(gnark_bin: impl Into<PathBuf>, setup_dir: impl Into<PathBuf>) -> Self {
        Self {
            gnark_bin: gnark_bin.into(),
            setup_dir: setup_dir.into(),
        }
    }
}

impl Prover for GnarkCliProver {
    fn prove<P: OuterProof>(&self, inner: &CanonicalInnerProof) -> Result<P, ProveError> {
        let work = TempDir::new().map_err(ProveError::Io)?;
        // The Go prover reads only system_id + n_real from meta.json; the
        // prover-facing `write_to` emits exactly that (no codegen section).
        inner.write_to(work.path()).map_err(ProveError::Io)?;

        let out = work.path().join("outer_proof.json");
        let output = Command::new(&self.gnark_bin)
            .arg("prove")
            .arg("--inner")
            .arg(work.path())
            .arg("--setup")
            .arg(&self.setup_dir)
            .arg("--out")
            .arg(&out)
            .output()
            .map_err(|e| ProveError::Spawn {
                bin: self.gnark_bin.clone(),
                source: e,
            })?;

        if !output.status.success() {
            return Err(ProveError::GnarkFailed {
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        let json = std::fs::read_to_string(&out).map_err(ProveError::Io)?;
        P::from_json(&json).map_err(ProveError::Parse)
    }
}
