//! The RISC Zero plugin, split along the two plugin halves:
//!
//! - [`codegen`] — the inner-layer half: implements
//!   [`zkwrap_core::InnerCodegen`] ([`Risc0Codegen`]), turning the canonical
//!   inner proof's `meta.json.codegen` section into the wiring the Composer
//!   bakes into `validators/verify.ak`.
//! - [`canonicalize`] — the serializer half: native RISC Zero `Receipt` →
//!   canonical inner proof + `meta.json` (the bundle `zkwrap-gnark` consumes).
//!
//! On top of those, [`validator`] is the host-facing factory: one call
//! ([`build_validator`]) turns a receipt + canonical bundle + outer proof into a
//! ready-to-`aiken check` project, hiding `compose` and the Aiken test suite.

pub mod canonicalize;
pub mod codegen;
pub mod validator;

pub use canonicalize::canonicalize;
pub use zkwrap_core::{Canonicalized, ReadBundleError};
pub use codegen::Risc0Codegen;
pub use validator::{build_validator, BuildValidatorError, Risc0ValidatorRequest};

/// `system_id` matching the canonical inner proof's `meta.json`. Shared by both
/// plugin halves: the codegen keys on it; the serializer will stamp it.
pub const SYSTEM_ID: &str = "risc0-v3";
