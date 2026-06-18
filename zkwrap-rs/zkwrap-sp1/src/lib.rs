//! The SP1 plugin, split along the two plugin halves:
//!
//! - [`codegen`] — the inner-layer half: implements
//!   [`zkwrap_core::InnerCodegen`] ([`Sp1Codegen`]), turning the canonical inner
//!   proof's `meta.json.codegen` section into the wiring the Composer bakes into
//!   `validators/verify.ak`.
//! - [`canonicalize`] — the serializer half: an SP1 native `SP1Proof` +
//!   `public_values` → canonical inner proof + `meta.json`.
//!
//! On top of those, [`validator`] is the host-facing factory: one call
//! ([`build_validator`]) turns a canonical bundle + outer proof into a
//! ready-to-`aiken check` project.

pub mod canonicalize;
pub mod codegen;
pub mod validator;

pub use canonicalize::{canonicalize, CanonicalizeError, Canonicalized};
pub use codegen::Sp1Codegen;
pub use validator::{build_validator, BuildValidatorError, Sp1ValidatorRequest};

/// `system_id` matching the canonical inner proof's `meta.json`. Shared by both
/// plugin halves: the codegen keys on it; the serializer stamps it.
pub const SYSTEM_ID: &str = "sp1-v6";
