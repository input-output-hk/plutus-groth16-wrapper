//! The RISC Zero plugin, split along the two plugin halves:
//!
//! - [`codegen`] — the inner-layer half: implements
//!   [`zkwrap_core::InnerCodegen`] ([`Risc0Codegen`]), turning the canonical
//!   inner proof's `meta.json.codegen` section into the wiring the Composer
//!   bakes into `validators/verify.ak`.
//! - [`canonicalize`] — the serializer half: native RISC Zero `Receipt` →
//!   canonical inner proof + `meta.json` (the bundle `zkwrap-gnark` consumes).

pub mod canonicalize;
pub mod codegen;

pub use canonicalize::{canonicalize, Canonicalized};
pub use codegen::Risc0Codegen;

/// `system_id` matching the canonical inner proof's `meta.json`. Shared by both
/// plugin halves: the codegen keys on it; the serializer will stamp it.
pub const SYSTEM_ID: &str = "risc0-v3";
