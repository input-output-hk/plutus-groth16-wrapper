//! The SP1 plugin, split along the two plugin halves:
//!
//! - [`codegen`] — the inner-layer half: implements
//!   [`zkwrap_core::InnerCodegen`] ([`Sp1Codegen`]), turning the canonical inner
//!   proof's `meta.json.codegen` section into the wiring the Composer bakes into
//!   `validators/verify.ak`.
//! - [`canonicalize`] — the serializer half: SP1 Groth16 artifacts (raw seal,
//!   public values, program vkey hash) → canonical inner proof + `meta.json`.
//!
//! On top of those, [`validator`] is the host-facing factory: one call
//! ([`build_validator`]) turns a canonical bundle + outer proof into a
//! ready-to-`aiken check` project.
//!
//! ## SP1 inner axis (circuit v6.1.0)
//!
//! - `n_real = 5`:
//!   `[vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce]`.
//!   - `vkey_hash` (program identity, baked like RISC Zero's `image_id`),
//!     `exit_code` (baked; 0 = success) and `vk_root` (baked SP1-version
//!     constant) are version/program constants.
//!   - `committed_values_digest = SHA256(public_values)` reduced to BN254 Fr is
//!     derived on-chain; `proof_nonce` is per-proof and rides in the redeemer.
//! - The inner Groth16 VK is fixed for SP1 circuit version v6.1.0; the canonical
//!   form is baked into this crate (see [`canonicalize`]).
//!
//! ## sp1-sdk feature
//!
//! The core [`canonicalize`] takes raw artifact bytes and pulls in no SP1
//! dependency, so it builds in the default workspace. With the `sp1-sdk`
//! feature, [`canonicalize_proof`] accepts SP1's native
//! `SP1ProofWithPublicValues` / `SP1VerifyingKey` for seemless integration.

pub mod canonicalize;
pub mod codegen;
pub mod validator;

pub use canonicalize::{canonicalize, CanonicalizeError, Canonicalized};
pub use codegen::Sp1Codegen;
pub use validator::{build_validator, BuildValidatorError, Sp1ValidatorRequest};

#[cfg(feature = "sp1-sdk")]
pub use canonicalize::canonicalize_proof;

/// `system_id` matching the canonical inner proof's `meta.json`. Shared by both
/// plugin halves: the codegen keys on it; the serializer stamps it.
pub const SYSTEM_ID: &str = "sp1-v6";
