//! The two-axis codegen interface.
//!
//! A generated Aiken validator is composed along two independent, pluggable
//! axes: the **outer layer** — the proving engine (keyed by outer-backend id) —
//! and the **inner layer** — the inner-system scaffolding (keyed by
//! `system_id`). The [`Composer`](crate::codegen::composer) stitches one of
//! each into a project.
//!
//! Both traits return **structured data**, never Aiken source blobs (except
//! the vendored inner-layer `.ak`, which is constant-free and generic). The
//! Composer owns all Aiken string assembly, so a plugin cannot emit malformed
//! glue.
//!
//! ## The outer-layer ABI the Composer assembles against
//!
//! Every [`OuterCodegen`]'s rendered outer layer exposes a single entry point
//! with the universal shape
//!
//! ```aiken
//! pub fn verify(<proof_params…>, inner_vk_hash: Int, inputs: List<Int>) -> Bool
//! ```
//!
//! where `<proof_params…>` is [`OuterCodegen::proof_params`] (each `ByteArray`)
//! and `inputs` is the **`MAX_INPUTS`-length** public-input vector.
//!
//! ## The inner-layer → outer-layer seam
//!
//! The inner layer produces a `List<Int>` of `n_real` real inputs and knows
//! nothing of the outer public-input layout (`inner_vk_hash`, `MAX_INPUTS`,
//! padding, the commitment, or the outer backend). The Composer materializes
//! the expansion at the `validators/verify.ak` call site: it length-pins the
//! `n_real` list and pads to `MAX_INPUTS` with **literal zeros**

pub mod composer;

use serde_json::Value;

#[derive(Debug)]
pub enum CodegenError {
    /// A required field was missing or malformed in the meta.json `codegen` section.
    Meta(String),
    /// The backend's VK artifact (`outer_vk.json`) was malformed or did not
    /// match the selected backend.
    Artifact(String),
    /// Template rendering failed.
    Render(String),
}

impl std::fmt::Display for CodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodegenError::Meta(s) => write!(f, "meta.json codegen: {s}"),
            CodegenError::Artifact(s) => write!(f, "vk artifact: {s}"),
            CodegenError::Render(s) => write!(f, "render: {s}"),
        }
    }
}

impl std::error::Error for CodegenError {}

/// A redeemer-side parameter the generated entry point must accept and forward
/// into an inner-layer call (e.g. RISC Zero's `journal_bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawParam {
    pub name: String,
    pub ty:   String,
}

impl RawParam {
    pub fn new(name: impl Into<String>, ty: impl Into<String>) -> Self {
        RawParam { name: name.into(), ty: ty.into() }
    }
}

/// Data an inner-layer plugin contributes to `validators/verify.ak`.
///
/// The plugin returns data only; the Composer turns it into Aiken source.
#[derive(Debug, Clone)]
pub struct InnerWiring {
    /// Full `const <name>: <ty> = <value>` Aiken lines holding app/inner-binding
    /// values (baked here so promoting one to a redeemer field is a one-line
    /// edit at the call site).
    pub consts:     Vec<String>,
    /// Redeemer-side inputs the generated entry must accept and pass through to
    /// [`InnerWiring::call_expr`].
    pub raw_params: Vec<RawParam>,
    /// The expression producing the `List<Int>` of `n_real` real inputs, e.g.
    /// `risc0.real_inputs(journal_bytes, control_root_0, …)`.
    pub call_expr:  String,
}

/// Deploy-time plugin trait: contribute the inner layer (inner-system
/// scaffolding that derives the `n_real` real inner public inputs).
pub trait InnerCodegen {
    /// Keys the inner layer; matches the canonical inner proof's `meta.json` `system_id`.
    fn system_id(&self) -> &str;
    /// Number of real inputs the inner layer produces. Must equal the length
    /// of the list returned by [`InnerWiring::call_expr`].
    fn n_real(&self) -> usize;
    /// Aiken module basename for the vendored inner-layer source (e.g. `"risc0"`),
    /// placed at `lib/zkwrap/<module_name>.ak`.
    fn module_name(&self) -> &str;
    /// The generic, constant-free inner-layer source, vendored verbatim
    /// (via `include_str!`). Takes app-binding values as parameters.
    fn module_source(&self) -> &'static str;
    /// Per-guest wiring derived from the canonical inner proof's
    /// `meta.json.codegen` section (opaque to the prover binary).
    fn wiring(&self, codegen: &Value) -> Result<InnerWiring, CodegenError>;
}

/// What an outer-layer backend contributes to the project:
/// the rendered verifier source plus the one VK fact the
/// Composer's ABI needs. The backend owns its artifact type; the engine sees
/// only this engine-owned struct.
#[derive(Debug, Clone)]
pub struct OuterWiring {
    /// Rendered `lib/zkwrap/<module_name>.ak` with the outer VK baked into
    /// `verify`.
    pub source:     String,
    /// `MAX_INPUTS` baked at circuit setup — the public-input vector length 
    pub max_inputs: usize,
}

/// Deploy-time plugin trait: the outer layer — the proving engine — keyed by
/// outer-backend id.
pub trait OuterCodegen {
    /// Keys the outer layer; matches `outer_vk.json` / `outer_proof.json` `backend`.
    fn backend_id(&self) -> &str;
    /// Aiken module basename for the rendered outer layer (e.g. `"groth16"`),
    /// placed at `lib/zkwrap/<module_name>.ak`.
    fn module_name(&self) -> &str;
    /// Proof-side parameters of the outer-layer `verify`, in order (each `ByteArray`),
    /// that the generated entry forwards before `inner_vk_hash` and the inputs
    /// list. See the [module-level outer-layer ABI](self).
    fn proof_params(&self) -> &'static [&'static str];
    /// Parse and validate the backend's own VK artifact (`outer_vk.json` text)
    /// and render the outer layer with the setup-bound crypto (outer VK points)
    /// baked directly into `verify`. The backend owns artifact parsing and the
    /// `backend`-id check; the engine stays free of any concrete VK type.
    fn render(&self, vk_json: &str) -> Result<OuterWiring, CodegenError>;
}
