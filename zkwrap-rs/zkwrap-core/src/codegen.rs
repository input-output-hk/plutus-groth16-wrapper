//! The two-axis codegen interface.
//!
//! A generated Aiken validator is composed along two independent, pluggable
//! axes: **Layer 1** the proving engine (keyed by outer-backend id) and
//! **Layer 2** the inner-system scaffolding (keyed by `system_id`). The
//! [`Composer`](crate::codegen::composer) stitches one of each into a project.
//!
//! Both traits return **structured data**, never Aiken source blobs (except
//! the vendored Layer 2 `.ak`, which is constant-free and generic). The
//! Composer owns all Aiken string assembly, so a plugin cannot emit malformed
//! glue.
//!
//! ## The Layer 1 ABI the Composer assembles against
//!
//! Every [`OuterBackend`]'s rendered Layer 1 exposes a single entry point with
//! the universal shape
//!
//! ```aiken
//! pub fn verify(<proof_params…>, inner_vk_hash: Int, inputs: List<Int>) -> Bool
//! ```
//!
//! where `<proof_params…>` is [`OuterBackend::proof_params`] (each `ByteArray`)
//! and `inputs` is the **`MAX_INPUTS`-length** public-input vector. 
//!
//! ## The Layer 2 → Layer 1 seam
//!
//! Layer 2 produces a `List<Int>` of `n_real` real inputs and knows nothing of
//! the outer public-input layout (`inner_vk_hash`, `MAX_INPUTS`, padding, the
//! commitment, or the outer backend). The Composer materializes the expansion
//! at the `validators/verify.ak` call site: it length-pins the `n_real` list
//! and pads to `MAX_INPUTS` with **literal zeros** — which double as ADR-0002's
//! mandatory excess-zero enforcement.

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
/// into a Layer 2 call (e.g. RISC Zero's `journal_bytes`).
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

/// Data a Layer 2 plugin contributes to `validators/verify.ak`.
///
/// The plugin returns data only; the Composer turns it into Aiken source.
#[derive(Debug, Clone)]
pub struct Layer2Wiring {
    /// Full `const <name>: <ty> = <value>` lines holding app/inner-binding
    /// values (baked here so promoting one to a redeemer field is a one-line
    /// edit at the call site — ADR-0007).
    pub consts:     Vec<String>,
    /// Redeemer-side inputs the generated entry must accept and pass through to
    /// [`Layer2Wiring::call_expr`].
    pub raw_params: Vec<RawParam>,
    /// The expression producing the `List<Int>` of `n_real` real inputs, e.g.
    /// `risc0.real_inputs(journal_bytes, control_root_0, …)`.
    pub call_expr:  String,
}

/// Deploy-time plugin trait: contribute the Layer 2 fragment (inner-system
/// scaffolding that derives the `n_real` real inner public inputs).
pub trait Layer2Codegen {
    /// Keys Layer 2; matches the canonical inner proof's `meta.json` `system_id`.
    fn system_id(&self) -> &str;
    /// Number of real inputs the Layer 2 entry produces. Must equal the length
    /// of the list returned by [`Layer2Wiring::call_expr`].
    fn n_real(&self) -> usize;
    /// Aiken module basename for the vendored Layer 2 source (e.g. `"risc0"`),
    /// placed at `lib/zkwrap/<module_name>.ak`.
    fn module_name(&self) -> &str;
    /// The generic, constant-free Layer 2 source, vendored verbatim
    /// (via `include_str!`). Takes app-binding values as parameters.
    fn layer2_source(&self) -> &'static str;
    /// Per-guest wiring derived from the canonical inner proof's
    /// `meta.json.codegen` section (opaque to the prover binary).
    fn layer2_wiring(&self, codegen: &Value) -> Result<Layer2Wiring, CodegenError>;
}

/// What a Layer 1 backend contributes to the project, symmetric to
/// [`Layer2Wiring`]: the rendered verifier source plus the one VK fact the
/// Composer's ABI needs. The backend owns its artifact type; the engine sees
/// only this engine-owned struct.
#[derive(Debug, Clone)]
pub struct Layer1 {
    /// Rendered `lib/zkwrap/<module_name>.ak` with the outer VK baked into
    /// `verify`.
    pub source:     String,
    /// `MAX_INPUTS` baked at circuit setup — the public-input vector length 
    pub max_inputs: usize,
}

/// Deploy-time plugin trait: the proving engine (Layer 1), keyed by
/// outer-backend id. Symmetric to [`Layer2Codegen`].
pub trait OuterBackend {
    /// Keys Layer 1; matches `outer_vk.json` / `outer_proof.json` `backend`.
    fn backend_id(&self) -> &str;
    /// Aiken module basename for the rendered Layer 1 (e.g. `"groth16"`),
    /// placed at `lib/zkwrap/<module_name>.ak`.
    fn module_name(&self) -> &str;
    /// Proof-side parameters of the Layer 1 `verify`, in order (each `ByteArray`),
    /// that the generated entry forwards before `inner_vk_hash` and the inputs
    /// list. See the [module-level Layer 1 ABI](self).
    fn proof_params(&self) -> &'static [&'static str];
    /// Parse and validate the backend's own VK artifact (`outer_vk.json` text)
    /// and render Layer 1 with the setup-bound crypto (outer VK points)
    /// baked directly into `verify`. The backend owns artifact parsing
    /// and the `backend`-id check; the engine stays free of any concrete VK type.
    fn render_layer1(&self, vk_json: &str) -> Result<Layer1, CodegenError>;
}
