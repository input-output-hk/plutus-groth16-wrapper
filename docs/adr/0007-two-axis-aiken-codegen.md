# Two-axis Aiken codegen: pluggable proving engine × inner system

**Status:** accepted. Supersedes [ADR-0004 (Rust plugin owns Aiken codegen)](0004-rust-plugin-owns-aiken-codegen.md), which assumed the inner-system plugin owns the whole validator template.

The generated Aiken validator is composed along **two independent axes**, each pluggable by the same mechanism:

- **Outer layer — the proving engine** (chosen by *outer backend*): the generic, inner-system-agnostic on-chain proof verifier. Groth16/BLS12-381 today; PLONK/BLS12-381 later. Owns pairing checks, IC accumulation, the Pedersen/commitment handling, and the public-input **expansion convention** (prepend `InnerVKHash`, pad to `MAX_INPUTS`, fold any commitment input).
- **Inner layer — the inner-system scaffolding** (chosen by `system_id`): derives the `n_real` real inner public inputs from the redeemer's inner artifact. RISC Zero's journal-authentication chain producing 5 inputs; SP1's single SHA-256 producing 2; etc.

A **Composer** in Rust stitches one outer layer + one inner layer into a generated Aiken **project**. The matrix `{Groth16, PLONK, …} × {RISC Zero, SP1, …}` is assembled from `m + n` fragments, not `m × n` hand-written validators.

## The seam between layers

**Inner layer → `List<Int>` of `n_real` real inputs → outer layer.** One-way and minimal. The inner layer knows nothing of the outer public-input layout — not `InnerVKHash`, `MAX_INPUTS`, padding, the commitment, or the outer backend. The outer layer takes the real inputs as opaque field elements and applies its own expansion. This works because every proof system verifies a statement against a public-input vector of field elements — that is the universal interface that keeps the two axes orthogonal.

This mirrors the snarkjs Aiken verifier (`templates/verifier_groth16.ak.ejs`), whose `verify(pi_a, pi_b, pi_c, public_signals: List<Int>)` is exactly the outer-layer entry point. Plain snarkjs has no inner layer because it has no inner-system-wrapping concept; the inner layer is the new axis we add on top.

## Two kinds of constant, handled by why they exist

Instance-specific values split into two categories, baked in different places:

- **Setup-bound crypto** — outer VK points, Pedersen commitment keys. They come from the trusted setup and can *never* depend on application logic or the redeemer. They are **baked directly into the outer-layer `verify`** (the Composer renders the outer layer with them filled in, snarkjs-style), never exposed as parameters. Exposing them would be pointless plumbing and would blur the verifier's fixed cryptographic identity.
- **Inner/app-binding** — `InnerVKHash`, RISC Zero `image_id` / `control_root` / per-guest digests. They identify which inner system/program and *may* later become redeemer-driven (e.g. "accept any of N allowed programs"). These are **function parameters** of the generic `lib/` logic; only the generated `validators/verify.ak` holds them as baked `const`s and passes them in.

Consequences:
- **The outer layer is rendered** (VK baked into `verify`), so it is not invariant across deployments. **The inner-layer `lib/` logic is invariant** — generic and constant-free, vendored verbatim. Promoting an inner/app-binding constant to a redeemer field is a **one-line edit at the call site** in `validators/verify.ak`, with `lib/` untouched.
- The **policy surface** (which programs/systems are accepted) lives entirely in `validators/verify.ak`; the verifier's **cryptographic identity** (outer VK) is fixed inside the outer layer where app logic cannot reach it.

## Binding granularity: per guest program

A generated validator binds to **one inner system *and* one guest program** — RISC Zero's `pre_state_digest` *is* the guest `image_id`. So it verifies "*my specific* program executed and halted cleanly," not "any RISC Zero proof." Re-deploying for a different guest re-runs codegen with that guest's constants. The program-binding constants (`image_id`, etc.) are baked as named `const`s in `validators/verify.ak` and **passed as parameters** into the generic inner-layer function, per the principle above, so they can later move to the redeemer.

## Where the values come from

- **Outer VK points** — from `outer_vk.json` (the trusted-setup output), crossing the language boundary as **data**, not generated Aiken. Codegen stays uniformly in Rust regardless of which prover (Go gnark, future Rust Halo2) produced the proof.
- **`InnerVKHash`** — read from `outer_proof.json` (gnark is the single source of truth; see [ADR-0005](0005-poseidon2-bls12381-for-inner-vk-hash.md)).
- **Outer-backend identifier** (e.g. `gnark-groth16-bls12381`) — in `outer_vk.json` (authoritative) and echoed in `outer_proof.json`. Keys the Composer's choice of outer layer; lets it cross-check that proof and VK came from the same backend.
- **Per-guest inner-layer constants** — a `codegen` section in the canonical inner proof's `meta.json`, opaque to the prover binary (Go reads only `system_id` + `n_real`). See [canonical-inner-proof.md](../schemas/canonical-inner-proof.md). There is no separate sidecar. On the Rust side this section is a *typed* per-plugin struct, not an opaque blob — see the [typed-codegen refinement](#refinement-typed-codegen).

## Plugin interface (the surface a new system author implements)

Two **structured-data** traits — the Composer owns all Aiken string assembly, so the seam is typed and a plugin cannot emit malformed glue. The static inner-layer logic is a `.ak` file shipped via `include_str!`, not rendered at runtime.

```rust
// Prove-time: native receipt → canonical inner proof bundle (+ meta.json codegen section).
pub trait Canonicalize { /* receipt → CanonicalInnerProof + codegen constants */ }

// Deploy-time: contribute the inner-layer fragment.
pub trait InnerCodegen {
    fn system_id(&self) -> &str;                       // keys the inner layer; matches meta.json
    fn n_real(&self) -> usize;                         // length the inner layer must produce
    fn module_source(&self) -> &'static str;           // include_str!("…/risc0.ak")
}
```

The per-guest *wiring* (const lines + call expr) is **not** a trait method — see the [typed-codegen refinement](#refinement-typed-codegen) below.

A symmetric trait makes the proving engine pluggable on the same mechanism:

```rust
pub trait OuterCodegen {
    fn backend_id(&self) -> &str;                      // keys the outer layer; matches outer_vk.json
    fn render(&self, vk_json: &str) -> OuterWiring;    // parses its own VK; bakes consts into verify
}
```

(The outer layer is *rendered* — the outer VK and commitment keys are baked into its `verify` — so its trait yields rendered source (`OuterWiring`), unlike the inner layer whose `module_source` is vendored verbatim and takes app-binding values as parameters. The backend parses its own VK artifact from the raw `outer_vk.json` text, so the engine names no concrete VK type.)

The Composer knows **only the two traits**: it resolves `backend_id → impl OuterCodegen` and `system_id → impl InnerCodegen`, asks the backend to render the outer layer (VK baked) and the plugin for its vendored inner-layer source + wiring, and assembles the project. No per-backend or per-system knowledge in the Composer.

Adding a system = new plugin crate impl `Canonicalize` + `InnerCodegen` + one `.ak` file. Adding a backend = new crate impl `OuterCodegen` + one `.ak` file. Neither touches the Composer, the other axis, or the Go prover.

## Refinement (typed codegen)

*Refines the mechanics below; the two-axis decision, the seam, and the meta.json placement are unchanged.*

The original sketch had `InnerCodegen::wiring(&self, codegen: &serde_json::Value) -> InnerWiring` — the per-guest constants travelled as an **opaque JSON blob** and each plugin parsed it by hand (`get`/`as_str`/`hex::decode`, per field). That is a stringly-typed seam with no compile-time schema. Refined to:

- **Typed per-plugin codegen.** Each plugin defines a serde struct for its constants (`Risc0CodegenData`, `Sp1CodegenData`) whose fields are validated at deserialize (32-byte hex via the shared `zkwrap_core::Hex32`). The struct *owns* its `wiring(&self) -> InnerWiring` — the logic moved off the trait onto the data.
- **Generic bundle in core.** `Canonicalized` becomes `zkwrap_core::CanonicalBundle<C>` — the system-agnostic `CanonicalInnerProof` plus typed `codegen: C`. Core never names a plugin's codegen type; `write_to`/`read_from` (de)serialize `C` via serde, with `C` nested under `meta.json`'s `codegen` key exactly as before (still prover-opaque; Go still reads only `system_id` + `n_real`).
- **`InnerCodegen` loses `wiring`.** It keeps only the static facts (`system_id`, `n_real`, `module_name`, `module_source`). The Composer's `ComposeRequest` takes a ready-made `&InnerWiring` (computed by the plugin's `build_validator` from its typed codegen), so `serde_json::Value` is gone from the codegen path and `compose` stays object-safe.

Net: the per-guest schema is explicit and compile-checked, hex/length errors surface at deserialize, and the plugin interface for a new system is `Canonicalize` + `InnerCodegen` (static) + a serde codegen struct with a `wiring()` method.

## Output artifact

A full, ready-to-`aiken check` **project**, not a bare file:

```
out/
├── aiken.toml                 (static)
├── lib/zkwrap/
│   ├── groth16.ak             Outer layer — rendered: outer VK + commitment keys baked into verify
│   └── risc0.ak               Inner layer — vendored verbatim, generic, constant-free
├── validators/verify.ak       generated: app/inner-binding const block + wiring of inner layer → outer layer
└── test/                      (optional) generated smoke test with a fixture
```

## Crate layout

```
zkwrap-core      Composer + OuterCodegen & InnerCodegen traits + Outer/InnerWiring
                 types + OuterVk parsing + vk_hash (existing). The outer layer (Groth16)
                 lives here for now, in its own module; extract to a dedicated
                 zkwrap-groth16 crate when a second backend (PLONK) lands.
zkwrap-risc0     impl Canonicalize + InnerCodegen; ships risc0.ak
zkwrap-sp1       impl Canonicalize + InnerCodegen; ships sp1.ak (later)
```

## Considered alternatives

- **Go prover emits the outer-layer `.ak`** alongside `outer_proof.json` (locality: Go holds the outer VK). Rejected: it couples outer-layer codegen to the prover's *language*, which varies (future Rust Halo2 prover), fragmenting codegen across Go and Rust while the Composer is Rust. Instead the outer VK crosses as data and all codegen is Rust.
- **Trait returns Aiken source fragments** (plugin assembles its own glue). Rejected in favour of structured data: a stringly-typed seam re-implemented per plugin, vs. one typed assembly point in the Composer.
- **Outer/inner layers as imported Aiken library packages** (typed cross-package seam). Deferred, not rejected. The inner-layer logic is invariant (generic, constant-free), so vendoring it is byte-identical to a future published package. The outer layer is rendered (VK baked in) so it is not invariant, but its *logic* is — a published outer-layer package would take the VK as data rather than baking it. Adopt only if independent versioning of the verifier libraries becomes worth the Aiken dependency-management friction — likely never necessary.
- **Per-guest constants in the canonical inner proof struct / a separate sidecar.** Rejected: the binary proof contract stays generic (Go-only), and there is already a metadata file (`meta.json`) to carry a system-specific, prover-opaque `codegen` section — no new file, no pollution.

## Consequences

- The seam contract (`<sys>_real_inputs(...) -> List<Int>` feeding the outer layer's `verify(...)`) is enforced only at output-compile time, not across an Aiken package boundary by the type system. Acceptable at small matrix size; revisit if the matrix grows.
- `n_real` / `MAX_INPUTS` are baked as the *shape* of the generated `validators/verify.ak` (literal padding zeros, a length-pinning `expect`), not as runtime constants. The literal zeros double as ADR-0002's mandatory excess-zero enforcement, for free.
