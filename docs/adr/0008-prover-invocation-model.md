# Outer-prover invocation: pluggable `Prover`, persistent service to amortize proving-key load

**Status:** **Partially implemented.** The `Prover` trait and the one-shot `CliProver` are **implemented** — shipped as `GnarkCliProver` in the `zkwrap-prover` crate (it writes the canonical inner proof to a temp dir and spawns `zkwrap-gnark prove`, paying the PK-load cost per call as described below). The persistent `ServiceProver` remains **proposed / unbuilt**; the open questions at the end still stand for it. [ADR-0003 (file-based plugin↔prover boundary)](0003-file-based-plugin-prover-boundary.md) and [ADR-0004 (gnark prover CLI)](0004-gnark-prover-cli.md) **remain in force** — the file-based one-shot path is now the live default via `GnarkCliProver`.

## Context

The off-chain pipeline is: host (Rust) → `canonicalize` (Rust plugin) → **outer prover** (gnark, Go) → outer proof → Aiken codegen. Today the host↔prover boundary is **file-based** (ADR-0003): the plugin writes the canonical inner proof to a directory and the one-shot `zkwrap-gnark prove` binary (ADR-0004) reads it, loads the proving key, proves, and writes the outer proof.

**The bottleneck is proving-key load, not proving.** Reading the ~1.1 GB outer proving key from disk takes **~40 s**, while the proof itself takes **~7 s**. A fresh `prove` process reloads the PK on every invocation, so any workflow that proves more than once pays the 40 s tax repeatedly. Neither the file boundary nor an in-memory pipe fixes this — a freshly spawned process reloads the PK regardless of how the *inner proof* arrives. Only a **persistent process that loads the PK once** amortizes it.

We want, in time: (a) amortized PK load, (b) ergonomic host invocation (import-and-call, mirroring `risc0-ethereum`), and (c) optionally no disk round-trip. We will implement the simple one-shot path first, but want the design to be forward-compatible with a persistent service so we don't have to unpick it later.

## Decision (preliminary)

1. **A Rust `Prover` abstraction** decouples "produce the outer proof" from "how the outer prover is invoked":
   ```rust
   trait Prover {
       fn prove(&self, inner: &CanonicalInnerProof) -> Result<OuterProof, ProveError>;
   }
   ```
   It names only `zkwrap-core` types (`CanonicalInnerProof` in, `OuterProof`/bytes out).

2. **Pluggable backends:**
   - `CliProver` — spawns the one-shot `zkwrap-gnark` (current behavior; pays the PK tax per call). The dev/test default.
   - `ServiceProver` — talks to a **long-running prover** that loads the PK once into memory and serves many requests. The performance path.

3. **The PK and VK stay server-side.** The client ships only the canonical inner proof and receives the outer proof; the ~1.1 GB key is never sent over a wire. The service is configured with which circuit/PK it holds.

4. **Transport-neutral serialization.** The canonical inner proof's serialized bytes *are* the request payload — the same bytes that `write_to(dir)` persists. So `canonicalize` stays **I/O-free** (`Receipt → CanonicalInnerProof`), serialization is decoupled from persistence, and disk vs. RPC is just a choice of transport over identical bytes.

5. **Placement.** The `Prover` trait and its impls live in a dedicated orchestration/driver crate (working name `zkwrap-prover`), **not** in `zkwrap-core`. Rationale: a trait belongs with its consumer, and the consumer is the off-chain pipeline driver, not core (core never proves); and the impls need `std::process` / a network client, which must stay out of the pure codegen+contracts crate. Core continues to own only the data types.

6. **Relationship to ADR-0003.** This *evolves* the file boundary rather than abandoning it: the file/CLI path stays valid as a `CliProver` backend; the service is added alongside. If/when the service is adopted as the default, this ADR may supersede parts of ADR-0003.

## Considered alternatives

- **One-shot CLI only (status quo).** Simplest, already works. Rejected as the end state: 40 s PK load on every proof.
- **stdin-pipe to a one-shot subprocess.** Avoids a temp file for the inner proof, but the subprocess still reloads the PK each call — does **not** address the bottleneck. Useful only as a no-disk transport, not a performance fix.
- **Long-lived subprocess "daemon" over stdio.** Loads the PK once; simpler than a network service (no sockets/auth). A strong candidate `ServiceProver` transport for local single-host use.
- **Networked service (HTTP/gRPC).** Loads the PK once and enables remote/shared/scaled proving; costs lifecycle, concurrency, and a trust/auth model.
- **Attack the load cost directly** (mmap the PK, lazier/faster deserialization). Orthogonal — could complement either model; doesn't remove the need for persistence if proving repeatedly.
- **In-process via CGO/FFI** (Rust calls gnark in the same process). No separate process at all, but heavy and fragile across the Go runtime, and counter to ADR-0003's language-independence rationale. Rejected.

## Consequences

- **Pros:** amortizes PK load (pay ~40 s once, not per proof); the backend is swappable without touching `canonicalize` or codegen; ergonomic import-and-call host API; an in-memory/no-disk path becomes possible; core stays pure.
- **Costs / risks:** a service to run and manage (process lifecycle, concurrency, ~GB of PK resident in RAM); a transport and wire/framing protocol to design and version; a trust/auth model if it's ever networked; more moving parts than a CLI.

## Open questions (this is why it's preliminary)

- Transport: stdio co-process daemon vs. unix socket vs. HTTP vs. gRPC?
- Wire format / framing of the canonical bundle as a single request message (vs. today's four loose files).
- Single-proof vs. batched requests; concurrency model; cancellation/timeouts.
- Service configuration and discovery: which PK/circuit it holds, how the client finds it, local-only vs. networked.
- Do we keep the file-based one-shot CLI as the default for dev/CI even after the service exists?
- How this lands relative to ADR-0003 (supersede vs. coexist) and the Phase-7 CLI/SDK form factor.
