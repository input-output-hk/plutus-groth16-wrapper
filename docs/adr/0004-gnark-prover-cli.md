# `zkwrap-gnark` CLI shape and artifact formats

The Go gnark prover binary exposes three subcommands — `unsafe-setup`, `prove`, `verify` — and a small set of file artifacts that form the contract between this binary, the Rust plugins, and downstream Aiken codegen.

```
zkwrap-gnark unsafe-setup --max-inputs N --out <setup-dir>
zkwrap-gnark prove        --inner <inner-proof-dir> --setup <setup-dir> --out <outer-proof.json>
zkwrap-gnark verify       --proof <outer-proof.json> --setup <setup-dir>
```

`unsafe-setup` writes three files to `<setup-dir>`: `outer_pk.bin` (gnark native proving key), `outer_vk.json` (field-by-field compressed-hex BLS12-381 verifying key), and `circuit.r1cs` (gnark native compiled R1CS). `prove` and `verify` read this directory as a bundle. `prove` emits a single `outer_proof.json` containing the BLS12-381 proof (`ar`, `bs`, `krs` as compressed hex), the `inner_vk_hash`, and the padded `inputs[]`. Byte layouts live in [docs/schemas/outer-proof-artifacts.md](../schemas/outer-proof-artifacts.md).

## Why these decisions

**Three subcommands rather than one.** Trusted setup is a one-time-per-`MAX_INPUTS` ceremony that takes minutes and produces hundreds of megabytes; per-proof proving is a recurring sub-second-to-minutes operation. Bundling them into one invocation would obscure the ceremony boundary. `verify` is included for off-chain round-tripping (Phase 2 step 4) — it is intentionally minimal: outer Groth16 verify only, no soundness checks (those are the Aiken validator's job per ADR-0002).

**`unsafe-setup`, not `setup`.** gnark's `groth16.Setup(ccs)` uses insecure local randomness. A real ceremony for production deployment would use an MPC protocol and is out of scope for this binary. The `unsafe-` prefix makes the distinction visible at the CLI rather than hiding it behind a manual or a flag.

**JSON for verifying key, JSON envelope for proof + public inputs.** The plugin's Aiken codegen function generates Aiken source by inlining compressed BLS12-381 points as hex literals (`#"…"`, CIP-57 syntax). Field-by-field JSON makes this a template substitution — no binary parsing in the plugin. The proof and its public inputs are combined into a single `outer_proof.json` because they are always consumed together; splitting them invites drift between proof and inputs and forces consumers to track two filenames. Hex overhead is negligible at this size.

**gnark native binary for proving key and R1CS.** Only `zkwrap-gnark prove` reads these; no plugin or Aiken consumer cares about their internal layout. The proving key is large (hundreds of MB) and re-deriving the R1CS at every prove call would waste tens of seconds to minutes — saving both during setup is straightforward via gnark's `WriteRawTo` / `WriteTo`.

**`MAX_INPUTS` is a flag only on `unsafe-setup`.** It is baked into both `outer_pk.bin` and `circuit.r1cs`. `prove` and `verify` read it from the loaded artifacts (and cross-check against `outer_vk.json`); passing `--max-inputs` to those subcommands is treated as a usage error.

**`inner_vk_hash` in the JSON, not `vk_hash`.** The codebase has both inner and outer verifying keys. The bare term is ambiguous; the prefixed term is not. The glossary in `CONTEXT.md` was renamed from `VKHash` to `InnerVKHash` for the same reason.

**Compressed BLS12-381 throughout the outer artifacts.** Cardano's Plutus builtins (`bls12_381_G1_uncompress`, etc.) consume the zcash-flavored compressed encoding directly. The canonical *inner* proof remains uncompressed because its audience is gnark's `SetBytes()` inside the wrapper circuit — different consumer, different encoding.

**No positional arguments, named flags throughout. Stderr for human output, stdout silent. Exit codes `0` / `1` / `2` (success / operational failure / misuse). `--out` overwrites silently.** Operational conventions chosen for predictable scripting; no `--force` guard because the iteration cost of accidental overwrite is bounded (re-run setup, re-run prove).

## What this locks in

Once `zkwrap-risc0` / `zkwrap-sp1` plugins generate Aiken validators by parsing `outer_vk.json` and embedding hex from `outer_proof.json` fixtures, the JSON schemas become load-bearing. Changes after that point require coordinated updates across the gnark binary, every plugin, every generated Aiken validator, and any committed test fixtures. The CLI flag names and exit-code conventions are softer — they can evolve with deprecation if needed.
