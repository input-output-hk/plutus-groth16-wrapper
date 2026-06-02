# Poseidon2 over BLS12-381 Fr for `InnerVKHash`

The in-circuit hash that produces `InnerVKHash` (ADR-0001) is **Poseidon2** over the **BLS12-381 scalar field**, using gnark-crypto's default parameters and the **Merkle-Damgard** mode with an all-zero initial state.

| | Value |
|---|---|
| Library | `gnark-crypto/ecc/bls12-381/fr/poseidon2` (off-circuit) and `gnark/std/permutation/poseidon2` + `gnark/std/hash` (in-circuit) |
| Width `t` | 2 |
| Full rounds `R_F` | 6 |
| Partial rounds `R_P` | 50 |
| sBox degree | 5 |
| Construction | Merkle-Damgard, `IV = 0` (block-sized) |
| Block | one BLS12-381 Fr element (32 bytes) |

The in-circuit construction is `poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)` wrapped by `hash.NewMerkleDamgardHasher(api, perm, 0)`. The off-circuit construction is `poseidonbls.NewMerkleDamgardHasher()`, which calls `GetDefaultParameters()` and yields the same `(2, 6, 50)` parameters.

## Why this choice

**Native arithmetic over BLS12-381 Fr.** The wrapper circuit's native field *is* BLS12-381 Fr. A hash over that field is the cheapest possible in-circuit — every other family (SHA-2, Blake, Keccak, MiMC over a different field) would be either much more expensive in constraints or require non-native arithmetic.

**Cardano never executes Poseidon.** The Aiken validator only checks `proof_signal[0] == hardcoded_constant`; it never recomputes the hash on-chain. So the choice optimises purely for in-circuit cost and library availability, with no on-chain implementation constraint.

**Poseidon2 over Poseidon-1.** Poseidon2 is the newer variant (eprint 2023/323) with a sparser internal matrix that reduces partial-round cost. gnark exposes both, but Poseidon-1 in gnark only has reference parameters for a smaller set of curves; Poseidon2 has a packaged BLS12-381 implementation with matching in-circuit and off-circuit code paths, which eliminates a category of soundness bug.

**Default parameters from `GetDefaultParameters()`.** Round counts (`R_F=6, R_P=50`) and sBox degree (`d=5`) for BLS12-381 Fr come straight from gnark-crypto's reference implementation, which derives them from the standard Poseidon2 security analysis. Choosing custom parameters would invalidate the security argument without measurable benefit.

**Merkle-Damgard, not sponge.** The MD construction with width 2 uses the permutation as a 2-to-1 compressor and chains it over the input. gnark-crypto and gnark both ship the same MD wrapper; both default `IV = 0`. The alternative (sponge with width 3) is also natively supported but yields no benefit at our input size — the inner VK is a fixed-length sequence of limbs, not a variable-length stream, and MD's incremental cost (one permutation per block) is identical at this scale.

**Identical default seeding across in-circuit and off-circuit.** The round-key derivation in both packages is keyed off the same deterministic seed string (`Poseidon2-BLS12_381[t=2,rF=6,rP=50,d=5]`), produced from the same parameters. As long as both call sites use these defaults, the round keys match — no manual round-key transfer needed.

## What gets hashed

The Poseidon2-MD preimage is the gnark-recursive-form inner VK, flattened to a canonical limb sequence:

1. `E` ∈ Gt (precomputed `e(α, β)`) — 12 BN254 Fp elements (`A0..A11`) in the emulated basis used by `sw_bn254.GTEl` (9-twist of native `bn254.GT`; see `sw_bn254.NewGTEl`).
2. `GammaNeg` ∈ G2 — 4 BN254 Fp elements (`X.A0, X.A1, Y.A0, Y.A1`).
3. `DeltaNeg` ∈ G2 — 4 BN254 Fp elements (same order).
4. `IC[0..MAX_INPUTS]` ∈ G1 — 2 BN254 Fp elements per point (`X, Y`), padded with zero G1 points if the inner system's `n_real + 1 < MAX_INPUTS + 1`.

Each BN254 Fp element is decomposed into **4 little-endian 64-bit limbs**, matching `emulated.Element[BN254Fp]`'s native limb layout. Each limb is one block fed to the MD hasher.

Total limb count: 48 (E) + 16 (GammaNeg) + 16 (DeltaNeg) + 8·(MAX_INPUTS + 1) (IC).

This canonical preimage defines the `InnerVKHash` constant baked into a generated Aiken validator.

**Resolved (Phase 3): the codegen does not recompute the hash.** The gnark prover already
emits `inner_vk_hash` in `outer_proof.json` (computed by `circuit.ComputeInnerVKHash`), and
that file is the input fed into Aiken codegen. The Aiken generator therefore **reads
`inner_vk_hash` from the prover output** rather than recomputing it — gnark is the single
source of truth, which avoids a second production implementation of the same constant having
to agree with the in-circuit hash forever.

A pure-Rust Poseidon2/BLS12-381 implementation does exist at
`zkwrap-rs/zkwrap-core/src/{poseidon2,vk_hash}.rs`, but **only as a cross-check**: it
independently reproduces the constant so a regression test can detect a *silent change in
`gnark-crypto`'s Poseidon2* (e.g. a parameter, round-constant, or MDS revision in a future
version bump) that would otherwise quietly shift every baked `InnerVKHash`. It is verified
limb-for-limb against the gnark reference via `testdata/inner_vk_hash_vectors.json` (dumped by
`go test ./internal/circuit -run TestDumpVKHashVectors -dump-vectors`). It is not on the
codegen path.

## What this locks in

Once the plugin embeds a hardcoded `InnerVKHash` constant in any generated Aiken validator, the entire preimage definition — basis transformation of E, limb order, endianness, padding convention, Poseidon2 parameters — becomes load-bearing. Any change requires regenerating every deployed validator's constant and any committed fixtures. The wrapper circuit itself is also bound: a different MD `IV` or a different round count would require a fresh trusted setup.

Changes to the **inner VK layout** (e.g., a new field added to the canonical inner proof) ripple through both the in-circuit hash and the plugin's off-chain hash computation, and must be coordinated.

## Risks not addressed

**No fresh security argument for the parameters.** We use gnark-crypto's defaults without independent review. If the upstream parameters are revised (e.g., to address a future cryptanalysis result), we re-evaluate.

**Silent `gnark-crypto` Poseidon2 drift.** Because the baked `InnerVKHash` comes from gnark
(see "What gets hashed"), a future `gnark-crypto` version that revised the Poseidon2
parameters, round constants, or MDS would silently change every generated constant. This is
mitigated — not eliminated — by the independent Rust cross-check in `zkwrap-core::vk_hash`,
which round-trips against a pinned gnark-dumped fixture (`inner_vk_hash_vectors.json`) for the
real RISC Zero Phase 1 VK. If gnark drifts, regenerating the fixture makes the Rust test fail,
flagging the change before it reaches a deployed validator. The fixture must be regenerated
deliberately, never blindly, on any `gnark-crypto` bump.
