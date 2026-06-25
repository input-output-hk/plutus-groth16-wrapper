# PLONK Outer Proof Artifacts

The file artifacts produced and consumed by `zkwrap-gnark` when the outer backend
is **gnark PLONK over BLS12-381** (`--backend plonk`). Sibling to
[outer-proof-artifacts.md](./outer-proof-artifacts.md) (the Groth16 outer
backend); the outer proof system differs, and — unlike Groth16 — there is **no
`MAX_INPUTS` padding** (see next section). The wrapper circuit logic
(`circuit.OuterCircuit`), the public-input *layout*
`[InnerVKHash, input_0, input_1, …]`, the `InnerVKHash` (Poseidon2), and both
inner layers are **untouched**.

Setup writes a co-located bundle (`outer_pk.bin`, `outer_vk.json`,
`circuit.r1cs`); prove writes a single self-contained file (`outer_proof.json`).
Together these form the contract between the gnark prover, the Rust plugins, and
the Aiken PLONK codegen (`plonk.ak`).

See also: [canonical-inner-proof.md](./canonical-inner-proof.md) and the validated
de-risking spike `experiments/aiken-plonk-spike/` (the source of every
transcript/encoding decision below).

**Backend id:** `gnark-plonk-bls12381`.

**Status:** every byte order, point encoding, domain tag, and hash preimage in
this document was pinned and exercised end-to-end by the spike — a real gnark
PLONK/BLS12-381 outer proof (production proof shape: 9 public signals + one BSB22
commitment) verifies on Cardano at **4.82 B cpu / 3.05 M mem** (Plutus V3 limits
10 B / 14 M).

---

## Public-input sizing — exact, no `MAX_INPUTS` padding

The Groth16 backend compiles one universal wrapper circuit with a fixed
`MAX_INPUTS` and zero-pads shorter inner systems ([ADR-0002](../adr/0002-universal-wrapper-circuit.md)).
That padding exists **only** to avoid a separate Groth16 trusted-setup *ceremony*
per inner system. PLONK has no per-circuit ceremony: `plonk.Setup` deterministically
derives the proving/verifying key from a circuit-independent KZG SRS. So the PLONK
backend compiles the wrapper circuit with **exactly the inner system's public-input
count** (`num_inputs = n_real`) and derives the VK from the shared SRS — no padding,
at either the outer public-signal layer or the inner-VK IC layer.

Consequences:

- The PLONK outer VK depends **only on `num_inputs`**, not on the inner system. The
  inner VK is a private circuit witness (`OuterCircuit.VerifyingKey`); only its
  public-input count is fixed at compile time. So two inner systems with the same
  `n_real` (e.g. RISC Zero and SP1 v6, both `n_real = 5`) compile to the same SCS
  and **share the same outer VK**; different `n_real` yields a different VK. The
  generated Aiken validator still differs per system because it bakes that system's
  `inner_vk_hash`, but the underlying PLONK VK (and a single committed `outer_vk.json`
  fixture) can be reused across same-`n_real` systems.
- ADR-0002's padded-slot soundness obligation (the Aiken validator must check
  zero-padded slots, or an adversary forges values there via a padded inner VK)
  **does not apply**: with exact inputs there are no padded slots.
- This is a deliberate divergence from ADR-0002, whose reasoning is Groth16-scoped;
  it warrants its own ADR.

Throughout this document, `num_inputs` denotes the exact inner public-input count
(`= n_real`). The public-input vector is `[InnerVKHash, input_0, …,
input_{num_inputs − 1}]` with **no trailing zero slots**.

---

## Setup-dir layout

```
<setup-dir>/
  outer_pk.bin       # gnark native PLONK proving key (binary, large)
  outer_vk.json      # PLONK outer verifying key as structured hex
  circuit.r1cs       # gnark native compiled SparseR1CS (SCS)
```

All three files are produced by
`zkwrap-gnark unsafe-setup --backend plonk --max-inputs N --out <setup-dir>`.
The directory is consumed as a bundle by `prove` and `verify` via
`--setup <setup-dir>`. The bundle is self-describing: every file carries
`backend = "gnark-plonk-bls12381"` (directly in `outer_vk.json`, implicitly in
the SCS/pk format), so `prove`/`verify` dispatch on the recorded backend.

### `outer_pk.bin` — Outer proving key

gnark native binary, produced by `pk.WriteRawTo(file)` on the
`plonk.ProvingKey` returned from `plonk.Setup`. Read back via `pk.ReadFrom(file)`.
Format is opaque to non-gnark consumers. Carries (a slice of) the KZG SRS in
Lagrange + canonical bases, so its size scales with the padded domain size
(`vk.Size`), not with `num_inputs` directly.

### `circuit.r1cs` — Compiled constraint system (SparseR1CS)

gnark native binary holding the **SparseR1CS** (`cs.SparseR1CS`) produced by
`frontend.Compile(BLS12_381, scs.NewBuilder, &OuterCircuit{…})` — **not** the
`r1cs.NewBuilder` system the Groth16 backend uses. The filename `circuit.r1cs` is
retained for layout symmetry with the Groth16 bundle; the contents are a PLONK
SCS. Read back via `scs.NewSparseR1CS(BLS12_381).ReadFrom(file)`. Saved so that
`prove` does not re-compile the wrapper circuit on every invocation; deterministic
given the circuit source and `num_inputs`, so it is a build artifact, not a secret.

### `outer_vk.json` — Outer verifying key

```json
{
  "backend":             "gnark-plonk-bls12381",
  "num_inputs":          <int, = inner system's n_real>,
  "size":                <int, padded domain size, power of two>,
  "size_inv":            "<32 bytes, BLS12-381 Fr, hex>",
  "generator":           "<32 bytes, BLS12-381 Fr, hex>",
  "nb_public_variables": <int>,
  "coset_shift":         "<32 bytes, BLS12-381 Fr, hex>",
  "kzg": {
    "g1":   "<48 bytes, compressed BLS12-381 G1, hex>",
    "g2_0": "<96 bytes, compressed BLS12-381 G2, hex>",
    "g2_1": "<96 bytes, compressed BLS12-381 G2, hex>"
  },
  "s":   ["<96B uncompressed G1 hex>", "<96B uncompressed G1 hex>", "<96B uncompressed G1 hex>"],
  "ql":  "<96 bytes, uncompressed BLS12-381 G1, hex>",
  "qr":  "<96 bytes, uncompressed BLS12-381 G1, hex>",
  "qm":  "<96 bytes, uncompressed BLS12-381 G1, hex>",
  "qo":  "<96 bytes, uncompressed BLS12-381 G1, hex>",
  "qk":  "<96 bytes, uncompressed BLS12-381 G1, hex>",
  "qcp": ["<96 bytes, uncompressed BLS12-381 G1, hex>", ...],
  "commitment_constraint_indexes": [<int>, ...]
}
```

| Field | Description |
|-------|-------------|
| `backend`             | Canonical outer-backend id. Fixed at `"gnark-plonk-bls12381"`. |
| `num_inputs`          | Exact number of inner public inputs (`= n_real`) this VK was compiled for. No padding. |
| `size`                | Padded domain size `n` (a power of two); the multiplicative subgroup order. `Zₕ(ζ) = ζⁿ − 1`. (The domain is padded to a power of two by gnark internally; this is unrelated to public-input count.) |
| `size_inv`            | `n⁻¹` in Fr. Used in every Lagrange evaluation. |
| `generator`           | Domain generator `ω` (an `n`-th root of unity in Fr). |
| `nb_public_variables` | Number of public variables `= 1 + num_inputs` (`InnerVKHash` + the input slots). Used to offset the wire index when folding a BSB22 commitment into the public inputs: the `i`-th commitment's Lagrange point is `ω^(nb_public_variables + commitment_constraint_indexes[i])`. |
| `coset_shift`         | Coset generator (gnark default `7`). Appears in the permutation argument's linearization. |
| `kzg.g1`              | KZG SRS `[1]₁` (G1 generator), compressed. Not transcript-bound, so compressed suffices. |
| `kzg.g2_0`            | KZG SRS `[1]₂` (G2 generator), compressed. |
| `kzg.g2_1`            | KZG SRS `[s]₂` (the secret-scaled G2), compressed. The two G2 points are the only pairing-side inputs; the final check is `e(folded_digest_acc, [1]₂) · e(−folded_quotient, [s]₂) == 1`. |
| `s`                   | Permutation polynomial commitments `[S₁, S₂, S₃]`, **uncompressed** (96-byte gnark `RawBytes`). (`S₃` participates in the linearized-polynomial MSM; `S₁`, `S₂` are KZG-batched openings.) |
| `ql,qr,qm,qo,qk`      | Selector commitments (left, right, multiplication, output, constant), **uncompressed**. |
| `qcp`                 | Commitment-selector commitments, one per BSB22 commitment, **uncompressed**. The wrapper forces exactly **one** (`api.Commit` over the public inputs — the same mechanism that yields the Pedersen commitment in the Groth16 path), so length is `1` for the production circuit. |
| `commitment_constraint_indexes` | Constraint (wire) index of each BSB22 commitment, used to locate its Lagrange point in the public-input fold (see `nb_public_variables`). Length matches `qcp`. |

**Codegen note.** Every VK G1 point bound into the Fiat-Shamir transcript
(`s[0..2]`, `ql,qr,qm,qo,qk`, `qcp[]`) is hashed in **uncompressed** form (see
Transcript), and Plutus has no `G1 → uncompressed-bytes` builtin — so the
uncompressed bytes must come *from* the artifact; it's expensive to recover them
on-chain from a point. The VK therefore stores these points uncompressed and
**only** uncompressed: the Aiken codegen bakes those bytes as the transcript
preimage, and the 48-byte compressed form each on-chain EC op needs is derived
cheaply via `compress_from_uncompressed`. 
`kzg.g1`/`g2_*` are not transcript-bound and stay compressed (codegen
`bls12_381_*_uncompress`es them directly). Storing one encoding avoids
reimplementing gnark's exact compressed↔uncompressed conversion (a y-coordinate
`sqrt`) in the Rust codegen.

---

## Outer proof file

```
<outer-proof.json>
```

Produced by
`zkwrap-gnark prove --backend plonk --inner <inner-proof-dir> --setup <setup-dir> --out <outer-proof.json>`.
Consumed by `zkwrap-gnark verify --proof <outer-proof.json>` and by the plugin's
Aiken codegen / test-fixture machinery.

```json
{
  "backend":       "gnark-plonk-bls12381",
  "num_inputs":    <int, = inner system's n_real>,
  "inner_vk_hash": "<32 bytes, BLS12-381 Fr, hex>",
  "inputs":        ["<32B Fr hex>", ...],
  "lro": [ {"c": "<48B>", "u": "<96B>"}, {"c": "...", "u": "..."}, {"c": "...", "u": "..."} ],
  "z":   {"c": "<48B compressed G1 hex>", "u": "<96B uncompressed G1 hex>"},
  "h":   [ {"c": "...", "u": "..."}, {"c": "...", "u": "..."}, {"c": "...", "u": "..."} ],
  "bsb22_commitments": [ {"c": "...", "u": "..."} ],
  "lin_digest": {"c": "<48B compressed G1 hex>", "u": "<96B uncompressed G1 hex>"},
  "batched_proof": {
    "h":              {"c": "<48B compressed G1 hex>", "u": "<96B uncompressed G1 hex>"},
    "claimed_values": ["<32B Fr hex>", ...]
  },
  "z_shifted_opening": {
    "h":             {"c": "<48B compressed G1 hex>", "u": "<96B uncompressed G1 hex>"},
    "claimed_value": "<32B Fr hex>"
  }
}
```

Every G1 point is a `{"c": …, "u": …}` object carrying **both** encodings: `c` =
48-byte compressed (for on-chain EC ops via `bls12_381_G1_uncompress`), `u` =
96-byte uncompressed gnark `Marshal()`/`RawBytes()` (the exact preimage gnark
hashes in the SHA-256 transcript). Plutus cannot serialize a G1 element back to
bytes, so any point that is transcript-bound must ship its `u` form. `verify`
validates each `u` decompresses to the matching `c`.

| Field | Description |
|-------|-------------|
| `backend`       | Must equal `outer_vk.json`'s `backend`. |
| `num_inputs`    | Must equal `outer_vk.json`'s `num_inputs`. |
| `inner_vk_hash` | In-circuit Poseidon2 hash of the inner VK, exposed as the first public signal. 32-byte big-endian Fr. (Carried as a named field — not folded into `inputs` — because the Aiken codegen bakes it as the `inner_vk_hash` constant; it is the [source of truth](../adr/) for that constant.) |
| `inputs`        | The public input vector, length exactly `num_inputs` (`= n_real`); it mirrors the canonical inner proof one-for-one, with **no zero padding**. Each element 32-byte big-endian Fr. |
| `lro`           | Wire commitments `[L, R, O]` (left/right/output). Transcript-bound (uncompressed) under `gamma`. |
| `z`             | Grand-product (permutation) commitment. Transcript-bound (uncompressed) under `alpha`; also bound **compressed** in the two-opening batch scalar. |
| `h`             | Quotient commitments `[H₀, H₁, H₂]` (the split `t(X)`). Transcript-bound (uncompressed) under `zeta`. |
| `bsb22_commitments` | BSB22 commitments, one per `qcp` entry (one for the production circuit). Transcript-bound (uncompressed) under `alpha`; also hash-to-field'd into the public-input contribution (see below). |
| `lin_digest`    | The **linearized-polynomial commitment**. Normally computed inside the verifier, but the on-chain verifier must feed its *uncompressed* bytes into the `gamma_kzg` transcript, and Plutus cannot serialize a computed G1. So the prover emits it: the verifier recomputes the digest on-chain via MSM, then binds the supplied bytes with `compress(provided.u) == computed_compressed` before hashing `provided.u`. (Same trick as the Groth16 Pedersen-commitment preimage, ADR-0006.) |
| `batched_proof.h` | KZG batch-opening proof `Wζ` at `ζ` (the folded opening of `[lin_digest, L, R, O, S₁, S₂, Qcp…]`). Used only in EC/pairing ops — **not** transcript-bound — so `u` is informational; only `c` is load-bearing. |
| `batched_proof.claimed_values` | Claimed evaluations at `ζ`, in gnark order: `[lin, l, r, o, s1, s2, qcp…]`. `lin` is the claimed opening of the linearized polynomial; `l,r,o` are wire evals; `s1,s2` are the first two permutation evals; trailing entries are the `qcp` (commitment-selector) evals. 32-byte big-endian Fr each. |
| `z_shifted_opening.h` | KZG opening proof `Wζω` of `Z` at the shifted point `ζω`. Not transcript-bound; only `c` is load-bearing. |
| `z_shifted_opening.claimed_value` | Claimed evaluation `Z(ζω)` (`zu`). 32-byte big-endian Fr. |

`inputs.length` MUST equal `num_inputs`. The public-input vector the transcript
and verifier consume is `[inner_vk_hash, inputs[0], …, inputs[num_inputs − 1]]`
(declaration order, ADR-0001). `system_id` is intentionally absent — inner-system
identification is the Aiken validator's job via the baked `inner_vk_hash`.

---

## Fiat-Shamir transcript (the load-bearing contract)

gnark PLONK verification is a single KZG pairing check whose challenges are
derived by a **SHA-256** Fiat-Shamir transcript (`crypto/sha256`, a Plutus V3
builtin). All four main challenges use gnark's `fiat-shamir.Transcript`:
`NewTranscript(sha256.New(), "gamma", "beta", "alpha", "zeta")`. For challenge
`name`, `ComputeChallenge(name)` hashes `name's bound data ‖ previous
challenge value` and the result is reduced into Fr by `fr.Element.SetBytes`
(big-endian, mod `r`). Reproduce the binding order **exactly**; any deviation
changes every downstream challenge.

**Point encoding in the transcript:** every G1 point is hashed **uncompressed**
(`G1Affine.Marshal()` = 96 bytes, `x_be ‖ y_be`, three MSBs of byte 0 are format
flags). Fr scalars are hashed as 32-byte big-endian (`fr.Element.Bytes()`).

### Challenge binding order

| Challenge | Binds (in order), each as `Marshal()` (G1) or 32B BE (Fr) |
|-----------|-----------------------------------------------------------|
| `gamma`   | `S₀, S₁, S₂, Ql, Qr, Qm, Qo, Qk` (VK), then `Qcp[]` (VK), then the public inputs `[inner_vk_hash, inputs…]` (Fr), then `L, R, O`. |
| `beta`    | (nothing additional — derived from the running transcript state after `gamma`). |
| `alpha`   | `Bsb22Commitments[]`, then `Z`. |
| `zeta`    | `H₀, H₁, H₂`. |

### BSB22 commitment → public-input fold

Each BSB22 commitment contributes to the evaluated public input `PI(ζ)` via a
hash-to-field of its **uncompressed** bytes:

- **Algorithm:** RFC-9380 `expand_message_xmd` over **SHA-256**
  (gnark-crypto `fr/hash_to_field`).
- **Domain separation tag (DST):** the ASCII string `"BSB22-Plonk"`.
- This is the **same** `expand_message_xmd`(SHA-256) primitive the Groth16 outer
  spike uses for its Pedersen commitment; **only the DST differs**.
- The resulting field element `hashedCmt` is folded with the Lagrange weight at
  `ω^(nb_public_variables + commitment_constraint_indexes[i])`.

### KZG batch-fold challenge `gamma_kzg`

A separate single-challenge SHA-256 transcript (`NewTranscript(sha256.New(),
"gamma")`, gnark `kzg.deriveGamma`), binding **in order**:

1. `ζ` (Fr, 32B BE),
2. the digests **uncompressed**: `[lin_digest, L, R, O, S₁, S₂, Qcp…]`,
3. the claimed values (Fr): `[lin, l, r, o, s1, s2, qcp…]`,
4. `zu = Z(ζω)` (Fr).

`gamma_kzg` MUST match the prover exactly — the prover's batched-opening
quotient (`batched_proof.h`) is bound to it. This is why `lin_digest`'s
uncompressed bytes must be supplied and verified (see the proof table).

### Two-opening batch scalar (Solidity-style, deterministic)

gnark's Go `kzg.BatchVerifyMultiPoints` folds the two openings (at `ζ` and `ζω`)
with a **random** λ, which is not reproducible on-chain. We instead derive λ
deterministically, mirroring gnark's PLONK **Solidity** verifier:

- `λ = SHA-256( compress(folded_digest) ‖ compress(Z) )`, reduced into Fr.
- Both points are **compressed** (48B) here — the one place compressed bytes are
  hashed.

A valid proof verifies under *any* λ, so a deterministic λ preserves soundness.
**The port target is gnark's PLONK Solidity verifier, not the Go one.**

### Final pairing check

```
e( acc, [1]₂ ) · e( −folded_quotient, [s]₂ ) == 1
```
where `acc` and `folded_quotient` are assembled from the two openings folded by
`λ` (full scalar formulas in `experiments/aiken-plonk-spike/refverify/main.go`
and the generated `plonk.ak`).

---

## Fr and curve encoding

Identical to [outer-proof-artifacts.md](./outer-proof-artifacts.md#fr-and-curve-encoding):

- **BLS12-381 Fr element** — 32 bytes big-endian, in `[0, r)`,
  `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
- **G1 compressed** — 48 bytes, zcash-flavored (3 MSB flags + 381-bit x).
- **G1 uncompressed** — 96 bytes, gnark `Marshal()`/`RawBytes()` (`x_be ‖ y_be`,
  3 MSB flags in byte 0). This is the exact transcript preimage.
- **G2 compressed** — 96 bytes, zcash-flavored (x is `c1 ‖ c0`).

**Hex convention:** lowercase, no `0x`, no separators.

---

## Validation rules

`zkwrap-gnark prove --backend plonk` MUST refuse to proceed if:

1. `<setup-dir>/outer_vk.json`, `outer_pk.bin`, `circuit.r1cs` are all present and readable.
2. `outer_vk.json.backend == "gnark-plonk-bls12381"` and `num_inputs` agrees across the bundle.
3. The inner-proof directory passes [canonical-inner-proof.md](./canonical-inner-proof.md).
4. The canonical inner proof's `n_real` **equals** `num_inputs` (exact — the VK was compiled for this inner system; there is no padding).

`zkwrap-gnark verify` MUST refuse if:

1. `outer_proof.json` is well-formed, `inputs.length == num_inputs`, and every G1 `u` decompresses to its `c`.
2. `outer_proof.json` and `outer_vk.json` agree on `backend` and `num_inputs`.
3. `lin_digest` recomputed from the VK + proof + challenges matches the supplied `lin_digest` (compress-equality).
4. The PLONK verification (`plonk.Verify` over `[inner_vk_hash, inputs…]`) succeeds.

Failures of (1)–(4) are operational and exit `1`. Malformed CLI invocations exit `2`.
