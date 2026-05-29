# Outer Proof Artifacts

The file artifacts produced and consumed by the `zkwrap-gnark` binary. Setup writes
a co-located bundle (`outer_pk.bin`, `outer_vk.json`, `circuit.r1cs`); prove writes
a single self-contained file (`outer_proof.json`). Together these form the
contract between the gnark prover, the Rust plugins, and Aiken codegen.

See also: [ADR-0004](../adr/0004-gnark-prover-cli.md),
[canonical-inner-proof.md](./canonical-inner-proof.md).

---

## Setup-dir layout

```
<setup-dir>/
  outer_pk.bin       # gnark native proving key (binary, large)
  outer_vk.json      # outer verifying key as structured hex
  circuit.r1cs       # gnark native compiled R1CS
```

All three files are produced by `zkwrap-gnark unsafe-setup --max-inputs N --out <setup-dir>`.
The directory is consumed as a bundle by `prove` and `verify` via `--setup <setup-dir>`.

### `outer_pk.bin` — Outer proving key

gnark native binary, produced by `pk.WriteRawTo(file)` on the
`groth16.ProvingKey[BLS12_381]` returned from `groth16.Setup`. Read back via
`pk.ReadFrom(file)`.

Format is opaque to non-gnark consumers. Size scales with `MAX_INPUTS` and the
wrapper circuit constraint count (expected hundreds of megabytes).

### `circuit.r1cs` — Compiled R1CS

gnark native binary, produced by `ccs.WriteTo(file)` on the
`constraint.ConstraintSystem` returned from `frontend.Compile(BLS12_381, r1cs.NewBuilder, …)`.
Read back via `r1cs.NewR1CS(BLS12_381).ReadFrom(file)`.

Saved so that `prove` does not re-compile the wrapper circuit on every invocation.
The R1CS is deterministic given the circuit source and `MAX_INPUTS`, so this is
purely a build artifact — not a secret.

### `outer_vk.json` — Outer verifying key

```json
{
  "backend":    "gnark-groth16-bls12381",
  "max_inputs": 16,
  "alpha_g1":   "<48 bytes, compressed BLS12-381 G1, hex>",
  "beta_g2":    "<96 bytes, compressed BLS12-381 G2, hex>",
  "gamma_g2":   "<96 bytes, compressed BLS12-381 G2, hex>",
  "delta_g2":   "<96 bytes, compressed BLS12-381 G2, hex>",
  "ic": [
    "<48 bytes, compressed BLS12-381 G1, hex>",
    "<48 bytes, compressed BLS12-381 G1, hex>",
    ...
  ],
  "commitment_keys": [
    {
      "g":             "<96 bytes, compressed BLS12-381 G2, hex>",
      "g_sigma_neg":   "<96 bytes, compressed BLS12-381 G2, hex>"
    }
  ],
  "public_and_commitment_committed": [
    [<int>, <int>, ...],
    ...
  ]
}
```

| Field | Description |
|-------|-------------|
| `backend`    | Canonical identifier of the outer backend. Currently fixed at `"gnark-groth16-bls12381"`. Future Halo2 backend will use a different identifier. |
| `max_inputs` | The compile-time `MAX_INPUTS` constant baked into the wrapper circuit. |
| `alpha_g1`   | Outer Groth16 VK alpha point on G1, compressed. |
| `beta_g2`    | Outer Groth16 VK beta point on G2, compressed. |
| `gamma_g2`   | Outer Groth16 VK gamma point on G2, compressed. |
| `delta_g2`   | Outer Groth16 VK delta point on G2, compressed. |
| `ic`         | Outer Groth16 VK IC array. Length `max_inputs + 2 + len(commitment_keys)`: `IC[0]` is the constant term, `IC[1]` is the `InnerVKHash` coefficient, `IC[2..max_inputs+1]` are the per-input coefficients matching `inputs[0..max_inputs-1]`, and the trailing `len(commitment_keys)` slot(s) hold the Pedersen-commitment-folded public input(s). |
| `commitment_keys` | Pedersen commitment verifying keys (Bowe–Gabizon, [eprint 2022/1072](https://eprint.iacr.org/2022/1072)). The wrapper circuit uses emulated BN254 arithmetic inside BLS12-381; gnark's emulated rangechecks need a Fiat-Shamir challenge produced by hashing a Pedersen commitment, so the outer setup unavoidably emits one commitment slot. Each entry is `{g, g_sigma_neg}` — two compressed BLS12-381 G2 points. |
| `public_and_commitment_committed` | Index lists used by the verifier to fold each commitment into the public-input vector. Per commitment `i`, `public_and_commitment_committed[i]` lists the wire indices included in the Fiat-Shamir hash that produces the implicit committed public input. Indices are 1-based into the full public/private wire vector (gnark convention). |

**Hex convention:** lowercase hex, no `0x` prefix, no separators. Compressed BLS12-381 points
use the zcash-flavored encoding (most-significant bit of byte 0 is the compression flag,
second-most-significant bit indicates infinity, third-most-significant bit selects the y root).
This is what gnark's `point.Bytes()` returns and what Cardano's `bls12_381_G1_uncompress` /
`bls12_381_G2_uncompress` builtins expect.

---

## Outer proof file

```
<outer-proof.json>
```

Produced by `zkwrap-gnark prove --inner <inner-proof-dir> --setup <setup-dir> --out <outer-proof.json>`.
Consumed by `zkwrap-gnark verify --proof <outer-proof.json>` and by the
plugin's Aiken codegen / test-fixture machinery.

```json
{
  "backend":    "gnark-groth16-bls12381",
  "max_inputs": 16,
  "proof": {
    "ar":             "<48 bytes, compressed BLS12-381 G1, hex>",
    "bs":             "<96 bytes, compressed BLS12-381 G2, hex>",
    "krs":            "<48 bytes, compressed BLS12-381 G1, hex>",
    "commitments":    ["<48 bytes, compressed BLS12-381 G1, hex>", ...],
    "commitment_pok": "<48 bytes, compressed BLS12-381 G1, hex>"
  },
  "inner_vk_hash": "<32 bytes, BLS12-381 Fr, hex>",
  "inputs": [
    "<32 bytes, BLS12-381 Fr, hex>",
    "<32 bytes, BLS12-381 Fr, hex>",
    ...
  ]
}
```

| Field | Description |
|-------|-------------|
| `backend`              | Must equal the `backend` field of the `outer_vk.json` used for proving. |
| `max_inputs`           | Must equal the `max_inputs` field of the `outer_vk.json` used for proving. |
| `proof.ar`             | Outer Groth16 proof A point, compressed G1. |
| `proof.bs`             | Outer Groth16 proof B point, compressed G2. |
| `proof.krs`            | Outer Groth16 proof C point, compressed G1. |
| `proof.commitments`    | One compressed G1 point per entry in `outer_vk.json`'s `commitment_keys`. Pedersen commitments to the values listed in `public_and_commitment_committed`. |
| `proof.commitment_pok` | Batched Pedersen proof-of-knowledge, compressed G1, that binds the prover to the commitments. Verifier checks `e(commitment_pok, [g]_2) == ∏ e(commitments[i], [g_sigma_neg]_2)` (one combined pairing per the batched form gnark uses). |
| `inner_vk_hash`        | The in-circuit Poseidon hash of the inner VK, exposed as the first outer public signal. 32-byte big-endian BLS12-381 Fr element. |
| `inputs`               | The `MAX_INPUTS`-length public input vector exposed by the wrapper circuit. Slots `[0, n_real)` mirror the canonical inner proof's `public_inputs.bin`; slots `[n_real, MAX_INPUTS)` are zero. Each element is a 32-byte big-endian BLS12-381 Fr element. |

`inputs.length` MUST equal `max_inputs`. The public-input vector consumed by
`groth16.Verify` is `[inner_vk_hash, inputs[0], …, inputs[max_inputs - 1]]`
(see ADR-0001).

`system_id` is intentionally absent — the gnark prover is system-agnostic, and
inner-system identification is the Aiken validator's responsibility (via the
`inner_vk_hash` constant baked in at codegen time).

---

## Fr and curve encoding

### BLS12-381 Fr element

32 bytes, big-endian representation of a BLS12-381 scalar field element. Must be
in `[0, r)` where `r` is the BLS12-381 scalar field modulus
(`0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`).

### BLS12-381 G1 compressed point

48 bytes, zcash-flavored compressed affine encoding. The three most significant
bits of byte 0 are flags: compression (always 1 in this format), infinity, and
y-sign. The remaining 381 bits are the x-coordinate big-endian.

### BLS12-381 G2 compressed point

96 bytes, zcash-flavored compressed affine encoding. Same flag layout as G1 in
byte 0; the 762-bit x-coordinate is two Fq elements (`x.c1` then `x.c0`,
big-endian within each).

---

## Validation rules

`zkwrap-gnark prove` MUST refuse to proceed if any of the following fails:

1. `<setup-dir>/outer_vk.json`, `<setup-dir>/outer_pk.bin`, `<setup-dir>/circuit.r1cs` all present and readable.
2. The `backend` and `max_inputs` fields agree across `outer_vk.json` and any other source of truth (e.g., R1CS metadata if checked).
3. The inner-proof directory passes the validation rules in
   [canonical-inner-proof.md](./canonical-inner-proof.md).
4. The canonical inner proof's `n_real` is `<= max_inputs`.

`zkwrap-gnark verify` MUST refuse if:

1. `outer_proof.json` is well-formed and `inputs.length == max_inputs`.
2. `outer_proof.json` and `outer_vk.json` agree on `backend` and `max_inputs`.
3. The outer Groth16 verification `groth16.Verify(proof, vk, [inner_vk_hash, inputs…])` succeeds.

Failures of (1)–(3) are operational and exit `1`. Malformed CLI invocations (missing
flags, conflicting flags, unknown subcommands) exit `2`.
