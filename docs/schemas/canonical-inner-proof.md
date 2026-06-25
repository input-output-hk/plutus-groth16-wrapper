# Canonical Inner Proof Format

The canonical inner proof is the normalized, language-agnostic representation of a BN254
Groth16 proof produced by a plugin and consumed by an outer backend prover binary.

It is the contract between the Rust plugin library and the Go gnark prover (or future Halo2
prover). Both sides implement their serialization independently against this spec.

---

## On-disk layout

A canonical inner proof is a directory containing exactly these files:

```
<proof-dir>/
  vk.bin            # BN254 Groth16 verifying key
  proof.bin         # BN254 Groth16 proof
  public_inputs.bin # Real public inputs (n_real × 32 bytes)
  meta.json         # Metadata: system_id, n_real
```

---

## Encoding conventions

All multi-byte integers are **big-endian**. All curve coordinates are **uncompressed** (both
X and Y serialized). No length prefixes unless stated.

### BN254 Fr element (`Bn254Fr`)

32 bytes, big-endian representation of a BN254 scalar field element.

### BN254 G1 affine point (`Bn254G1`)

64 bytes:

```
[0:32]  X coordinate, big-endian Fq element
[32:64] Y coordinate, big-endian Fq element
```

The point at infinity is not valid in this format — all G1 points must be on the curve.

### BN254 G2 affine point (`Bn254G2`)

128 bytes, following gnark's `WriteRawTo` coordinate order (imaginary part of X first):

```
[0:32]   X.A1 (imaginary part), big-endian Fq element
[32:64]  X.A0 (real part),      big-endian Fq element
[64:96]  Y.A1 (imaginary part), big-endian Fq element
[96:128] Y.A0 (real part),      big-endian Fq element
```

This order matches gnark's `WriteRawTo` output and both the RISC Zero and SP1 seal formats
(verified in Phase 1 experiments).

---

## `vk.bin` — Verifying key

Fixed-size header followed by a variable-length IC array:

```
[0:64]   alpha_g1   Bn254G1  (64 bytes)
[64:192] beta_g2    Bn254G2  (128 bytes)
[192:320] gamma_g2  Bn254G2  (128 bytes)
[320:448] delta_g2  Bn254G2  (128 bytes)
[448:452] n_ic      uint32 big-endian  (= n_real + 1)
[452 + i*64 : 452 + (i+1)*64]  IC[i]  Bn254G1, for i in 0..n_ic
```

Total size: `452 + (n_real + 1) × 64` bytes.

`IC[0]` is the constant term (independent of public inputs). `IC[1..n_real]` are the
per-input accumulation points.

**Note on source formats:** RISC Zero uses snarkjs JSON (decimal coordinates); SP1 uses
gnark compressed binary. The Rust plugin for each system must convert to this uncompressed
binary layout.

---

## `proof.bin` — Proof

256 bytes, fixed:

```
[0:64]   ar   Bn254G1  (A point)
[64:192] bs   Bn254G2  (B point)
[192:256] krs Bn254G1  (C point)
```

`CommitmentPok` is not included. gnark skips the Pedersen commitment check when
`vk.PublicAndCommitmentCommitted` is empty, which is the case for both RISC Zero and SP1
(both have zero Pedersen commitments in their BN254 Groth16 circuits). If a future inner
system uses gnark Pedersen commitments, this spec must be extended.

**Note (outer ≠ inner):** the outer wrapper proof DOES carry Pedersen commitments —
gnark's emulated-arithmetic rangechecks require them. See
[outer-proof-artifacts.md](./outer-proof-artifacts.md) for the outer schema's
`commitment_keys` / `commitments` / `commitment_pok` fields. This canonical
inner-proof spec describes the contract between the Rust plugin and the Go
prover for native-BN254 systems where the commitment slot is absent.

**Note on SP1 source format:** SP1's `seal.bin` is 324 bytes (includes `CommitmentPok` as a
serialization artifact). The SP1 plugin reads only bytes `[0:256]` for `proof.bin`.

---

## `public_inputs.bin` — Real public inputs

`n_real × 32` bytes: exactly `n_real` consecutive `Bn254Fr` elements in proof order.

No padding to `MAX_INPUTS` here. Padding is the prover binary's responsibility — it reads
`n_real` from `meta.json` and zero-fills remaining slots before passing them to the outer
circuit.

---

## `meta.json` — Metadata (also the inner system config)

```json
{
  "system_id": "<string>",
  "n_real":    <uint>,
  "codegen":   { <system-specific, optional> }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `system_id` | string | Identifies the inner proof system. Canonical values: `"risc0-v3"`, `"sp1-v3"`. Used by the prover binary to select the Aiken validator template parameters. |
| `n_real` | uint | Number of real public inputs in `public_inputs.bin`. Must equal `IC.len() - 1` from `vk.bin`. |
| `codegen` | object | **Optional. Opaque to the prover binary.** System-specific per-guest constants consumed only by the Rust Composer when generating the inner-layer fragment. The prover MUST ignore this section. |

`meta.json` MUST contain `system_id` and `n_real`; it MAY contain a `codegen` section.
The prover binary parses only the first two and ignores any additional fields (the Go
`metaFile` struct declares only `system_id` and `n_real`, so unknown fields are dropped).

For RISC Zero (`system_id = "risc0-v3"`), the `codegen` section carries the values the inner-layer
journal-authentication chain bakes per guest program:

```json
"codegen": {
  "image_id":          "<hex 32B>",  // pre_state_digest — binds to one guest program
  "post_state_digest": "<hex 32B>",
  "control_root":      "<hex>",      // → split into inputs[0], inputs[1]
  "bn254_control_id":  "<hex 32B>"   // → inputs[4]
}
```

There is no separate inner-system-config file; this section is it.

---

## Rust struct

```rust
pub struct CanonicalInnerProof {
    pub vk:            Bn254Vk,
    pub proof:         Bn254Proof,
    /// Real inputs only, length == n_real. No padding.
    pub public_inputs: Vec<Bn254Fr>,
    pub system_id:     &'static str,
}

pub struct Bn254Vk {
    pub alpha_g1: Bn254G1,
    pub beta_g2:  Bn254G2,
    pub gamma_g2: Bn254G2,
    pub delta_g2: Bn254G2,
    /// IC[0] is the constant term; IC[1..] are per-input. len() == n_real + 1.
    pub ic:       Vec<Bn254G1>,
}

pub struct Bn254Proof {
    pub ar:  Bn254G1,
    pub bs:  Bn254G2,
    pub krs: Bn254G1,
}

/// BN254 Fr element: 32 bytes big-endian.
pub struct Bn254Fr(pub [u8; 32]);

/// BN254 G1 affine uncompressed: X || Y, each 32 bytes big-endian.
pub struct Bn254G1(pub [u8; 64]);

/// BN254 G2 affine uncompressed: X.A1 || X.A0 || Y.A1 || Y.A0, each 32 bytes big-endian.
/// A1 (imaginary part) precedes A0 (real part) — gnark WriteRawTo convention.
pub struct Bn254G2(pub [u8; 128]);
```

`n_real` is implicit as `public_inputs.len()` — no separate field in the struct.

---

## Go prover consumption

The Go prover binary reads the four files and constructs gnark types:

```go
// vk.bin → *bn254groth16.VerifyingKey
vk.G1.Alpha.SetBytes(data[0:64])    // uncompressed G1
vk.G2.Beta.SetBytes(data[64:192])   // uncompressed G2
vk.G2.Gamma.SetBytes(data[192:320])
vk.G2.Delta.SetBytes(data[320:448])
nIC := binary.BigEndian.Uint32(data[448:452])
vk.G1.K = make([]bn254.G1Affine, nIC)
for i := range vk.G1.K {
    vk.G1.K[i].SetBytes(data[452+i*64 : 452+(i+1)*64])
}
vk.Precompute()

// proof.bin → *bn254groth16.Proof (CommitmentPok is zero-valued, ignored by gnark)
proof.Ar.X.SetBytes(data[0:32]);    proof.Ar.Y.SetBytes(data[32:64])
proof.Bs.X.A1.SetBytes(data[64:96]); proof.Bs.X.A0.SetBytes(data[96:128])
proof.Bs.Y.A1.SetBytes(data[128:160]); proof.Bs.Y.A0.SetBytes(data[160:192])
proof.Krs.X.SetBytes(data[192:224]); proof.Krs.Y.SetBytes(data[224:256])

// public_inputs.bin → fr.Vector (n_real elements)
// prover pads to MAX_INPUTS with fr.Element{} (zero) before circuit assignment
```

---

## Validation rules

A plugin MUST ensure before writing:

1. `IC.len() == n_real + 1` (constant term plus one point per real input).
2. `public_inputs.len() == n_real`.
3. All G1 and G2 points are valid curve points (on the curve, not infinity).
4. All Fr elements are in range `[0, r)` where `r` is the BN254 scalar field modulus.
5. `n_real <= MAX_INPUTS` (prover binary enforces this at runtime; plugin should not exceed it).
