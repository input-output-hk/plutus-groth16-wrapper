//! Regenerates the baked canonical SP1 Groth16 verifying key
//! (`src/sp1_groth16_vk_v3_0_0.bin`) entirely in Rust — no Go round-trip.
//!
//! SP1's fixed v3.0.0 Groth16 VK ships in gnark's *compressed* point encoding.
//! `sp1-verifier` embeds those exact bytes as the public `GROTH16_VK_BYTES`
//! constant and decodes them with the `bn` (substrate-bn-succinct) curve crate.
//! The gnark compressed→affine decode is `pub(crate)` there, so the three
//! decode helpers below are vendored **verbatim** from
//! `sp1-verifier-3.4.0/src/groth16/converter.rs` + `constants.rs` (only the
//! error handling is simplified). Using SP1's own VK bytes and decode logic
//! keeps this authoritative; the curve math is identical to SP1's on-chain
//! verifier.
//!
//! We then re-emit the points in the canonical uncompressed [`Bn254Vk`] layout
//! (`docs/schemas/canonical-inner-proof.md`) and, by default, assert the result
//! still matches the committed `.bin` (the oracle the rest of the crate trusts).
//!
//! Run: `cargo run -p zkwrap-sp1 --bin gen-canonical-vk --features gen-vk [-- <out.bin>]`

use std::path::PathBuf;

use bn::{AffineG1, AffineG2, Fq, Fq2};
use zkwrap_core::{Bn254G1, Bn254G2, Bn254Vk};

// --- gnark compressed-point flags (constants.rs) -----------------------------
const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

// --- vendored verbatim from sp1-verifier-3.4.0 converter.rs ------------------

/// Deserialize an `Fq` (with the y-sign flag) from a 32-byte compressed buffer.
fn deserialize_with_flags(buf: &[u8]) -> (Fq, u8) {
    assert_eq!(buf.len(), 32, "invalid x length");
    let m_data = buf[0] & MASK;
    if m_data == COMPRESSED_INFINITY {
        assert!(
            !(buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0)),
            "invalid point: infinity flag on zero x"
        );
        (Fq::zero(), COMPRESSED_INFINITY)
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;
        let x = Fq::from_be_bytes_mod_order(&x_bytes).expect("x bytes to Fq");
        (x, m_data)
    }
}

fn unchecked_compressed_x_to_g1_point(buf: &[u8]) -> AffineG1 {
    let (x, m_data) = deserialize_with_flags(buf);
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x).expect("invalid point");

    let mut final_y = y;
    if y.cmp(&neg_y) == core::cmp::Ordering::Greater {
        if m_data == COMPRESSED_POSITIVE {
            final_y = -y;
        }
    } else if m_data == COMPRESSED_NEGATIVE {
        final_y = -y;
    }
    AffineG1::new_unchecked(x, final_y)
}

fn unchecked_compressed_x_to_g2_point(buf: &[u8]) -> AffineG2 {
    assert_eq!(buf.len(), 64, "invalid x length");
    let (x1, flag) = deserialize_with_flags(&buf[..32]);
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).expect("x0 bytes to Fq");
    let x = Fq2::new(x0, x1);

    if flag == COMPRESSED_INFINITY {
        return AffineG2::one();
    }
    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x).expect("invalid point");
    match flag {
        COMPRESSED_POSITIVE => AffineG2::new_unchecked(x, y),
        COMPRESSED_NEGATIVE => AffineG2::new_unchecked(x, neg_y),
        _ => panic!("invalid point flag"),
    }
}

// --- canonical re-emission ----------------------------------------------------

fn fq_be(f: Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    f.to_big_endian(&mut out).expect("Fq to_big_endian");
    out
}

/// G1 → canonical `x_be ‖ y_be`.
fn g1_canonical(p: &AffineG1) -> Bn254G1 {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_be(p.x()));
    out[32..64].copy_from_slice(&fq_be(p.y()));
    Bn254G1(out)
}

/// G2 → canonical gnark order `X.A1 ‖ X.A0 ‖ Y.A1 ‖ Y.A0` (imaginary before real).
fn g2_canonical(p: &AffineG2) -> Bn254G2 {
    let (x, y) = (p.x(), p.y());
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_be(x.imaginary()));
    out[32..64].copy_from_slice(&fq_be(x.real()));
    out[64..96].copy_from_slice(&fq_be(y.imaginary()));
    out[96..128].copy_from_slice(&fq_be(y.real()));
    Bn254G2(out)
}

fn main() {
    // SP1's own embedded fixed v3.0.0 Groth16 VK, in gnark compressed form.
    let buf: &[u8] = *sp1_verifier::GROTH16_VK_BYTES;

    // Layout (docs/research/sp1-artifact-format.md §4): alpha[0..32],
    // beta_g2[64..128], gamma_g2[128..192], delta_g2[224..288], num_k[288..292],
    // then K points. (Slots [32..64]=beta_g1 and [192..224]=delta_g1 are unused
    // in verification.) We store the *real* beta_g2 — sp1-verifier negates it
    // for the pairing check, but the canonical VK carries the raw point.
    let alpha = unchecked_compressed_x_to_g1_point(&buf[0..32]);
    let beta = unchecked_compressed_x_to_g2_point(&buf[64..128]);
    let gamma = unchecked_compressed_x_to_g2_point(&buf[128..192]);
    let delta = unchecked_compressed_x_to_g2_point(&buf[224..288]);

    let num_k = u32::from_be_bytes(buf[288..292].try_into().unwrap());
    let ic: Vec<Bn254G1> = (0..num_k as usize)
        .map(|i| {
            let off = 292 + i * 32;
            g1_canonical(&unchecked_compressed_x_to_g1_point(&buf[off..off + 32]))
        })
        .collect();

    let vk = Bn254Vk {
        alpha_g1: g1_canonical(&alpha),
        beta_g2: g2_canonical(&beta),
        gamma_g2: g2_canonical(&gamma),
        delta_g2: g2_canonical(&delta),
        ic,
    };
    let bytes = vk.to_bytes();

    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sp1_groth16_vk_v3_0_0.bin");
    if let Ok(existing) = std::fs::read(&committed) {
        assert_eq!(
            bytes,
            existing,
            "regenerated canonical VK differs from the committed {}",
            committed.display()
        );
        eprintln!(
            "✔ regenerated VK matches committed {} ({} bytes)",
            committed.display(),
            bytes.len()
        );
    }

    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or(committed);
    std::fs::write(&out, &bytes).expect("write canonical vk");
    eprintln!(
        "wrote {} bytes (n_ic={}) to {}",
        bytes.len(),
        num_k,
        out.display()
    );
}
