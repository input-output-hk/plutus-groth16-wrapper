//! `InnerVKHash` computation: the off-chain twin of the wrapper circuit's
//! in-circuit Poseidon2 hash over the gnark-recursive-form inner verifying key.
//!
//! **Role: cross-check only, not the codegen path.** Aiken codegen reads the
//! baked `InnerVKHash` from the gnark prover output (`outer_proof.json`); gnark
//! is the single source of truth (ADR-0005). This mirrors gnark's
//! `circuit.ComputeInnerVKHash` limb-for-limb purely so a regression test can
//! catch a silent change in `gnark-crypto`'s Poseidon2 that would otherwise
//! shift every baked constant. Pinned against `inner_vk_hash_vectors.json`.

/// Poseidon2 over the BLS12-381 scalar field — the hash the wrapper circuit
/// uses; exists solely for this cross-check.
pub mod poseidon2;
#[cfg(test)]
mod test_vectors;

use self::poseidon2::MerkleDamgardHasher;
use crate::inner::{Bn254G1, Bn254G2, Bn254Vk};
use ark_bls12_381::Fr;
use ark_bn254::{Bn254, Fq, Fq12, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

/// Computes `InnerVKHash` for a BN254 inner verifying key, padding IC to
/// `max_inputs + 1` with zero G1 points. Returns the 32-byte big-endian digest.
///
/// Preimage order: `E` (12 Fp, the `sw_bn254.GTEl` basis of
/// `e(alpha, beta)`), `GammaNeg` (4 Fp), `DeltaNeg` (4 Fp), then
/// `IC[0..=max_inputs]` (2 Fp each). Each Fp is fed as 4 little-endian 64-bit
/// limbs, one Poseidon2-MD block per limb.
pub fn compute_inner_vk_hash(vk: &Bn254Vk, max_inputs: usize) -> [u8; 32] {
    let alpha = parse_g1(&vk.alpha_g1);
    let beta = parse_g2(&vk.beta_g2);
    let gamma_neg = -parse_g2(&vk.gamma_g2);
    let delta_neg = -parse_g2(&vk.delta_g2);

    let e = Bn254::pairing(alpha, beta).0;
    let gt_limbs = gt_emulated_basis(&e);

    let mut h = MerkleDamgardHasher::new();
    for fp in &gt_limbs {
        write_fp(&mut h, fp);
    }
    write_g2(&mut h, &gamma_neg);
    write_g2(&mut h, &delta_neg);
    for i in 0..=max_inputs {
        match vk.ic.get(i) {
            Some(ic) => write_g1(&mut h, &parse_g1(ic)),
            None => {
                // Zero G1 padding: X = Y = 0 → eight zero limbs.
                for _ in 0..8 {
                    h.update_fr(&Fr::from(0u64));
                }
            }
        }
    }
    h.finalize()
}

/// Decomposes a BN254 `Fq12` into the 12 `Fq` coordinates carried by gnark's
/// `sw_bn254.GTEl` (the emulated GT basis). Mirrors `gtEmulatedBasis`, which
/// applies a 9-twist: `twist(a0, a1) = a0 - 9·a1`.
///
/// gnark `bn254.GT` tower `C{0,1}.B{0,1,2}.A{0,1}` maps to ark
/// `Fq12.c{0,1}.c{0,1,2}.c{0,1}`.
pub fn gt_emulated_basis(e: &Fq12) -> [Fq; 12] {
    let nine = Fq::from(9u64);
    let twist = |a0: Fq, a1: Fq| a0 - nine * a1;
    // c0 = C0 (Fq6), c1 = C1 (Fq6); ci.cj = B{j} (Fq2); a.c0/a.c1 = A0/A1.
    let c0 = &e.c0;
    let c1 = &e.c1;
    [
        twist(c0.c0.c0, c0.c0.c1), // C0.B0
        twist(c1.c0.c0, c1.c0.c1), // C1.B0
        twist(c0.c1.c0, c0.c1.c1), // C0.B1
        twist(c1.c1.c0, c1.c1.c1), // C1.B1
        twist(c0.c2.c0, c0.c2.c1), // C0.B2
        twist(c1.c2.c0, c1.c2.c1), // C1.B2
        c0.c0.c1,                  // C0.B0.A1
        c1.c0.c1,                  // C1.B0.A1
        c0.c1.c1,                  // C0.B1.A1
        c1.c1.c1,                  // C1.B1.A1
        c0.c2.c1,                  // C0.B2.A1
        c1.c2.c1,                  // C1.B2.A1
    ]
}

/// Decomposes a BN254 `Fq` into 4 little-endian 64-bit limbs (the native limb
/// layout of `emulated.Element[BN254Fp]`).
fn fp_limbs64(x: &Fq) -> [u64; 4] {
    x.into_bigint().0
}

fn write_fp(h: &mut MerkleDamgardHasher, x: &Fq) {
    for limb in fp_limbs64(x) {
        h.update_fr(&Fr::from(limb));
    }
}

fn write_g1(h: &mut MerkleDamgardHasher, p: &G1Affine) {
    write_fp(h, &p.x);
    write_fp(h, &p.y);
}

fn write_g2(h: &mut MerkleDamgardHasher, p: &G2Affine) {
    // gnark writeG2 order: X.A0, X.A1, Y.A0, Y.A1.
    write_fp(h, &p.x.c0);
    write_fp(h, &p.x.c1);
    write_fp(h, &p.y.c0);
    write_fp(h, &p.y.c1);
}

/// G1 uncompressed: X(32 BE) || Y(32 BE).
fn parse_g1(p: &Bn254G1) -> G1Affine {
    let x = Fq::from_be_bytes_mod_order(&p.0[0..32]);
    let y = Fq::from_be_bytes_mod_order(&p.0[32..64]);
    G1Affine::new_unchecked(x, y)
}

/// G2 uncompressed, gnark `WriteRawTo` order: X.A1 || X.A0 || Y.A1 || Y.A0
/// (imaginary part first), each 32 bytes BE. ark `Fq2` is `(c0 = A0, c1 = A1)`.
fn parse_g2(p: &Bn254G2) -> G2Affine {
    use ark_bn254::Fq2;
    let x_a1 = Fq::from_be_bytes_mod_order(&p.0[0..32]);
    let x_a0 = Fq::from_be_bytes_mod_order(&p.0[32..64]);
    let y_a1 = Fq::from_be_bytes_mod_order(&p.0[64..96]);
    let y_a0 = Fq::from_be_bytes_mod_order(&p.0[96..128]);
    G2Affine::new_unchecked(Fq2::new(x_a0, x_a1), Fq2::new(y_a0, y_a1))
}

#[cfg(test)]
mod tests {
    use super::test_vectors::load_vectors;
    use super::*;

    fn fp_from_hex(h: &str) -> Fq {
        Fq::from_be_bytes_mod_order(&hex::decode(h).unwrap())
    }

    fn fp_to_hex(x: &Fq) -> String {
        use ark_ff::BigInteger;
        let mut out = [0u8; 32];
        let be = x.into_bigint().to_bytes_be();
        out[32 - be.len()..].copy_from_slice(&be);
        hex::encode(out)
    }

    fn load_vk() -> Bn254Vk {
        let v = load_vectors();
        let bytes = hex::decode(&v.vk.vk_bytes_hex).unwrap();
        Bn254Vk::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn gt_limbs_match_gnark() {
        let v = load_vectors();
        let vk = load_vk();
        let alpha = parse_g1(&vk.alpha_g1);
        let beta = parse_g2(&vk.beta_g2);
        let e = Bn254::pairing(alpha, beta).0;
        let limbs = gt_emulated_basis(&e);
        for (i, fp) in limbs.iter().enumerate() {
            assert_eq!(fp_to_hex(fp), v.vk.gt_limbs[i], "gt limb {i}");
        }
    }

    #[test]
    fn gamma_delta_neg_match_gnark() {
        let v = load_vectors();
        let vk = load_vk();
        let gamma_neg = -parse_g2(&vk.gamma_g2);
        let delta_neg = -parse_g2(&vk.delta_g2);
        let g = [
            &gamma_neg.x.c0,
            &gamma_neg.x.c1,
            &gamma_neg.y.c0,
            &gamma_neg.y.c1,
        ];
        let d = [
            &delta_neg.x.c0,
            &delta_neg.x.c1,
            &delta_neg.y.c0,
            &delta_neg.y.c1,
        ];
        for (i, fp) in g.iter().enumerate() {
            assert_eq!(fp_to_hex(fp), v.vk.gamma_neg[i], "gamma_neg fp {i}");
        }
        for (i, fp) in d.iter().enumerate() {
            assert_eq!(fp_to_hex(fp), v.vk.delta_neg[i], "delta_neg fp {i}");
        }
    }

    #[test]
    fn limb_sequence_matches_gnark() {
        // Rebuild the full ordered u64 limb sequence and compare to the dump.
        let v = load_vectors();
        let vk = load_vk();
        let alpha = parse_g1(&vk.alpha_g1);
        let beta = parse_g2(&vk.beta_g2);
        let e = Bn254::pairing(alpha, beta).0;
        let gt_limbs = gt_emulated_basis(&e);
        let gamma_neg = -parse_g2(&vk.gamma_g2);
        let delta_neg = -parse_g2(&vk.delta_g2);

        let mut seq: Vec<u64> = Vec::new();
        let push_fp = |x: &Fq, seq: &mut Vec<u64>| seq.extend_from_slice(&fp_limbs64(x));
        for fp in &gt_limbs {
            push_fp(fp, &mut seq);
        }
        for g2 in [&gamma_neg, &delta_neg] {
            push_fp(&g2.x.c0, &mut seq);
            push_fp(&g2.x.c1, &mut seq);
            push_fp(&g2.y.c0, &mut seq);
            push_fp(&g2.y.c1, &mut seq);
        }
        for i in 0..=v.vk.max_inputs {
            match vk.ic.get(i) {
                Some(ic) => {
                    let p = parse_g1(ic);
                    push_fp(&p.x, &mut seq);
                    push_fp(&p.y, &mut seq);
                }
                None => seq.extend_from_slice(&[0u64; 8]),
            }
        }
        assert_eq!(seq, v.vk.limb_seq_u64);
    }

    #[test]
    fn inner_vk_hash_round_trips_against_gnark() {
        let v = load_vectors();
        let vk = load_vk();
        let digest = compute_inner_vk_hash(&vk, v.vk.max_inputs);
        assert_eq!(hex::encode(digest), v.vk.inner_vk_hash);
        // And the headline value the spike pins.
        assert_eq!(
            hex::encode(digest),
            "0c42ca6b6e6c574b5b21c90360bed01945966b844fb47b5430d0d801bbe8e6ca"
        );
    }

    #[test]
    fn fp_round_trip_hex() {
        let v = load_vectors();
        let fp = fp_from_hex(&v.vk.gt_limbs[0]);
        assert_eq!(fp_to_hex(&fp), v.vk.gt_limbs[0]);
    }
}
