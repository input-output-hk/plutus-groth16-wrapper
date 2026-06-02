//! Poseidon2 permutation and Merkle-Damgard hash over the BLS12-381 scalar
//! field, byte-for-byte compatible with `gnark-crypto`'s
//! `ecc/bls12-381/fr/poseidon2` default parameters `(t=2, R_F=6, R_P=50, d=5)`.
//!
//! **Role: cross-check only, not the codegen path.** Aiken codegen sources the
//! baked `InnerVKHash` from the gnark prover output (`outer_proof.json`); gnark
//! is the single source of truth (ADR-0005). This Rust reimplementation exists
//! solely to detect a *silent change in `gnark-crypto`'s Poseidon2* — a future
//! parameter, round-constant, or MDS revision that would otherwise quietly
//! shift every baked constant. Correctness is pinned by KATs dumped from the
//! gnark reference in `testdata/inner_vk_hash_vectors.json`.

use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use sha3::{Digest, Keccak256};
use std::sync::OnceLock;

const WIDTH: usize = 2;
const NB_FULL_ROUNDS: usize = 6;
const NB_PARTIAL_ROUNDS: usize = 50;
/// Mirrors `gnark-crypto`'s `Parameters.String()` for these parameters; the
/// round keys are a deterministic Keccak-256 chain seeded by this exact string.
const SEED: &str = "Poseidon2-BLS12_381[t=2,rF=6,rP=50,d=5]";

/// Number of rounds = full + partial. Round-key layout: the first `R_F/2` and
/// last `R_F/2` rounds carry `WIDTH` keys (full rounds); the middle `R_P`
/// rounds carry a single key each (partial rounds).
const NB_ROUNDS: usize = NB_FULL_ROUNDS + NB_PARTIAL_ROUNDS;

/// Round keys in `gnark-crypto` generation order. `round_keys[r]` has length
/// `WIDTH` for full rounds and `1` for partial rounds.
fn round_keys() -> &'static Vec<Vec<Fr>> {
    static KEYS: OnceLock<Vec<Vec<Fr>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        // Deterministic round-constant derivation, mirroring gnark-crypto's
        // initRC: pre-hash the seed, then iterate Keccak-256 over the previous
        // digest, decoding each digest big-endian (reduced mod r) as one key.
        let mut rnd = Keccak256::digest(SEED.as_bytes()).to_vec(); // keccak(seed)
        let mut next = || -> Fr {
            rnd = Keccak256::digest(&rnd).to_vec();
            Fr::from_be_bytes_mod_order(&rnd)
        };

        let mut keys: Vec<Vec<Fr>> = Vec::with_capacity(NB_ROUNDS);
        let rf = NB_FULL_ROUNDS / 2;
        for _ in 0..rf {
            keys.push((0..WIDTH).map(|_| next()).collect());
        }
        for _ in 0..NB_PARTIAL_ROUNDS {
            keys.push(vec![next()]);
        }
        for _ in 0..rf {
            keys.push((0..WIDTH).map(|_| next()).collect());
        }
        keys
    })
}

#[inline]
fn sbox(x: Fr) -> Fr {
    // degree-5 sBox: x^5
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// External (full-round) MDS for t=2: circ(2,1) — `M_E = [[2,1],[1,2]]`.
#[inline]
fn mat_mul_external(s: &mut [Fr; WIDTH]) {
    let tmp = s[0] + s[1];
    s[0] += tmp;
    s[1] += tmp;
}

/// Internal (partial-round) MDS for t=2: `M_I = [[2,1],[1,3]]`.
#[inline]
fn mat_mul_internal(s: &mut [Fr; WIDTH]) {
    let sum = s[0] + s[1];
    s[0] += sum;
    s[1] = s[1].double() + sum;
}

/// Applies the Poseidon2 permutation in place. Mirrors `Permutation.Permutation`.
pub fn permutation(state: &mut [Fr; WIDTH]) {
    let keys = round_keys();
    let rf = NB_FULL_ROUNDS / 2;

    mat_mul_external(state);

    for round in keys.iter().take(rf) {
        for (s, k) in state.iter_mut().zip(round) {
            *s += k;
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        mat_mul_external(state);
    }
    for round in keys.iter().take(rf + NB_PARTIAL_ROUNDS).skip(rf) {
        state[0] += round[0];
        state[0] = sbox(state[0]);
        mat_mul_internal(state);
    }
    for round in keys.iter().skip(rf + NB_PARTIAL_ROUNDS) {
        for (s, k) in state.iter_mut().zip(round) {
            *s += k;
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        mat_mul_external(state);
    }
}

/// Decodes a 32-byte big-endian block as an Fr element (canonical inputs only).
fn fr_from_be_bytes(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// Canonical 32-byte big-endian encoding of an Fr element, matching gnark's
/// `fr.Element.Bytes()` / `Marshal()`.
pub fn fr_to_be_bytes(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = f.into_bigint().to_bytes_be(); // 32 bytes for a 256-bit BigInt
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// 2-to-1 compression with feed-forward of the right input, mirroring
/// `Permutation.Compress`: `out = right + permute(left, right)[1]`.
fn compress(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut x = [fr_from_be_bytes(left), fr_from_be_bytes(right)];
    let feed = x[1];
    permutation(&mut x);
    fr_to_be_bytes(&(feed + x[1]))
}

/// Merkle-Damgard hasher over Poseidon2/BLS12-381 Fr with `IV = 0`, matching
/// `poseidonbls.NewMerkleDamgardHasher()`. Each absorbed block must be exactly
/// 32 bytes (one canonical Fr element); inputs are not padded here.
#[derive(Default)]
pub struct MerkleDamgardHasher {
    /// Chaining state; `Default` is the all-zero `IV` mandated by ADR-0005.
    state: [u8; 32],
}

impl MerkleDamgardHasher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs one 32-byte Fr block.
    pub fn update_block(&mut self, block: &[u8; 32]) {
        self.state = compress(&self.state, block);
    }

    /// Absorbs one Fr element as a 32-byte big-endian block.
    pub fn update_fr(&mut self, f: &Fr) {
        let block = fr_to_be_bytes(f);
        self.update_block(&block);
    }

    /// Returns the current 32-byte big-endian digest.
    pub fn finalize(&self) -> [u8; 32] {
        self.state
    }

    /// Returns the digest decoded as an Fr element.
    pub fn finalize_fr(&self) -> Fr {
        fr_from_be_bytes(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::load_vectors;

    fn fr_from_hex(h: &str) -> Fr {
        let bytes = hex::decode(h).unwrap();
        fr_from_be_bytes(&bytes)
    }

    #[test]
    fn round_keys_match_gnark() {
        let v = load_vectors();
        let keys = round_keys();
        assert_eq!(keys.len(), v.round_keys.len(), "round count");
        for (r, (got, want)) in keys.iter().zip(&v.round_keys).enumerate() {
            assert_eq!(got.len(), want.len(), "round {r} key count");
            for (j, (g, w)) in got.iter().zip(want).enumerate() {
                assert_eq!(*g, fr_from_hex(w), "round {r} key {j}");
            }
        }
    }

    #[test]
    fn permutation_matches_gnark_kats() {
        let v = load_vectors();
        for (i, kat) in v.perm_kats.iter().enumerate() {
            let mut state = [fr_from_hex(&kat.r#in[0]), fr_from_hex(&kat.r#in[1])];
            permutation(&mut state);
            assert_eq!(fr_to_be_bytes(&state[0]), hex32(&kat.out[0]), "perm {i} out0");
            assert_eq!(fr_to_be_bytes(&state[1]), hex32(&kat.out[1]), "perm {i} out1");
        }
    }

    #[test]
    fn merkle_damgard_matches_gnark_kats() {
        let v = load_vectors();
        for (i, kat) in v.md_kats.iter().enumerate() {
            let mut h = MerkleDamgardHasher::new();
            for block in &kat.blocks {
                h.update_block(&hex32(block));
            }
            assert_eq!(h.finalize(), hex32(&kat.digest), "md kat {i}");
        }
    }

    fn hex32(h: &str) -> [u8; 32] {
        let v = hex::decode(h).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
}
